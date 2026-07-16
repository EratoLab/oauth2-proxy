package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util/ptr"
	"golang.org/x/oauth2"
)

// OIDCProvider represents an OIDC based Identity Provider
type OIDCProvider struct {
	*ProviderData

	SkipNonce                                    bool
	AllowExpiredIDTokenOnExternalTokenRedemption bool
}

const (
	oidcDefaultScope       = "openid email profile"
	oidcNotBeforeClockSkew = 5 * time.Minute
)

// NewOIDCProvider initiates a new OIDCProvider
func NewOIDCProvider(p *ProviderData, opts options.OIDCOptions) *OIDCProvider {
	name := "OpenID Connect"

	if p.ProviderName != "" {
		name = p.ProviderName
	}

	oidcProviderDefaults := providerDefaults{
		name:        name,
		loginURL:    nil,
		redeemURL:   nil,
		profileURL:  nil,
		validateURL: nil,
		scope:       oidcDefaultScope,
	}

	if len(p.AllowedGroups) > 0 {
		oidcProviderDefaults.scope += " groups"
	}

	p.setProviderDefaults(oidcProviderDefaults)
	p.getAuthorizationHeaderFunc = makeOIDCHeader

	return &OIDCProvider{
		ProviderData: p,
		SkipNonce:    ptr.Deref(opts.InsecureSkipNonce, options.DefaultInsecureSkipNonce),
		AllowExpiredIDTokenOnExternalTokenRedemption: ptr.Deref(opts.InsecureAllowExpiredIDTokenOnExternalRedemption, options.DefaultInsecureAllowExpiredIDTokenOnExternalRedemption),
	}
}

var _ Provider = (*OIDCProvider)(nil)

// GetLoginURL makes the LoginURL with optional nonce support
func (p *OIDCProvider) GetLoginURL(redirectURI, state, nonce string, extraParams url.Values) string {
	if !p.SkipNonce {
		extraParams.Add("nonce", nonce)
	}
	// Response mode should only be set if a non default mode is requested
	if p.AuthRequestResponseMode != "" {
		extraParams.Add("response_mode", p.AuthRequestResponseMode)
	}

	loginURL := makeLoginURL(p.Data(), redirectURI, state, extraParams)
	return loginURL.String()
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *OIDCProvider) Redeem(ctx context.Context, redirectURL, code, codeVerifier string) (*sessions.SessionState, error) {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return nil, err
	}

	var opts []oauth2.AuthCodeOption
	if codeVerifier != "" {
		opts = append(opts, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	}

	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
		RedirectURL: redirectURL,
	}

	ctx = oidc.ClientContext(ctx, requests.DefaultHTTPClient)
	token, err := c.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %v", err)
	}

	return p.createSession(ctx, token, false)
}

// EnrichSession is called after Redeem to allow providers to enrich session fields
// such as User, Email, Groups with provider specific API calls.
func (p *OIDCProvider) EnrichSession(_ context.Context, s *sessions.SessionState) error {
	// If a mandatory email wasn't set, error at this point.
	if s.Email == "" {
		return errors.New("neither the id_token nor the profileURL set an email")
	}
	return nil
}

// ValidateSession checks that the session's IDToken is still valid
func (p *OIDCProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	client := p.ProviderData.HTTPClient
	if client == nil {
		client = requests.DefaultHTTPClient
	}
	ctx = oidc.ClientContext(ctx, client)

	if s.CreatedFromExternalToken && p.AllowExpiredIDTokenOnExternalTokenRedemption && s.AccessToken != "" {
		idToken, err := p.verifyIDTokenAllowingExpiry(ctx, s.IDToken)
		if err != nil {
			logger.Errorf("external id_token verification failed: %v", err)
			return false
		}
		if err := p.validateExternalAccessToken(ctx, s.AccessToken, idToken.Subject); err != nil {
			logger.Errorf("external access_token validation failed: %v", err)
			return false
		}
		if _, err := validateExternalAccessTokenExpiry(s.AccessToken, time.Now()); err != nil {
			return false
		}
		return true
	}

	// https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
	// The ID Token is optional in the Refresh Token Response
	if s.Refreshed {
		validateEndpointAvailable := p.Data().ValidateURL != nil && p.Data().ValidateURL.String() != ""
		if validateEndpointAvailable && !validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken)) {
			logger.Errorf("access_token validation failed")
			return false
		}
		return true
	}

	if _, err := p.Verifier.Verify(ctx, s.IDToken); err != nil {
		logger.Errorf("id_token verification failed: %v", err)
		return false
	}
	if s.CreatedFromExternalToken {
		// The external identity provider, rather than oauth2-proxy, initiated the
		// authentication flow, so there is no oauth2-proxy nonce to check.
		return true
	}

	if p.SkipNonce {
		return true
	}

	if err := p.checkNonce(s); err != nil {
		logger.Errorf("nonce verification failed: %v", err)
		return false
	}

	return true
}

// RefreshSession uses the RefreshToken to fetch new Access and ID Tokens
func (p *OIDCProvider) RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if s == nil || s.RefreshToken == "" {
		return false, nil
	}

	ctx = oidc.ClientContext(ctx, requests.DefaultHTTPClient)
	err := p.redeemRefreshToken(ctx, s)
	if err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	return true, nil
}

// redeemRefreshToken uses a RefreshToken with the RedeemURL to refresh the
// Access Token and (probably) the ID Token.
func (p *OIDCProvider) redeemRefreshToken(ctx context.Context, s *sessions.SessionState) error {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return err
	}

	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
	}
	t := &oauth2.Token{
		RefreshToken: s.RefreshToken,
		Expiry:       time.Now().Add(-time.Hour),
	}
	token, err := c.TokenSource(ctx, t).Token()
	if err != nil {
		return fmt.Errorf("failed to get token: %v", err)
	}

	newSession, err := p.createSession(ctx, token, true)
	if err != nil {
		return fmt.Errorf("unable create new session state from response: %v", err)
	}

	// It's possible that if the refresh token isn't in the token response the
	// session will not contain an id token.
	// If it doesn't it's probably better to retain the old one
	if newSession.IDToken != "" {
		s.IDToken = newSession.IDToken
		s.Email = newSession.Email
		s.User = newSession.User
		s.Groups = newSession.Groups
		s.PreferredUsername = newSession.PreferredUsername
	}

	s.AccessToken = newSession.AccessToken
	s.RefreshToken = newSession.RefreshToken
	s.CreatedAt = newSession.CreatedAt
	s.ExpiresOn = newSession.ExpiresOn

	return nil
}

// CreateSessionFromToken converts Bearer IDTokens into sessions
func (p *OIDCProvider) CreateSessionFromToken(ctx context.Context, token string) (*sessions.SessionState, error) {
	ctx = oidc.ClientContext(ctx, requests.DefaultHTTPClient)
	idToken, err := p.Verifier.Verify(ctx, token)
	if err != nil {
		return nil, err
	}

	ss, err := p.buildSessionFromClaims(token, "")
	if err != nil {
		return nil, err
	}

	// Allow empty Email in Bearer case since we can't hit the ProfileURL
	if ss.Email == "" {
		ss.Email = ss.User
	}

	ss.AccessToken = token
	ss.IDToken = token
	ss.RefreshToken = ""

	ss.CreatedAtNow()
	ss.SetExpiresOn(idToken.Expiry)

	return ss, nil
}

// CreateSessionFromExternalToken validates an externally acquired ID token and
// optional access token, then converts them into a session without a refresh token.
func (p *OIDCProvider) CreateSessionFromExternalToken(ctx context.Context, rawIDToken, accessToken string) (*sessions.SessionState, error) {
	client := p.ProviderData.HTTPClient
	if client == nil {
		client = requests.DefaultHTTPClient
	}
	ctx = oidc.ClientContext(ctx, client)

	accessToken = strings.TrimSpace(accessToken)
	idToken, err := p.verifyExternalIDToken(ctx, rawIDToken, accessToken)
	if err != nil {
		return nil, err
	}

	var accessTokenExpiry *time.Time
	if accessToken != "" {
		if err := p.validateExternalAccessToken(ctx, accessToken, idToken.Subject); err != nil {
			return nil, err
		}
		if p.AllowExpiredIDTokenOnExternalTokenRedemption {
			expiry, err := validateExternalAccessTokenExpiry(accessToken, time.Now())
			if err != nil {
				return nil, err
			}
			accessTokenExpiry = &expiry
		}
	}

	ss, err := p.buildSessionFromClaims(rawIDToken, accessToken)
	if err != nil {
		return nil, err
	}

	ss.AccessToken = accessToken
	ss.IDToken = rawIDToken
	ss.RefreshToken = ""
	ss.CreatedFromExternalToken = true
	ss.CreatedAtNow()
	if accessTokenExpiry != nil {
		ss.SetExpiresOn(*accessTokenExpiry)
	} else {
		ss.SetExpiresOn(idToken.Expiry)
	}

	return ss, nil
}

func (p *OIDCProvider) verifyExternalIDToken(ctx context.Context, rawIDToken, accessToken string) (*oidc.IDToken, error) {
	idToken, err := p.Verifier.Verify(ctx, rawIDToken)
	if err == nil {
		return idToken, nil
	}
	if !p.AllowExpiredIDTokenOnExternalTokenRedemption {
		return nil, fmt.Errorf("could not verify id_token: %v", err)
	}
	if accessToken == "" {
		return nil, fmt.Errorf("could not verify id_token: %v; an access_token is required when allowing an expired id_token", err)
	}

	idToken, allowExpiredErr := p.verifyIDTokenAllowingExpiry(ctx, rawIDToken)
	if allowExpiredErr != nil {
		return nil, fmt.Errorf("could not verify id_token: %v", allowExpiredErr)
	}
	if !idToken.Expiry.Before(time.Now()) {
		// The expiry-tolerant verifier only exists to handle expiration. If the
		// token is not expired, preserve the original verification failure.
		return nil, fmt.Errorf("could not verify id_token: %v", err)
	}

	logger.Printf("Allowing expired id_token from external token redemption; access_token expiry will determine the session lifetime")
	return idToken, nil
}

func (p *OIDCProvider) verifyIDTokenAllowingExpiry(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	if p.VerifierAllowingExpiredToken == nil {
		return nil, errors.New("OIDC verifier allowing expired tokens is not configured")
	}

	idToken, err := p.VerifierAllowingExpiredToken.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}
	if err := validateIDTokenNotBefore(idToken, time.Now()); err != nil {
		return nil, err
	}
	return idToken, nil
}

func validateIDTokenNotBefore(idToken *oidc.IDToken, now time.Time) error {
	var claims struct {
		NotBefore *json.Number `json:"nbf"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return fmt.Errorf("could not parse id_token temporal claims: %v", err)
	}
	if claims.NotBefore == nil {
		return nil
	}

	notBeforeUnix, err := claims.NotBefore.Int64()
	if err != nil {
		return fmt.Errorf("id_token nbf claim is not an integer Unix timestamp: %v", err)
	}
	notBefore := time.Unix(notBeforeUnix, 0)
	if now.Add(oidcNotBeforeClockSkew).Before(notBefore) {
		return fmt.Errorf("current time %v before the nbf (not before) time: %v", now, notBefore)
	}
	return nil
}

func validateExternalAccessTokenExpiry(accessToken string, now time.Time) (time.Time, error) {
	expiry, err := extractJWTExpiry(accessToken)
	if err != nil {
		logger.Errorf("external access_token expiry validation failed: %v", err)
		return time.Time{}, fmt.Errorf("access_token expiry validation failed: %v", err)
	}
	if !now.Before(expiry) {
		err := fmt.Errorf("access_token is expired (token expiry: %v)", expiry)
		logger.Errorf("external access_token expiry validation failed: %v", err)
		return time.Time{}, err
	}
	return expiry, nil
}

func extractJWTExpiry(rawToken string) (time.Time, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return time.Time{}, fmt.Errorf("access_token is not a JWT: expected 3 parts, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("access_token has an invalid JWT payload: %v", err)
	}
	var claims struct {
		ExpiresAt *json.Number `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, fmt.Errorf("access_token has an invalid JWT payload: %v", err)
	}
	if claims.ExpiresAt == nil {
		return time.Time{}, errors.New("access_token is missing exp claim")
	}

	expiresAtUnix, err := claims.ExpiresAt.Int64()
	if err != nil {
		return time.Time{}, fmt.Errorf("access_token exp claim is not an integer Unix timestamp: %v", err)
	}
	return time.Unix(expiresAtUnix, 0), nil
}

func (p *OIDCProvider) validateExternalAccessToken(ctx context.Context, accessToken, idTokenSubject string) error {
	header := makeOIDCHeader(accessToken)
	client := p.ProviderData.HTTPClient
	if client == nil {
		client = requests.DefaultHTTPClient
	}

	if p.ProfileURL != nil && p.ProfileURL.String() != "" && !p.SkipClaimsFromProfileURL {
		var claims struct {
			Subject string `json:"sub"`
		}
		result := requests.New(p.ProfileURL.String()).
			WithContext(ctx).
			WithClient(client).
			WithHeaders(header).
			Do()
		if err := result.UnmarshalInto(&claims); err != nil {
			return fmt.Errorf("access_token validation failed against profile URL: %v", err)
		}
		if claims.Subject == "" {
			return errors.New("access_token validation failed: profile response missing sub claim")
		}
		if claims.Subject != idTokenSubject {
			return errors.New("access_token validation failed: subject does not match id_token")
		}
		return nil
	}

	if p.ValidateURL != nil && p.ValidateURL.String() != "" {
		if !validateToken(ctx, p, accessToken, header) {
			return errors.New("access_token validation failed")
		}
		return nil
	}

	return errors.New("access_token validation failed: no profile or validation endpoint configured")
}

// createSession takes an oauth2.Token and creates a SessionState from it.
// It alters behavior if called from Redeem vs Refresh
func (p *OIDCProvider) createSession(ctx context.Context, token *oauth2.Token, refresh bool) (*sessions.SessionState, error) {
	_, err := p.verifyIDToken(ctx, token)
	if err != nil {
		switch err {
		case ErrMissingIDToken:
			// IDToken is mandatory in Redeem but optional in Refresh
			if !refresh {
				return nil, errors.New("token response did not contain an id_token")
			}
		default:
			return nil, fmt.Errorf("could not verify id_token: %v", err)
		}
	}

	rawIDToken := getIDToken(token)
	ss, err := p.buildSessionFromClaims(rawIDToken, token.AccessToken)
	if err != nil {
		return nil, err
	}

	ss.AccessToken = token.AccessToken
	ss.RefreshToken = token.RefreshToken
	ss.IDToken = rawIDToken

	ss.CreatedAtNow()
	ss.SetExpiresOn(token.Expiry)

	return ss, nil
}
