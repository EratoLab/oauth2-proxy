package providers

import (
	"context"
    "crypto/tls"
	"fmt"
    "net/http"
	"net/url"
    "os"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	internaloidc "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/oidc"
    "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
    "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util"
	k8serrors "k8s.io/apimachinery/pkg/util/errors"
)

const (
	CodeChallengeMethodPlain = "plain"
	CodeChallengeMethodS256  = "S256"
)

// Provider represents an upstream identity provider implementation
type Provider interface {
	Data() *ProviderData
	GetLoginURL(redirectURI, finalRedirect, nonce string, extraParams url.Values) string
	Redeem(ctx context.Context, redirectURI, code, codeVerifier string) (*sessions.SessionState, error)
	// Deprecated: Migrate to EnrichSession
	GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error)
	EnrichSession(ctx context.Context, s *sessions.SessionState) error
	Authorize(ctx context.Context, s *sessions.SessionState) (bool, error)
	ValidateSession(ctx context.Context, s *sessions.SessionState) bool
	RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error)
	CreateSessionFromToken(ctx context.Context, token string) (*sessions.SessionState, error)
}

func NewProvider(providerConfig options.Provider) (Provider, error) {
	providerData, err := newProviderDataFromConfig(providerConfig)
	if err != nil {
		return nil, fmt.Errorf("could not create provider data: %v", err)
	}
	switch providerConfig.Type {
	case options.ADFSProvider:
		return NewADFSProvider(providerData, providerConfig), nil
	case options.AzureProvider:
		return NewAzureProvider(providerData, providerConfig.AzureConfig), nil
	case options.MicrosoftEntraIDProvider:
		return NewMicrosoftEntraIDProvider(providerData, providerConfig), nil
	case options.BitbucketProvider:
		return NewBitbucketProvider(providerData, providerConfig.BitbucketConfig), nil
	case options.DigitalOceanProvider:
		return NewDigitalOceanProvider(providerData), nil
	case options.FacebookProvider:
		return NewFacebookProvider(providerData), nil
	case options.GitHubProvider:
		return NewGitHubProvider(providerData, providerConfig.GitHubConfig), nil
	case options.GitLabProvider:
		return NewGitLabProvider(providerData, providerConfig)
	case options.GoogleProvider:
		return NewGoogleProvider(providerData, providerConfig.GoogleConfig)
	case options.KeycloakProvider:
		return NewKeycloakProvider(providerData, providerConfig.KeycloakConfig), nil
	case options.KeycloakOIDCProvider:
		return NewKeycloakOIDCProvider(providerData, providerConfig), nil
	case options.LinkedInProvider:
		return NewLinkedInProvider(providerData), nil
	case options.LoginGovProvider:
		return NewLoginGovProvider(providerData, providerConfig.LoginGovConfig)
	case options.NextCloudProvider:
		return NewNextcloudProvider(providerData), nil
	case options.OIDCProvider:
		return NewOIDCProvider(providerData, providerConfig.OIDCConfig), nil
	case options.SourceHutProvider:
		return NewSourceHutProvider(providerData), nil
	default:
		return nil, fmt.Errorf("unknown provider type %q", providerConfig.Type)
	}
}

func newProviderDataFromConfig(providerConfig options.Provider) (*ProviderData, error) {
	p := &ProviderData{
		Scope:                   providerConfig.Scope,
		ClientID:                providerConfig.ClientID,
		ClientSecret:            providerConfig.ClientSecret,
		ClientSecretFile:        providerConfig.ClientSecretFile,
		AuthRequestResponseMode: providerConfig.AuthRequestResponseMode,
	}

    // Build a provider-specific HTTP client if TLS settings or CA files are provided
    p.HTTPClient = buildProviderHTTPClient(providerConfig)

	needsVerifier, err := providerRequiresOIDCProviderVerifier(providerConfig.Type)
	if err != nil {
		return nil, err
	}

    if needsVerifier {
        pv, err := internaloidc.NewProviderVerifier(context.TODO(), internaloidc.ProviderVerifierOptions{
			AudienceClaims:         providerConfig.OIDCConfig.AudienceClaims,
			ClientID:               providerConfig.ClientID,
			ExtraAudiences:         providerConfig.OIDCConfig.ExtraAudiences,
			IssuerURL:              providerConfig.OIDCConfig.IssuerURL,
			JWKsURL:                providerConfig.OIDCConfig.JwksURL,
			PublicKeyFiles:         providerConfig.OIDCConfig.PublicKeyFiles,
			SkipDiscovery:          providerConfig.OIDCConfig.SkipDiscovery,
			SkipIssuerVerification: providerConfig.OIDCConfig.InsecureSkipIssuerVerification,
            HTTPClient:             p.HTTPClient,
        })
		if err != nil {
			return nil, fmt.Errorf("error building OIDC ProviderVerifier: %v", err)
		}

		p.Verifier = pv.Verifier()
		if pv.DiscoveryEnabled() {
			// Use the discovered values rather than any specified values
			endpoints := pv.Provider().Endpoints()
			pkce := pv.Provider().PKCE()
			providerConfig.LoginURL = endpoints.AuthURL
			providerConfig.RedeemURL = endpoints.TokenURL
			providerConfig.ProfileURL = endpoints.UserInfoURL
			providerConfig.OIDCConfig.JwksURL = endpoints.JWKsURL
			p.SupportedCodeChallengeMethods = pkce.CodeChallengeAlgs
		}
	}

	errs := []error{}
	for name, u := range map[string]struct {
		dst **url.URL
		raw string
	}{
		"login":    {dst: &p.LoginURL, raw: providerConfig.LoginURL},
		"redeem":   {dst: &p.RedeemURL, raw: providerConfig.RedeemURL},
		"profile":  {dst: &p.ProfileURL, raw: providerConfig.ProfileURL},
		"validate": {dst: &p.ValidateURL, raw: providerConfig.ValidateURL},
		"resource": {dst: &p.ProtectedResource, raw: providerConfig.ProtectedResource},
	} {
		var err error
		*u.dst, err = url.Parse(u.raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("could not parse %s URL: %v", name, err))
		}
	}
	// handle LoginURLParameters
	errs = append(errs, p.compileLoginParams(providerConfig.LoginURLParameters)...)

	if len(errs) > 0 {
		return nil, k8serrors.NewAggregate(errs)
	}

	// Make the OIDC options available to all providers that support it
	p.AllowUnverifiedEmail = providerConfig.OIDCConfig.InsecureAllowUnverifiedEmail
	p.EmailClaim = providerConfig.OIDCConfig.EmailClaim
	p.GroupsClaim = providerConfig.OIDCConfig.GroupsClaim
	p.SkipClaimsFromProfileURL = providerConfig.SkipClaimsFromProfileURL

	// Set PKCE enabled or disabled based on discovery and force options
	p.CodeChallengeMethod = parseCodeChallengeMethod(providerConfig)
	if len(p.SupportedCodeChallengeMethods) != 0 && p.CodeChallengeMethod == "" {
		logger.Printf("Warning: Your provider supports PKCE methods %+q, but you have not enabled one with --code-challenge-method", p.SupportedCodeChallengeMethods)
	}

	if providerConfig.OIDCConfig.UserIDClaim == "" {
		providerConfig.OIDCConfig.UserIDClaim = "email"
	}

	// TODO (@NickMeves) - Remove This
	// Backwards Compatibility for Deprecated UserIDClaim option
	if providerConfig.OIDCConfig.EmailClaim == options.OIDCEmailClaim &&
		providerConfig.OIDCConfig.UserIDClaim != options.OIDCEmailClaim {
		p.EmailClaim = providerConfig.OIDCConfig.UserIDClaim
	}

	p.setAllowedGroups(providerConfig.AllowedGroups)

	p.BackendLogoutURL = providerConfig.BackendLogoutURL

	return p, nil
}

// buildProviderHTTPClient constructs an HTTP client for provider communications
// honoring custom CA files and client TLS configuration if provided. If no
// configuration is provided, it returns the default client.
func buildProviderHTTPClient(providerConfig options.Provider) *http.Client {
    hasCAFiles := len(providerConfig.CAFiles) > 0
    hasTLS := providerConfig.MTLSCertFile != "" && providerConfig.MTLSKeyFile != ""
    if !hasCAFiles && !hasTLS {
        return requests.DefaultHTTPClient
    }

    // Clone the default transport to preserve standard settings
    baseTransport, ok := requests.DefaultTransport.(*http.Transport)
    if !ok {
        return requests.DefaultHTTPClient
    }
    transport := baseTransport.Clone()

    tlsConfig := &tls.Config{}

    if hasCAFiles {
        pool, err := util.GetCertPool(providerConfig.CAFiles, providerConfig.UseSystemTrustStore)
        if err == nil {
            tlsConfig.RootCAs = pool
            // Default to TLS1.2 minimum for provider communications when custom CAs are used
            tlsConfig.MinVersion = tls.VersionTLS12
        } else {
            logger.Printf("unable to load provider CA file(s): %v", err)
        }
    }

    if hasTLS {
        certData, err1 := os.ReadFile(providerConfig.MTLSCertFile)
        if err1 != nil {
            logger.Printf("could not read provider client cert file: %v", err1)
        } else {
            keyData, err2 := os.ReadFile(providerConfig.MTLSKeyFile)
            if err2 != nil {
                logger.Printf("could not read provider client key file: %v", err2)
            } else {
                if cert, err3 := tls.X509KeyPair(certData, keyData); err3 == nil {
                    tlsConfig.Certificates = []tls.Certificate{cert}
                } else {
                    logger.Printf("could not parse provider client certificate: %v", err3)
                }
            }
        }
    }

    transport.TLSClientConfig = tlsConfig
    return requests.NewClient(transport)
}

// (no helper needed for mTLS file paths)

// Pick the most appropriate code challenge method for PKCE
// At this time we do not consider what the server supports to be safe and
// only enable PKCE if the user opts-in
func parseCodeChallengeMethod(providerConfig options.Provider) string {
	switch {
	case providerConfig.CodeChallengeMethod != "":
		return providerConfig.CodeChallengeMethod
	default:
		return ""
	}
}

func providerRequiresOIDCProviderVerifier(providerType options.ProviderType) (bool, error) {
	switch providerType {
	case options.BitbucketProvider, options.DigitalOceanProvider, options.FacebookProvider, options.GitHubProvider,
		options.GoogleProvider, options.KeycloakProvider, options.LinkedInProvider, options.LoginGovProvider,
		options.NextCloudProvider, options.SourceHutProvider:
		return false, nil
	case options.ADFSProvider, options.AzureProvider, options.GitLabProvider, options.KeycloakOIDCProvider, options.OIDCProvider, options.MicrosoftEntraIDProvider:
		return true, nil
	default:
		return false, fmt.Errorf("unknown provider type: %s", providerType)
	}
}
