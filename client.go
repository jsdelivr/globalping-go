package globalping

import (
	"context"
	"net/http"
	"sync"
	"time"
)

const (
	GlobalpingAPIURL       = "https://api.globalping.io/v1"
	GlobalpingAuthURL      = "https://auth.globalping.io"
	GlobalpingDashboardURL = "https://dash.globalping.io"
)

type Client interface {
	// Creates a new measurement with parameters set in the request body. The measurement runs asynchronously and you can retrieve its current state at the URL returned in the Location header.
	//
	// https://globalping.io/docs/api.globalping.io#post-/v1/measurements
	CreateMeasurement(ctx context.Context, measurement *MeasurementCreate) (*MeasurementCreateResponse, error)

	// Returns the status and results of an existing measurement. Measurements are typically available for up to 7 days after creation.
	//
	// https://globalping.io/docs/api.globalping.io#get-/v1/measurements/-id-
	GetMeasurement(ctx context.Context, id string) (*Measurement, error)

	// Waits for the measurement to complete and returns the results.
	//
	// https://globalping.io/docs/api.globalping.io#get-/v1/measurements/-id-
	AwaitMeasurement(ctx context.Context, id string) (*Measurement, error)

	// Returns the status and results of an existing measurement. Measurements are typically available for up to 7 days after creation.
	//
	// https://globalping.io/docs/api.globalping.io#get-/v1/measurements/-id-
	GetMeasurementRaw(ctx context.Context, id string) ([]byte, error)

	// Returns a link to be used for authorization and listens for the authorization callback.
	//
	// onTokenRefresh will be called if the authorization is successful.
	Authorize(ctx context.Context, callback func(error)) (*AuthorizeResponse, error)

	// Returns the introspection response for the token.
	//
	// If the token is empty, the client's current token will be used.
	TokenIntrospection(ctx context.Context, token string) (*IntrospectionResponse, error)

	// Removes the current token from the client. It also revokes the tokens if the refresh token is available.
	//
	// onTokenRefresh will be called if the token is successfully removed.
	Logout(ctx context.Context) error

	// Revokes the token.
	RevokeToken(ctx context.Context, token string) error

	// Returns the rate limits for the current user or IP address.
	Limits(ctx context.Context) (*LimitsResponse, error)

	// Clears the expired cached entries.
	CacheClean()

	// Removes all cached entries regardless of expiration.
	CachePurge()
}

type Config struct {
	HTTPClient *http.Client // If set, this client will be used for API requests and authorization

	APIURL       string // optional
	DashboardURL string // optional

	AuthURL          string // optional
	AuthClientID     string
	AuthClientSecret string
	AuthToken        *Token
	OnTokenRefresh   func(*Token) // Callback function to be called when the token is refreshed or revoked.

	UserAgent          string
	CacheExpireSeconds int64 // Cache entry expiration time in seconds
}

type client struct {
	mu    sync.RWMutex
	http  *http.Client
	cache map[string]*cacheEntry

	authClientID     string
	authClientSecret string
	token            *Token
	onTokenRefresh   func(*Token)

	apiURL             string
	authURL            string
	dashboardURL       string
	cacheExpireSeconds int64
	userAgent          string
}

// Creates a new client with the given configuration.
// Note: The client caches API responses. Set CacheExpireSeconds to configure the cache entry expiration time in seconds, 0 means no expiration. Use CleanCache to clear the expired cached entries.
func NewClient(config Config) Client {
	c := &client{
		mu:                 sync.RWMutex{},
		authClientID:       config.AuthClientID,
		authClientSecret:   config.AuthClientSecret,
		onTokenRefresh:     config.OnTokenRefresh,
		apiURL:             config.APIURL,
		authURL:            config.AuthURL,
		dashboardURL:       config.DashboardURL,
		userAgent:          config.UserAgent,
		cache:              map[string]*cacheEntry{},
		cacheExpireSeconds: config.CacheExpireSeconds,
	}

	if config.APIURL == "" {
		c.apiURL = GlobalpingAPIURL
	}
	if config.AuthURL == "" {
		c.authURL = GlobalpingAuthURL
	}
	if config.DashboardURL == "" {
		c.dashboardURL = GlobalpingDashboardURL
	}

	if config.HTTPClient != nil {
		c.http = config.HTTPClient
	} else {
		c.http = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	if config.AuthToken != nil {
		c.token = &Token{
			AccessToken:  config.AuthToken.AccessToken,
			TokenType:    config.AuthToken.TokenType,
			RefreshToken: config.AuthToken.RefreshToken,
			ExpiresIn:    config.AuthToken.ExpiresIn,
			Expiry:       config.AuthToken.Expiry,
		}
		if c.token.TokenType == "" {
			c.token.TokenType = "Bearer"
		}
	}
	return c
}
