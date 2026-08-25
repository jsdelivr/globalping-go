package globalping

import (
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

var (
	APIURL = "https://api.globalping.io/v1"
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
	// The client-side wait limit is derived from the first response: 45 seconds if it omits timeout,
	// otherwise its timeout plus 10 seconds. Elapsed time includes the initial request.
	// If the measurement is still in progress after elapsed time exceeds the limit,
	// AwaitMeasurement returns a locally generated timeout error.
	//
	// https://globalping.io/docs/api.globalping.io#get-/v1/measurements/-id-
	AwaitMeasurement(ctx context.Context, id string) (*Measurement, error)

	// Returns the status and results of an existing measurement. Measurements are typically available for up to 7 days after creation.
	//
	// https://globalping.io/docs/api.globalping.io#get-/v1/measurements/-id-
	GetMeasurementRaw(ctx context.Context, id string) ([]byte, error)

	// Returns the rate limits for the current user or IP address.
	//
	// https://globalping.io/docs/api.globalping.io#get-/v1/limits
	Limits(ctx context.Context) (*LimitsResponse, error)

	// Returns a list of all probes currently online and their metadata, such as location and assigned tags.
	//
	// https://globalping.io/docs/api.globalping.io#get-/v1/probes
	Probes(ctx context.Context) (*ProbesResponse, error)

	// Clears the expired cached entries.
	CacheClean()

	// Removes all cached entries regardless of expiration.
	CachePurge()

	// Sets the authentication token for API requests.
	SetToken(token string)
}

type Config struct {
	AuthToken          string // Your GlobalPing API access token. Optional.
	UserAgent          string // User agent string for API requests. Optional.
	CacheExpireSeconds int64  // Cache entry expiration time in seconds. 0 means no expiration.

	HTTPClient *http.Client // If set, this client will be used for API requests. Optional.
}

type client struct {
	mu    sync.RWMutex
	http  *http.Client
	cache map[string]*cacheEntry

	cacheExpireSeconds int64
	userAgent          string
	authToken          atomic.Pointer[string]
}

// Creates a new client with the given configuration.
//
// Note: The client caches API responses.
// Set CacheExpireSeconds to configure the entry expiration and use CacheClean to clear the expired entries when reusing the client.
func NewClient(config Config) Client {
	c := &client{
		mu:                 sync.RWMutex{},
		userAgent:          config.UserAgent,
		cache:              map[string]*cacheEntry{},
		cacheExpireSeconds: config.CacheExpireSeconds,
	}

	if config.UserAgent == "" {
		c.userAgent = "globalping-go/" + Version + " (https://github.com/jsdelivr/globalping-go)"
	}

	if config.AuthToken != "" {
		c.authToken.Store(&config.AuthToken)
	}

	if config.HTTPClient != nil {
		c.http = config.HTTPClient
	} else {
		c.http = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	return c
}

func (c *client) SetToken(token string) {
	if token == "" {
		c.authToken.Store(nil)

		return
	}

	c.authToken.Store(&token)
}

func (c *client) newRequest(ctx context.Context, method string, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)

	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", c.userAgent)
	token := c.authToken.Load()

	if token != nil {
		req.Header.Set("Authorization", "Bearer "+*token)
	}

	return req, nil
}
