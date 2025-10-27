package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/jsdelivr/globalping-cli/utils"
)

var (
	moreCreditsRequiredNoAuthErr = "You only have %s remaining, and %d were required. Try requesting fewer probes or wait %s for the rate limit to reset. You can get higher limits by creating an account. Sign up at https://dash.globalping.io?view=add-credits"
	moreCreditsRequiredAuthErr   = "You only have %s remaining, and %d were required. Try requesting fewer probes or wait %s for the rate limit to reset. You can get higher limits by sponsoring us or hosting probes. Learn more at https://dash.globalping.io?view=add-credits"
	noCreditsNoAuthErr           = "You have run out of credits for this session. You can wait %s for the rate limit to reset or get higher limits by creating an account. Sign up at https://dash.globalping.io?view=add-credits"
	noCreditsAuthErr             = "You have run out of credits for this session. You can wait %s for the rate limit to reset or get higher limits by sponsoring us or hosting probes. Learn more at https://dash.globalping.io?view=add-credits"
	invalidRefreshTokenErr       = "You have been signed out by the API. Please try signing in again."
	invalidTokenErr              = "Your access token has been rejected by the API. Try signing in with a new token."
)

var (
	StatusUnauthorizedWithTokenRefreshed = 1000
)

// Docs: https://globalping.io/docs/api.globalping.io

type Locations struct {
	Magic string `json:"magic"`
}

type QueryOptions struct {
	Type string `json:"type,omitempty"`
}

type RequestOptions struct {
	Headers map[string]string `json:"headers,omitempty"`
	Path    string            `json:"path,omitempty"`
	Host    string            `json:"host,omitempty"`
	Query   string            `json:"query,omitempty"`
	Method  string            `json:"method,omitempty"`
}

type IPVersion int

const (
	IPVersion4 IPVersion = 4
	IPVersion6 IPVersion = 6
)

var PingProtocols = []string{"ICMP", "TCP"}
var TracerouteProtocols = []string{"ICMP", "TCP", "UDP"}
var DNSProtocols = []string{"TCP", "UDP"}
var MTRProtocols = []string{"ICMP", "TCP", "UDP"}
var HTTPProtocols = []string{"HTTP", "HTTPS", "HTTP2"}

type MeasurementOptions struct {
	Query     *QueryOptions   `json:"query,omitempty"`
	Request   *RequestOptions `json:"request,omitempty"`
	Protocol  string          `json:"protocol,omitempty"`
	Port      uint16          `json:"port"`
	Resolver  string          `json:"resolver,omitempty"`
	Trace     bool            `json:"trace,omitempty"`
	Packets   int             `json:"packets,omitempty"`
	IPVersion IPVersion       `json:"ipVersion,omitempty"`
}

type MeasurementType string

const (
	MeasurementTypePing       MeasurementType = "ping"
	MeasurementTypeTraceroute MeasurementType = "traceroute"
	MeasurementTypeDNS        MeasurementType = "dns"
	MeasurementTypeMTR        MeasurementType = "mtr"
	MeasurementTypeHTTP       MeasurementType = "http"
)

type MeasurementCreate struct {
	Limit             int                 `json:"limit"`
	Locations         []Locations         `json:"locations"`
	Type              MeasurementType     `json:"type"`
	Target            string              `json:"target"`
	InProgressUpdates bool                `json:"inProgressUpdates"`
	Options           *MeasurementOptions `json:"measurementOptions,omitempty"`
}

type MeasurementError struct {
	Code    int            `json:"-"`
	Message string         `json:"message"`
	Type    string         `json:"type"`
	Params  map[string]any `json:"params,omitempty"`
}

func (e *MeasurementError) Error() string {
	return e.Message
}

type MeasurementErrorResponse struct {
	Error *MeasurementError `json:"error"`
}

type MeasurementCreateResponse struct {
	ID          string `json:"id"`
	ProbesCount int    `json:"probesCount"`
}

type ProbeDetails struct {
	Continent string   `json:"continent"`
	Region    string   `json:"region"`
	Country   string   `json:"country"`
	City      string   `json:"city"`
	State     string   `json:"state,omitempty"`
	ASN       int      `json:"asn"`
	Network   string   `json:"network,omitempty"`
	Tags      []string `json:"tags,omitempty"`
}

type MeasurementStatus string

const (
	StatusInProgress MeasurementStatus = "in-progress"
	StatusFailed     MeasurementStatus = "failed"
	StatusOffline    MeasurementStatus = "offline"
	StatusFinished   MeasurementStatus = "finished"
)

type ProbeResult struct {
	Status    MeasurementStatus `json:"status"`    // The current measurement status.
	RawOutput string            `json:"rawOutput"` //  The raw output of the test. Can be presented to users but is not meant to be parsed by clients.

	// Common
	ResolvedAddress  string `json:"resolvedAddress"`  // The resolved IP address of the target
	ResolvedHostname string `json:"resolvedHostname"` // The resolved hostname of the target

	// Ping
	StatsRaw json.RawMessage `json:"stats,omitempty"` // Summary rtt and packet loss statistics. All times are in milliseconds.

	// DNS
	StatusCode     int             `json:"statusCode"`        // The HTTP status code.
	StatusCodeName string          `json:"statusCodeName"`    // The HTTP status code name.
	Resolver       string          `json:"resolver"`          // The hostname or IP of the resolver that answered the query.
	AnswersRaw     json.RawMessage `json:"answers,omitempty"` // An array of the received resource records.

	// HTTP
	RawHeaders string              `json:"rawHeaders"`        // The raw HTTP response headers.
	RawBody    string              `json:"rawBody"`           // The raw HTTP response body or null if there was no body in response. Note that only the first 10 kb are returned.
	Truncated  bool                `json:"truncated"`         // Indicates whether the rawBody value was truncated due to being too big.
	HeadersRaw json.RawMessage     `json:"headers,omitempty"` // The HTTP response headers.
	TLS        *HTTPTLSCertificate `json:"tls,omitempty"`     // Information about the TLS certificate or null if no TLS certificate is available.

	// Common
	HopsRaw    json.RawMessage `json:"hops,omitempty"`
	TimingsRaw json.RawMessage `json:"timings,omitempty"`
}

type PingStats struct {
	Min   float64 `json:"min"`   // The lowest rtt value.
	Avg   float64 `json:"avg"`   // The average rtt value.
	Max   float64 `json:"max"`   // The highest rtt value.
	Total int     `json:"total"` // The number of sent packets.
	Rcv   int     `json:"rcv"`   // The number of received packets.
	Drop  int     `json:"drop"`  // The number of dropped packets (total - rcv).
	Loss  float64 `json:"loss"`  // The percentage of dropped packets.
	Mdev  float64 `json:"mdev"`  // The mean deviation of the rtt values.
}

type PingTiming struct {
	RTT float64 `json:"rtt"` // The round-trip time for this packet.
	TTL int     `json:"ttl"` // The packet time-to-live value.
}

type TracerouteTiming struct {
	RTT float64 `json:"rtt"` // The round-trip time for this packet.
}

type TracerouteHop struct {
	ResolvedAddress  string             `json:"resolvedAddress"`  // The resolved IP address of the target
	ResolvedHostname string             `json:"resolvedHostname"` // The resolved hostname of the target
	Timings          []TracerouteTiming `json:"timings"`          // An array containing details for each packet. All times are in milliseconds.
}

type DNSAnswer struct {
	Name  string `json:"name"`  // The record domain name.
	Type  string `json:"type"`  // The record type.
	TTL   int    `json:"ttl"`   // The record time-to-live value in seconds.
	Class string `json:"class"` // The record class.
	Value string `json:"value"` // The record value.
}

type DNSTimings struct {
	Total float64 `json:"total"` // The total query time in milliseconds.
}

type TraceDNSHop struct {
	Resolver string      `json:"resolver"` // The hostname or IP of the resolver that answered the query.
	Answers  []DNSAnswer `json:"answers"`  // An array of the received resource records.
	Timings  DNSTimings  `json:"timings"`  // Details about the query times. All times are in milliseconds.
}

type MTRStats struct {
	Min   float64 `json:"min"`   // The lowest rtt value.
	Avg   float64 `json:"avg"`   // The average rtt value.
	Max   float64 `json:"max"`   // The highest rtt value.
	StDev float64 `json:"stDev"` // The standard deviation of the rtt values.

	JMin  float64 `json:"jMin"`  // The lowest jitter value.
	JAvg  float64 `json:"jAvg"`  // The average jitter value.
	JMax  float64 `json:"jMax"`  // The highest jitter value.
	Total int     `json:"total"` // The number of sent packets.
	Rcv   int     `json:"rcv"`   // The number of received packets.
	Drop  int     `json:"drop"`  // The number of dropped packets (total - rcv).

	Loss float64 `json:"loss"` // The percentage of dropped packets.
}

type MTRTiming struct {
	RTT float64 `json:"rtt"` // The round-trip time for this packet.
}

type MTRHop struct {
	ResolvedAddress  string      `json:"resolvedAddress"`  // The resolved IP address of the target
	ResolvedHostname string      `json:"resolvedHostname"` // The resolved hostname of the target
	ASN              []int       `json:"asn"`              // An array containing the ASNs assigned to this hop.
	Stats            MTRStats    `json:"stats"`            // Summary rtt and packet loss statistics. All times are in milliseconds.
	Timings          []MTRTiming `json:"timings"`          // An array containing details for each packet. All times are in milliseconds.
}

type HTTPTimings struct {
	Total     int `json:"total"`     // The total HTTP request time
	DNS       int `json:"dns"`       // The time required to perform the DNS lookup.
	TCP       int `json:"tcp"`       // The time from performing the DNS lookup to establishing the TCP connection.
	TLS       int `json:"tls"`       // The time from establishing the TCP connection to establishing the TLS session.
	FirstByte int `json:"firstByte"` // The time from establishing the TCP/TLS connection to the first response byte.
	Download  int `json:"download"`  // The time from the first byte to downloading the whole response.
}

type ProbeMeasurement struct {
	Probe  ProbeDetails `json:"probe"`
	Result ProbeResult  `json:"result"`
}

type TLSCertificateSubject struct {
	CommonName      string `json:"CN"`  // The subject's common name.
	AlternativeName string `json:"alt"` // The subject's alternative name.
}

type TLSCertificateIssuer struct {
	Country      string `json:"C"`  // The issuer's country.
	Organization string `json:"O"`  // The issuer's organization.
	CommonName   string `json:"CN"` // The issuer's common name.
}

type HTTPTLSCertificate struct {
	Protocol       string                `json:"protocol"`       // The negotiated SSL/TLS protocol version.
	ChipherName    string                `json:"cipherName"`     // The OpenSSL name of the cipher suite.
	Authorized     bool                  `json:"authorized"`     // Indicates whether a trusted authority signed the certificate
	Error          string                `json:"error"`          // The reason for rejecting the certificate if authorized is false
	CreatedAt      time.Time             `json:"createdAt"`      // The creation date and time of the certificate
	ExpiresAt      time.Time             `json:"expiresAt"`      // The expiration date and time of the certificate
	Subject        TLSCertificateSubject `json:"subject"`        // Information about the certificate subject.
	Issuer         TLSCertificateIssuer  `json:"issuer"`         // Information about the certificate issuer.
	KeyType        string                `json:"keyType"`        // The type of the used key, or null for unrecognized types.
	KeyBits        int                   `json:"keyBits"`        // The size of the used key, or null for unrecognized types.
	SerialNumber   string                `json:"serialNumber"`   // The certificate serial number as a : separated HEX string
	Fingerprint256 string                `json:"fingerprint256"` // The SHA-256 digest of the DER-encoded certificate as a : separated HEX string
	PublicKey      string                `json:"publicKey"`      // The public key as a : separated HEX string, or null for unrecognized types.
}

type Measurement struct {
	ID          string             `json:"id"`
	Type        MeasurementType    `json:"type"`
	Status      MeasurementStatus  `json:"status"`
	CreatedAt   string             `json:"createdAt"`
	UpdatedAt   string             `json:"updatedAt"`
	Target      string             `json:"target"`
	ProbesCount int                `json:"probesCount"`
	Results     []ProbeMeasurement `json:"results"`
}

func (c *client) CreateMeasurement(ctx context.Context, measurement *MeasurementCreate) (*MeasurementCreateResponse, error) {
	postData, err := json.Marshal(measurement)
	if err != nil {
		return nil, &MeasurementError{Message: "failed to marshal post data - please report this bug"}
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.apiURL+"/measurements", bytes.NewBuffer(postData))
	if err != nil {
		return nil, &MeasurementError{Message: "failed to create request - please report this bug"}
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept-Encoding", "br")
	req.Header.Set("Content-Type", "application/json")

	token, err := c.getToken(ctx)
	if err != nil {
		return nil, &MeasurementError{Message: "failed to get token: " + err.Error()}
	}
	if token != nil {
		req.Header.Set("Authorization", token.TokenType+" "+token.AccessToken)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &MeasurementError{Message: "request failed - please try again later"}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		var data MeasurementErrorResponse
		err = json.NewDecoder(resp.Body).Decode(&data)
		if err != nil {
			return nil, &MeasurementError{Message: "invalid error format returned - please report this bug"}
		}
		err := data.Error
		err.Code = resp.StatusCode

		if resp.StatusCode == http.StatusBadRequest {
			resErr := ""
			for _, v := range data.Error.Params {
				resErr += fmt.Sprintf(" - %s\n", v)
			}
			// Remove the last \n
			if len(resErr) > 0 {
				resErr = resErr[:len(resErr)-1]
			}
			err.Message = fmt.Sprintf("invalid parameters:\n%s", resErr)
			return nil, err
		}

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			if token != nil {
				if token.RefreshToken == "" {
					err.Message = invalidTokenErr
					return nil, err
				}
				if c.tryToRefreshToken(ctx, token.RefreshToken) {
					err.Code = StatusUnauthorizedWithTokenRefreshed
					return nil, err
				}
				err.Message = invalidRefreshTokenErr
				return nil, err
			}
			err.Message = data.Error.Message
			return nil, err
		}

		if resp.StatusCode == http.StatusUnprocessableEntity {
			err.Message = fmt.Sprintf("%s - please try a different location", utils.TextFromSentence(err.Message))
			return nil, err
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			rateLimitRemaining, _ := strconv.ParseInt(resp.Header.Get("X-RateLimit-Remaining"), 10, 64)
			rateLimitReset, _ := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64)
			creditsRemaining, _ := strconv.ParseInt(resp.Header.Get("X-Credits-Remaining"), 10, 64)
			requestCost, _ := strconv.ParseInt(resp.Header.Get("X-Request-Cost"), 10, 64)
			remaining := rateLimitRemaining + creditsRemaining
			if token == nil {
				if remaining > 0 {
					err.Message = fmt.Sprintf(moreCreditsRequiredNoAuthErr, utils.Pluralize(remaining, "credit"), requestCost, utils.FormatSeconds(rateLimitReset))
					return nil, err
				}
				err.Message = fmt.Sprintf(noCreditsNoAuthErr, utils.FormatSeconds(rateLimitReset))
				return nil, err

			} else {
				if remaining > 0 {
					err.Message = fmt.Sprintf(moreCreditsRequiredAuthErr, utils.Pluralize(remaining, "credit"), requestCost, utils.FormatSeconds(rateLimitReset))
					return nil, err
				}
				err.Message = fmt.Sprintf(noCreditsAuthErr, utils.FormatSeconds(rateLimitReset))
				return nil, err
			}
		}

		if resp.StatusCode == http.StatusInternalServerError {
			err.Message = "internal server error - please try again later"
			return nil, err
		}

		err.Message = fmt.Sprintf("unknown error response: %s", data.Error.Type)
		return nil, err
	}

	var bodyReader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "br" {
		bodyReader = brotli.NewReader(bodyReader)
	}

	res := &MeasurementCreateResponse{}
	err = json.NewDecoder(bodyReader).Decode(res)
	if err != nil {
		return nil, &MeasurementError{
			Message: fmt.Sprintf("invalid post measurement format returned - please report this bug: %s", err),
		}
	}

	return res, nil
}

func (c *client) GetMeasurement(ctx context.Context, id string) (*Measurement, error) {
	respBytes, err := c.GetMeasurementRaw(ctx, id)
	if err != nil {
		return nil, err
	}
	m := &Measurement{}
	err = json.Unmarshal(respBytes, m)
	if err != nil {
		return nil, &MeasurementError{
			Message: fmt.Sprintf("invalid get measurement format returned: %v %s", err, string(respBytes)),
		}
	}
	return m, nil
}

func (c *client) AwaitMeasurement(ctx context.Context, id string) (*Measurement, error) {
	respBytes, err := c.GetMeasurementRaw(ctx, id)
	if err != nil {
		return nil, err
	}
	m := &Measurement{}
	err = json.Unmarshal(respBytes, m)
	if err != nil {
		return nil, &MeasurementError{
			Message: fmt.Sprintf("invalid get measurement format returned: %v %s", err, string(respBytes)),
		}
	}
	for m.Status == StatusInProgress {
		time.Sleep(500 * time.Millisecond)
		respBytes, err := c.GetMeasurementRaw(ctx, id)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(respBytes, m)
		if err != nil {
			return nil, &MeasurementError{
				Message: fmt.Sprintf("invalid get measurement format returned: %v %s", err, string(respBytes)),
			}
		}
	}
	return m, nil
}

func (c *client) GetMeasurementRaw(ctx context.Context, id string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.apiURL+"/measurements/"+id, nil)
	if err != nil {
		return nil, &MeasurementError{Message: "failed to create request"}
	}

	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept-Encoding", "br")

	etag := c.getETag(id)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &MeasurementError{Message: "request failed"}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotModified {
		err := &MeasurementError{
			Code: resp.StatusCode,
		}
		if resp.StatusCode == http.StatusNotFound {
			err.Message = "measurement not found"
			return nil, err
		}

		if resp.StatusCode == http.StatusInternalServerError {
			err.Message = "internal server error - please try again later"
			return nil, err
		}
		err.Message = fmt.Sprintf("response code %d", resp.StatusCode)
		return nil, err
	}

	if resp.StatusCode == http.StatusNotModified {
		respBytes := c.getCachedResponse(id)
		if respBytes == nil {
			return nil, &MeasurementError{Message: "response not found in etags cache"}
		}
		return respBytes, nil
	}

	var bodyReader io.Reader = resp.Body

	if resp.Header.Get("Content-Encoding") == "br" {
		bodyReader = brotli.NewReader(bodyReader)
	}

	// Read the response body
	respBytes, err := io.ReadAll(bodyReader)
	if err != nil {
		return nil, &MeasurementError{Message: "failed to read response body"}
	}

	// save etag and response to cache
	c.cacheResponse(id, resp.Header.Get("ETag"), respBytes)

	return respBytes, nil
}

func DecodePingTimings(timings json.RawMessage) ([]PingTiming, error) {
	t := []PingTiming{}
	err := json.Unmarshal(timings, &t)
	if err != nil {
		return nil, &MeasurementError{Message: "invalid timings format returned (ping)"}
	}
	return t, nil
}

func DecodePingStats(stats json.RawMessage) (*PingStats, error) {
	s := &PingStats{}
	err := json.Unmarshal(stats, s)
	if err != nil {
		return nil, &MeasurementError{Message: "invalid stats format returned"}
	}
	return s, nil
}

func DecodeTracerouteHops(hops json.RawMessage) ([]TracerouteHop, error) {
	t := []TracerouteHop{}
	err := json.Unmarshal(hops, &t)
	if err != nil {
		return nil, &MeasurementError{Message: "invalid hops format returned"}
	}
	return t, nil
}

func DecodeDNSAnswers(answers json.RawMessage) ([]DNSAnswer, error) {
	a := []DNSAnswer{}
	err := json.Unmarshal(answers, &a)
	if err != nil {
		return nil, &MeasurementError{Message: "invalid answers format returned"}
	}
	return a, nil
}

func DecodeTraceDNSHops(hops json.RawMessage) ([]TraceDNSHop, error) {
	t := []TraceDNSHop{}
	err := json.Unmarshal(hops, &t)
	if err != nil {
		return nil, &MeasurementError{Message: "invalid hops format returned"}
	}
	return t, nil
}

func DecodeDNSTimings(timings json.RawMessage) (*DNSTimings, error) {
	t := &DNSTimings{}
	err := json.Unmarshal(timings, t)
	if err != nil {
		return nil, &MeasurementError{Message: "invalid timings format returned (other)"}
	}
	return t, nil
}

func DecodeMTRHops(hops json.RawMessage) ([]MTRHop, error) {
	t := []MTRHop{}
	err := json.Unmarshal(hops, &t)
	if err != nil {
		return nil, &MeasurementError{Message: "invalid hops format returned"}
	}
	return t, nil
}

func DecodeHTTPHeaders(headers json.RawMessage) (map[string]string, error) {
	h := map[string]string{}
	err := json.Unmarshal(headers, &h)
	if err != nil {
		return nil, &MeasurementError{Message: "invalid headers format returned"}
	}
	return h, nil
}

func DecodeHTTPTimings(timings json.RawMessage) (*HTTPTimings, error) {
	t := &HTTPTimings{}
	err := json.Unmarshal(timings, t)
	if err != nil {
		return nil, &MeasurementError{Message: "invalid timings format returned (other)"}
	}
	return t, nil
}
