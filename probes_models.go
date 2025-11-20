package globalping

import (
	"fmt"
	"net/http"
)

// https://globalping.io/docs/api.globalping.io#get-/v1/probes

// ProbeLocation represents the probe location information
type ProbeLocation struct {
	Continent string  `json:"continent"` // A two-letter continent code
	Region    string  `json:"region"`    // A geographic region name based on UN Standard Country or Area Codes for Statistical Use (M49)
	Country   string  `json:"country"`   // A two-letter country code based on ISO 3166-1 alpha-2
	State     string  `json:"state"`     // A two-letter US state code (can be empty)
	City      string  `json:"city"`      // A city name in English
	ASN       int     `json:"asn"`       // An autonomous system number (ASN)
	Network   string  `json:"network"`   // A network name, such as "Google LLC" or "DigitalOcean, LLC"
	Latitude  float64 `json:"latitude"`  // The latitude of probe location
	Longitude float64 `json:"longitude"` // The longitude of probe location
}

// Probe represents a single probe in the Globalping network
type Probe struct {
	Version   string        `json:"version"`   // The probe version
	Location  ProbeLocation `json:"location"`  // The probe location information
	Tags      []string      `json:"tags"`      // An array of additional values to fine-tune probe selection
	Resolvers []string      `json:"resolvers"` // An array of the default resolvers configured on the probe
}

// ProbesResponse represents the response from the probes endpoint
type ProbesResponse []Probe

// ProbesError represents an error response from the probes endpoint
type ProbesError struct {
	StatusCode int         `json:"-"`
	Header     http.Header `json:"-"`
	Type       string      `json:"type"`
	Message    string      `json:"message"`
}

func (e *ProbesError) Error() string {
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// ProbesErrorResponse wraps a ProbesError
type ProbesErrorResponse struct {
	Error *ProbesError `json:"error"`
}
