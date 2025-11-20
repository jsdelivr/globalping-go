package globalping

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Probes(t *testing.T) {
	expectedResponse := &ProbesResponse{
		{
			Version: "0.27.0",
			Location: ProbeLocation{
				Continent: "NA",
				Region:    "Northern America",
				Country:   "US",
				State:     "CA",
				City:      "Los Angeles",
				ASN:       13335,
				Network:   "Cloudflare, Inc.",
				Latitude:  34.0522,
				Longitude: -118.2437,
			},
			Tags: []string{"datacenter-network"},
			Resolvers: []string{
				"2606:4700:4700::1111",
				"2606:4700:4700::1001",
				"1.1.1.1",
				"1.0.0.1",
			},
		},
		{
			Version: "0.27.0",
			Location: ProbeLocation{
				Continent: "EU",
				Region:    "Western Europe",
				Country:   "DE",
				City:      "Frankfurt",
				ASN:       24940,
				Network:   "Hetzner Online GmbH",
				Latitude:  50.1109,
				Longitude: 8.6821,
			},
			Tags: []string{"datacenter-network"},
			Resolvers: []string{
				"2a01:4ff:ff00::add:2",
				"2a01:4ff:ff00::add:1",
				"185.12.64.2",
				"185.12.64.1",
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/probes" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			b, _ := json.Marshal(expectedResponse)
			_, err := w.Write(b)
			if err != nil {
				t.Fatal(err)
			}
			return
		}
		t.Fatalf("unexpected request to %s", r.URL.Path)
	}))
	defer server.Close()

	APIURL = server.URL

	client := NewClient(Config{})

	res, err := client.Probes(t.Context())
	assert.Nil(t, err)
	assert.Equal(t, expectedResponse, res)
}
