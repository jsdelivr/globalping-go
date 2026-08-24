package globalping

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/andybalholm/brotli"

	"github.com/stretchr/testify/assert"
)

const (
	defaultDate = "Thu, 13 Nov 2025 07:13:37 GMT"
)

func Test_ProbeResult_FailureSource(t *testing.T) {
	for _, test := range []struct {
		name     string
		response string
		expected FailureSource
	}{
		{name: "target", response: `{"failureSource":"target"}`, expected: FailureSourceTarget},
		{name: "resolver", response: `{"failureSource":"resolver"}`, expected: FailureSourceResolver},
		{name: "internal", response: `{"failureSource":"internal"}`, expected: FailureSourceInternal},
		{name: "omitted", response: `{}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var result ProbeResult

			err := json.Unmarshal([]byte(test.response), &result)

			assert.NoError(t, err)
			assert.Equal(t, test.expected, result.FailureSource)
		})
	}

	response, err := json.Marshal(ProbeResult{})
	assert.NoError(t, err)
	assert.NotContains(t, string(response), `"failureSource"`)
}

func Test_CreateMeasurement_Locations(t *testing.T) {
	for _, test := range []struct {
		name        string
		measurement *MeasurementCreate
		expected    string
		expectedErr string
	}{
		{
			name: "locations",
			measurement: &MeasurementCreate{
				Type:      MeasurementTypePing,
				Target:    "example.com",
				Locations: LocationOptions{{Country: "DE"}},
			},
			expected: `{"locations":[{"country":"DE"}],"type":"ping","target":"example.com"}`,
		},
		{
			name: "previous measurement",
			measurement: &MeasurementCreate{
				Type:      MeasurementTypePing,
				Target:    "example.com",
				Locations: PreviousMeasurementID("previous-measurement-id"),
			},
			expected: `{"locations":"previous-measurement-id","type":"ping","target":"example.com"}`,
		},
		{
			name: "nil interface",
			measurement: &MeasurementCreate{
				Type:   MeasurementTypePing,
				Target: "example.com",
			},
			expected: `{"type":"ping","target":"example.com"}`,
		},
		{
			name: "nil location options",
			measurement: &MeasurementCreate{
				Type:      MeasurementTypePing,
				Target:    "example.com",
				Locations: LocationOptions(nil),
			},
			expected: `{"type":"ping","target":"example.com"}`,
		},
		{
			name: "empty location options",
			measurement: &MeasurementCreate{
				Type:      MeasurementTypePing,
				Target:    "example.com",
				Locations: LocationOptions{},
			},
			expected: `{"type":"ping","target":"example.com"}`,
		},
		{
			name: "empty previous measurement",
			measurement: &MeasurementCreate{
				Type:      MeasurementTypePing,
				Target:    "example.com",
				Locations: PreviousMeasurementID(""),
			},
			expected: `{"type":"ping","target":"example.com"}`,
		},
		{
			name:        "nil measurement",
			expectedErr: "measurement is required",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			requestBody := make(chan []byte, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				assert.NoError(t, err)
				requestBody <- body
				w.WriteHeader(http.StatusAccepted)
				_, err = w.Write([]byte(`{"id":"abcd","probesCount":1}`))
				assert.NoError(t, err)
			}))
			defer server.Close()
			APIURL = server.URL

			client := NewClient(Config{})
			res, err := client.CreateMeasurement(t.Context(), test.measurement)

			if test.expectedErr != "" {
				assert.Nil(t, res)
				assert.EqualError(t, err, test.expectedErr)

				return
			}

			if !assert.NoError(t, err) {
				return
			}

			assert.Equal(t, &MeasurementCreateResponse{
				ID:          "abcd",
				ProbesCount: 1,
			}, res)
			assert.JSONEq(t, test.expected, string(<-requestBody))
		})
	}
}

func Test_CreateMeasurement_Authorized(t *testing.T) {
	server := generateServerAuthorized(`{"id":"abcd","probesCount":1}`)
	defer server.Close()

	client := NewClient(Config{
		AuthToken: "secret",
	})

	opts := &MeasurementCreate{Locations: LocationOptions{{Magic: "world"}}}
	res, err := client.CreateMeasurement(t.Context(), opts)

	assert.NoError(t, err)
	assert.Equal(t, &MeasurementCreateResponse{
		ID:          "abcd",
		ProbesCount: 1,
	}, res)
}

func Test_CreateMeasurement_Authorized_SetToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer new_token" {
			w.Header().Set("Date", defaultDate)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error": {"type": "unauthorized", "message": "Unauthorized."}}`))

			return
		}

		w.WriteHeader(http.StatusAccepted)
		_, err := w.Write([]byte(`{"id":"abcd","probesCount":1}`))

		if err != nil {
			panic(err)
		}
	}))
	defer server.Close()

	APIURL = server.URL

	client := NewClient(Config{
		AuthToken: "secret",
	})

	client.SetToken("new_token")

	opts := &MeasurementCreate{Locations: LocationOptions{{Magic: "world"}}}
	res, err := client.CreateMeasurement(t.Context(), opts)

	assert.NoError(t, err)
	assert.Equal(t, &MeasurementCreateResponse{
		ID:          "abcd",
		ProbesCount: 1,
	}, res)
}

func Test_CreateMeasurement_AuthorizedError(t *testing.T) {
	server := generateServerAuthorized(`{"id":"abcd","probesCount":1}`)
	defer server.Close()

	client := NewClient(Config{})

	opts := &MeasurementCreate{Locations: LocationOptions{{Magic: "world"}}}
	res, err := client.CreateMeasurement(t.Context(), opts)

	assert.Nil(t, res)
	assert.Equal(t, &MeasurementError{
		StatusCode: 401,
		Header: http.Header{
			"Content-Length": []string{"63"},
			"Content-Type":   []string{"text/plain; charset=utf-8"},
			"Date":           []string{defaultDate},
		},
		Type:    "unauthorized",
		Message: "Unauthorized.",
	}, err)
}

func Test_CreateMeasurement_ValidationError(t *testing.T) {
	server := generateServer(`{
    "error": {
        "message": "Validation Failed",
        "type": "validation_error",
        "params": {
			"target": "\"target\" does not match any of the allowed types"
        }
	},
	"links": {
		"documentation": "https://globalping.io/docs/api.globalping.io#post-/v1/measurements"
    }}`, 400)
	defer server.Close()

	client := NewClient(Config{})

	opts := &MeasurementCreate{Locations: LocationOptions{{Magic: "world"}}}
	res, err := client.CreateMeasurement(t.Context(), opts)

	assert.Nil(t, res)
	assert.Equal(t, &MeasurementError{
		StatusCode: 400,
		Header: http.Header{
			"Content-Length": []string{"299"},
			"Content-Type":   []string{"text/plain; charset=utf-8"},
			"Date":           []string{defaultDate},
		},
		Type:    "validation_error",
		Message: "Validation Failed",
		Params: map[string]any{
			"target": "\"target\" does not match any of the allowed types",
		},
		Links: &DocumentationLinks{
			Documentation: "https://globalping.io/docs/api.globalping.io#post-/v1/measurements",
		},
	}, err)
}

func Test_GetMeasurement_ErrorLinks(t *testing.T) {
	server := generateServer(`{
		"error": {
			"type": "not_found",
			"message": "Couldn't find the requested item."
		},
		"links": {
			"documentation": "https://globalping.io/docs/api.globalping.io#get-/v1/measurements/-id-"
		}
	}`, http.StatusNotFound)
	defer server.Close()

	client := NewClient(Config{})
	res, err := client.GetMeasurementRaw(t.Context(), "missing")

	assert.Nil(t, res)
	var measurementErr *MeasurementError

	if assert.ErrorAs(t, err, &measurementErr) {
		assert.Equal(t, &DocumentationLinks{
			Documentation: "https://globalping.io/docs/api.globalping.io#get-/v1/measurements/-id-",
		}, measurementErr.Links)
	}
}

func Test_GetMeasurement_Ping(t *testing.T) {
	server := generateServer(`{
	"id": "abcd",
	"type": "ping",
	"status": "finished",
	"createdAt": "2023-02-17T18:11:52.825Z",
	"updatedAt": "2023-02-17T18:11:53.969Z",
	"probesCount": 1,
	"locations": [{
		"continent": "EU",
		"region": "Western Europe",
		"country": "DE",
		"state": "HE",
		"city": "Frankfurt",
		"asn": 1234,
		"network": "Example Network",
		"tags": ["datacenter-network"],
		"magic": "DE+datacenter",
		"limit": 1
	}],
	"limit": 1,
	"measurementOptions": {
		"packets": 3,
		"protocol": "ICMP",
		"port": 80,
		"ipVersion": 4
	},
	"results": [
		{
		"probe": {
			"continent": "NA",
			"region": "Northern America",
			"country": "CA",
			"state": null,
			"city": "City",
			"asn": 7794,
			"longitude": -80.2222,
			"latitude": 43.3662,
			"network": "Network",
			"tags": [],
			"resolvers": [
			"1.1.1.1",
			"8.8.4.4"
			]
		},
		"result": {
			"status": "finished",
			"rawOutput": "PING",
			"resolvedAddress": "1.1.1.1",
			"resolvedHostname": "1.1.1.1:",
			"timings": [],
			"stats": {
				"min": 24.891,
				"max": 28.193,
				"avg": 27.088,
				"total": 3,
				"loss": 0,
				"rcv": 3,
				"drop": 0
			}
		}
	}]}`, http.StatusOK)
	defer server.Close()

	client := NewClient(Config{})

	res, err := client.GetMeasurement(t.Context(), "abcd")

	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, "abcd", res.ID)
	assert.Equal(t, MeasurementTypePing, res.Type)
	assert.Equal(t, MeasurementStatusFinished, res.Status)
	assert.Equal(t, "2023-02-17T18:11:52.825Z", res.CreatedAt)
	assert.Equal(t, "2023-02-17T18:11:53.969Z", res.UpdatedAt)
	assert.Equal(t, 1, res.ProbesCount)
	assert.Equal(t, []Locations{{
		Continent: "EU",
		Region:    "Western Europe",
		Country:   "DE",
		State:     "HE",
		City:      "Frankfurt",
		ASN:       1234,
		Network:   "Example Network",
		Tags:      []string{"datacenter-network"},
		Magic:     "DE+datacenter",
		Limit:     1,
	}}, res.Locations)

	if assert.NotNil(t, res.Limit) {
		assert.Equal(t, 1, *res.Limit)
	}

	assert.Equal(t, &MeasurementOptions{
		Protocol:  "ICMP",
		Port:      80,
		Packets:   3,
		IPVersion: IPVersion4,
	}, res.Options)
	assert.Equal(t, 1, len(res.Results))

	assert.Equal(t, "NA", res.Results[0].Probe.Continent)
	assert.Equal(t, "Northern America", res.Results[0].Probe.Region)
	assert.Equal(t, "CA", res.Results[0].Probe.Country)
	assert.Equal(t, "", res.Results[0].Probe.State)
	assert.Equal(t, "City", res.Results[0].Probe.City)
	assert.Equal(t, 7794, res.Results[0].Probe.ASN)
	assert.Equal(t, "Network", res.Results[0].Probe.Network)
	assert.Equal(t, 0, len(res.Results[0].Probe.Tags))
	assert.Equal(t, 43.3662, res.Results[0].Probe.Latitude)
	assert.Equal(t, -80.2222, res.Results[0].Probe.Longitude)
	assert.Equal(t, []string{"1.1.1.1", "8.8.4.4"}, res.Results[0].Probe.Resolvers)

	assert.Equal(t, "PING", res.Results[0].Result.RawOutput)
	assert.Equal(t, "1.1.1.1", res.Results[0].Result.ResolvedAddress)
	stats, err := DecodePingStats(res.Results[0].Result.StatsRaw)
	assert.NoError(t, err)
	assert.Equal(t, float64(27.088), stats.Avg)
	assert.Equal(t, float64(28.193), stats.Max)
	assert.Equal(t, float64(24.891), stats.Min)
	assert.Equal(t, 3, stats.Total)
	assert.Equal(t, 3, stats.Rcv)
	assert.Equal(t, 0, stats.Drop)
	assert.Equal(t, float64(0), stats.Loss)
}

func Test_GetMeasurement_Traceroute(t *testing.T) {
	server := generateServer(`{
	"id": "abcd",
	"type": "traceroute",
	"status": "finished",
	"createdAt": "2023-02-23T07:55:23.414Z",
	"updatedAt": "2023-02-23T07:55:25.496Z",
	"probesCount": 1,
	"results": [
		{
		"probe": {
			"continent": "EU",
			"region": "Northern Europe",
			"country": "GB",
			"state": null,
			"city": "London",
			"asn": 16276,
			"longitude": -0.1257,
			"latitude": 51.5085,
			"network": "OVH SAS",
			"tags": [],
			"resolvers": [
			"private"
			]
		},
		"result": {
			"rawOutput": "TRACEROUTE",
			"status": "finished",
			"resolvedAddress": "1.1.1.1",
			"resolvedHostname": "1.1.1.1",
			"hops": [
			{
				"resolvedHostname": "54.37.244.252",
				"resolvedAddress": "54.37.244.252",
				"timings": [
				{
					"rtt": 0.408
				},
				{
					"rtt": 0.502
				}
				]
			},
			{
				"resolvedHostname": "93.123.11.62",
				"resolvedAddress": "93.123.11.62",
				"timings": [
				{
					"rtt": 0.507
				},
				{
					"rtt": 0.524
				}
				]
			}
			]
	}}]}`, http.StatusOK)
	defer server.Close()

	client := NewClient(Config{})

	res, err := client.GetMeasurement(t.Context(), "abcd")

	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, "abcd", res.ID)
	assert.Equal(t, MeasurementTypeTraceroute, res.Type)
	assert.Equal(t, MeasurementStatusFinished, res.Status)
	assert.Equal(t, "2023-02-23T07:55:23.414Z", res.CreatedAt)
	assert.Equal(t, "2023-02-23T07:55:25.496Z", res.UpdatedAt)
	assert.Equal(t, 1, res.ProbesCount)
	assert.Nil(t, res.Locations)
	assert.Nil(t, res.Limit)
	assert.Nil(t, res.Options)
	assert.Equal(t, 1, len(res.Results))

	assert.Equal(t, "EU", res.Results[0].Probe.Continent)
	assert.Equal(t, "Northern Europe", res.Results[0].Probe.Region)
	assert.Equal(t, "GB", res.Results[0].Probe.Country)
	assert.Equal(t, "", res.Results[0].Probe.State)
	assert.Equal(t, "London", res.Results[0].Probe.City)
	assert.Equal(t, 16276, res.Results[0].Probe.ASN)
	assert.Equal(t, "OVH SAS", res.Results[0].Probe.Network)
	assert.Equal(t, 0, len(res.Results[0].Probe.Tags))

	assert.Equal(t, "TRACEROUTE", res.Results[0].Result.RawOutput)
	assert.Equal(t, "1.1.1.1", res.Results[0].Result.ResolvedAddress)
	assert.Equal(t, "1.1.1.1", res.Results[0].Result.ResolvedHostname)
}

func Test_GetMeasurement_DNS(t *testing.T) {
	server := generateServer(`{
	"id": "abcd",
	"type": "dns",
	"status": "finished",
	"createdAt": "2023-02-23T08:00:37.431Z",
	"updatedAt": "2023-02-23T08:00:37.640Z",
	"probesCount": 1,
	"results": [
		{
		"probe": {
			"continent": "EU",
			"region": "Western Europe",
			"country": "NL",
			"state": null,
			"city": "Amsterdam",
			"asn": 60404,
			"longitude": 4.8897,
			"latitude": 52.374,
			"network": "Liteserver",
			"tags": [],
			"resolvers": [
			"185.31.172.240",
			"89.188.29.4"
			]
		},
		"result": {
			"status": "finished",
			"statusCodeName": "NOERROR",
			"statusCode": 0,
			"rawOutput": "DNS",
			"answers": [
			{
				"name": "jsdelivr.com.",
				"type": "A",
				"ttl": 30,
				"class": "IN",
				"value": "92.223.84.84"
			}
			],
			"timings": {
			"total": 15
			},
			"resolver": "185.31.172.240"
		}
	}]}`, http.StatusOK)
	defer server.Close()
	client := NewClient(Config{})

	res, err := client.GetMeasurement(t.Context(), "abcd")

	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, "abcd", res.ID)
	assert.Equal(t, MeasurementTypeDNS, res.Type)
	assert.Equal(t, MeasurementStatusFinished, res.Status)
	assert.Equal(t, "2023-02-23T08:00:37.431Z", res.CreatedAt)
	assert.Equal(t, "2023-02-23T08:00:37.640Z", res.UpdatedAt)
	assert.Equal(t, 1, res.ProbesCount)
	assert.Equal(t, 1, len(res.Results))

	assert.Equal(t, "EU", res.Results[0].Probe.Continent)
	assert.Equal(t, "Western Europe", res.Results[0].Probe.Region)
	assert.Equal(t, "NL", res.Results[0].Probe.Country)
	assert.Equal(t, "", res.Results[0].Probe.State)
	assert.Equal(t, "Amsterdam", res.Results[0].Probe.City)
	assert.Equal(t, 60404, res.Results[0].Probe.ASN)
	assert.Equal(t, "Liteserver", res.Results[0].Probe.Network)
	assert.Equal(t, 0, len(res.Results[0].Probe.Tags))

	assert.Equal(t, "DNS", res.Results[0].Result.RawOutput)
	assert.Equal(t, TestStatusFinished, res.Results[0].Result.Status)
	assert.IsType(t, json.RawMessage{}, res.Results[0].Result.TimingsRaw)

	// Test timings
	timings, _ := DecodeDNSTimings(res.Results[0].Result.TimingsRaw)
	assert.Equal(t, float64(15), timings.Total)
}

func Test_GetMeasurement_MTR(t *testing.T) {
	server := generateServer(`{
	"id": "abcd",
	"type": "mtr",
	"status": "finished",
	"createdAt": "2023-02-23T08:08:25.187Z",
	"updatedAt": "2023-02-23T08:08:29.829Z",
	"probesCount": 1,
	"results": [
		{
		"probe": {
			"continent": "EU",
			"region": "Western Europe",
			"country": "NL",
			"state": null,
			"city": "Amsterdam",
			"asn": 54825,
			"longitude": 4.8897,
			"latitude": 52.374,
			"network": "Packet Host, Inc.",
			"tags": [],
			"resolvers": []
		},
		"result": {
			"status": "finished",
			"rawOutput": "MTR",
			"resolvedAddress": "92.223.84.84",
			"resolvedHostname": "92.223.84.84",
			"hops": [
			{
				"stats": {
				"min": 0.176,
				"max": 0.226,
				"avg": 0.2,
				"total": 3,
				"loss": 0,
				"rcv": 3,
				"drop": 0,
				"stDev": 0,
				"jMin": 0,
				"jMax": 0.2,
				"jAvg": 0.1
				},
				"asn": [],
				"timings": [
				{
					"rtt": 0.176
				},
				{
					"rtt": 0.216
				},
				{
					"rtt": 0.226
				}
				],
				"resolvedAddress": "172.19.66.225",
				"duplicate": false,
				"resolvedHostname": "172.19.66.225"
			},
			{
				"stats": {
				"min": 0.894,
				"max": 0.894,
				"avg": 0.9,
				"total": 1,
				"loss": 0,
				"rcv": 1,
				"drop": 0,
				"stDev": 0,
				"jMin": 0.9,
				"jMax": 0.9,
				"jAvg": 0.9
				},
				"asn": [
				199524
				],
				"timings": [
				{
					"rtt": 0.894
				}
				],
				"resolvedAddress": "92.223.84.84",
				"duplicate": true,
				"resolvedHostname": "92.223.84.84"
			}
			]
		}
	}]}`, http.StatusOK)
	defer server.Close()
	client := NewClient(Config{})

	res, err := client.GetMeasurement(t.Context(), "abcd")

	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, "abcd", res.ID)
	assert.Equal(t, MeasurementTypeMTR, res.Type)
	assert.Equal(t, MeasurementStatusFinished, res.Status)
	assert.Equal(t, "2023-02-23T08:08:25.187Z", res.CreatedAt)
	assert.Equal(t, "2023-02-23T08:08:29.829Z", res.UpdatedAt)
	assert.Equal(t, 1, res.ProbesCount)
	assert.Equal(t, 1, len(res.Results))

	assert.Equal(t, "EU", res.Results[0].Probe.Continent)
	assert.Equal(t, "Western Europe", res.Results[0].Probe.Region)
	assert.Equal(t, "NL", res.Results[0].Probe.Country)
	assert.Equal(t, "", res.Results[0].Probe.State)
	assert.Equal(t, "Amsterdam", res.Results[0].Probe.City)
	assert.Equal(t, 54825, res.Results[0].Probe.ASN)
	assert.Equal(t, "Packet Host, Inc.", res.Results[0].Probe.Network)
	assert.Equal(t, 0, len(res.Results[0].Probe.Tags))

	assert.Equal(t, "MTR", res.Results[0].Result.RawOutput)
	assert.Equal(t, TestStatusFinished, res.Results[0].Result.Status)
	assert.IsType(t, json.RawMessage{}, res.Results[0].Result.TimingsRaw)
}

func Test_GetMeasurement_HTTP(t *testing.T) {
	server := generateServer(`{
	"id": "abcd",
	"type": "http",
	"status": "finished",
	"createdAt": "2023-02-23T08:16:11.335Z",
	"updatedAt": "2023-02-23T08:16:12.548Z",
	"probesCount": 1,
	"results": [
		{
		"probe": {
			"continent": "NA",
			"region": "Northern America",
			"country": "CA",
			"state": null,
			"city": "Pembroke",
			"asn": 577,
			"longitude": -77.1162,
			"latitude": 45.8168,
			"network": "Bell Canada",
			"tags": [],
			"resolvers": [
			"private",
			"private"
			]
		},
		"result": {
			"status": "finished",
			"resolvedAddress": "5.101.222.14",
			"headers": {
			"server": "nginx",
			"date": "Thu, 23 Feb 2023 08:16:12 GMT",
			"content-type": "text/html; charset=utf-8",
			"connection": "close",
			"location": "/",
			"cf-ray": "79de849d3fa30c33-AMS",
			"vary": "Accept-Encoding",
			"cf-cache-status": "DYNAMIC",
			"x-render-origin-server": "Render",
			"x-response-time": "1ms",
			"cache": "MISS, MISS",
			"x-id": "am3-up-gc88, td2-up-gc10",
			"x-nginx": "nginx-be, nginx-be"
			},
			"rawHeaders": "Server: nginx\nDate: Thu, 23 Feb 2023 08:16:12 GMT\nContent-Type: text/html; charset=utf-8\nConnection: close\nLocation: /\nCF-Ray: 79de849d3fa30c33-AMS\nVary: Accept-Encoding\nCF-Cache-Status: DYNAMIC\nx-render-origin-server: Render\nx-response-time: 1ms\nCache: MISS\nX-ID: am3-up-gc88\nX-NGINX: nginx-be\nCache: MISS\nX-ID: td2-up-gc10\nX-NGINX: nginx-be",
			"rawBody": null,
			"statusCode": 301,
			"statusCodeName": "Moved Permanently",
			"timings": {
			"total": 583,
			"download": 18,
			"firstByte": 450,
			"dns": 24,
			"tls": 70,
			"tcp": 19
			},
			"tls": {
			"authorized": true,
			"createdAt": "2023-02-18T00:00:00.000Z",
			"expiresAt": "2024-02-18T23:59:59.000Z",
			"issuer": {
				"C": "GB",
				"ST": "Greater Manchester",
				"L": "Salford",
				"O": "Sectigo Limited",
				"CN": "Sectigo RSA Domain Validation Secure Server CA"
			},
			"subject": {
				"CN": "jsdelivr.com",
				"alt": "DNS:jsdelivr.com, DNS:data.jsdelivr.com, DNS:www.jsdelivr.com"
			}
			},
			"rawOutput": "HTTP"
		}
	}]}`, http.StatusOK)
	defer server.Close()
	client := NewClient(Config{})

	res, err := client.GetMeasurement(t.Context(), "abcd")

	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, "abcd", res.ID)
	assert.Equal(t, MeasurementTypeHTTP, res.Type)
	assert.Equal(t, MeasurementStatusFinished, res.Status)
	assert.Equal(t, "2023-02-23T08:16:11.335Z", res.CreatedAt)
	assert.Equal(t, "2023-02-23T08:16:12.548Z", res.UpdatedAt)
	assert.Equal(t, 1, res.ProbesCount)
	assert.Equal(t, 1, len(res.Results))

	assert.Equal(t, "NA", res.Results[0].Probe.Continent)
	assert.Equal(t, "Northern America", res.Results[0].Probe.Region)
	assert.Equal(t, "CA", res.Results[0].Probe.Country)
	assert.Equal(t, "", res.Results[0].Probe.State)
	assert.Equal(t, "Pembroke", res.Results[0].Probe.City)
	assert.Equal(t, 577, res.Results[0].Probe.ASN)
	assert.Equal(t, "Bell Canada", res.Results[0].Probe.Network)
	assert.Equal(t, 0, len(res.Results[0].Probe.Tags))

	assert.Equal(t, "HTTP", res.Results[0].Result.RawOutput)
	assert.Equal(t, TestStatusFinished, res.Results[0].Result.Status)
	assert.IsType(t, json.RawMessage{}, res.Results[0].Result.TimingsRaw)

	// Test timings
	timings, _ := DecodeHTTPTimings(res.Results[0].Result.TimingsRaw)
	assert.Equal(t, 583, timings.Total)
	assert.Equal(t, 18, timings.Download)
	assert.Equal(t, 450, timings.FirstByte)
	assert.Equal(t, 24, timings.DNS)
	assert.Equal(t, 70, timings.TLS)
	assert.Equal(t, 19, timings.TCP)
}

func Test_GetMeasurement_WithEtag(t *testing.T) {
	id1 := "123abc"
	id2 := "567xyz"

	cacheMissCount := 0
	cacheHitCount := 0

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		id := parts[len(parts)-1]

		etag := func(id string) string {
			return "etag-" + id
		}

		if r.Header.Get("If-None-Match") == etag(id) {
			// cache hit
			cacheHitCount++
			w.Header().Set("ETag", etag(id))
			w.WriteHeader(http.StatusNotModified)

			return
		}

		// cache miss, return full response
		cacheMissCount++
		m := &Measurement{
			ID: id,
		}

		w.Header().Set("ETag", etag(id))

		err := json.NewEncoder(w).Encode(m)
		assert.NoError(t, err)
	}))

	APIURL = s.URL

	defer s.Close()

	client := NewClient(Config{})

	// first request for id1
	m, err := client.GetMeasurement(t.Context(), id1)
	assert.NoError(t, err)

	assert.Equal(t, id1, m.ID)

	// first request for id1
	m, err = client.GetMeasurement(t.Context(), id2)
	assert.NoError(t, err)

	assert.Equal(t, id2, m.ID)

	// second request for id1
	m, err = client.GetMeasurement(t.Context(), id2)
	assert.NoError(t, err)

	assert.Equal(t, id2, m.ID)

	assert.Equal(t, 1, cacheHitCount)
	assert.Equal(t, 2, cacheMissCount)
}

func Test_GetMeasurement_WithBrotli(t *testing.T) {
	id := "123abc"

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		id := parts[len(parts)-1]

		assert.Equal(t, "br", r.Header.Get("Accept-Encoding"))

		m := &Measurement{
			ID: id,
		}

		w.Header().Set("Content-Encoding", "br")

		rW := brotli.NewWriter(w)

		defer func() {
			_ = rW.Close()
		}()

		err := json.NewEncoder(rW).Encode(m)
		assert.NoError(t, err)
	}))

	APIURL = s.URL

	defer s.Close()

	client := NewClient(Config{})

	m, err := client.GetMeasurement(t.Context(), id)
	assert.NoError(t, err)

	assert.Equal(t, id, m.ID)
}

func Test_GetMeasurementRaw_Json(t *testing.T) {
	server := generateServer(`{"id":"abcd"}`, http.StatusOK)
	defer server.Close()

	client := NewClient(Config{})
	res, err := client.GetMeasurementRaw(t.Context(), "abcd")

	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, `{"id":"abcd"}`, string(res))
}

func Test_AwaitMeasurement(t *testing.T) {
	const (
		measurementID             = "abcd"
		inProgressResponse        = `{"id":"abcd", "status":"in-progress"}`
		inProgressTimeoutResponse = `{"id":"abcd", "status":"in-progress", "timeout":5}`
		inProgressLaterTimeout    = `{"id":"abcd", "status":"in-progress", "timeout":30}`
		finishedResponse          = `{"id":"abcd", "status":"finished"}`
		finishedTimeoutResponse   = `{"id":"abcd", "status":"finished", "timeout":5}`
		timeoutError              = "timed out waiting for measurement abcd to finish: context deadline exceeded"
	)

	t.Run("calculates the timeout from the first response", func(t *testing.T) {
		for _, test := range []struct {
			name          string
			firstResponse string
			timeout       time.Duration
		}{
			{
				name:          "uses 45 seconds when timeout is omitted",
				firstResponse: inProgressResponse,
				timeout:       awaitMeasurementDefaultTimeout,
			},
			{
				name:          "adds 10 seconds and ignores a later timeout",
				firstResponse: inProgressTimeoutResponse,
				timeout:       5*time.Second + awaitMeasurementTimeoutBuffer,
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					requestCount := 0
					transport := roundTripFunc(func(_ *http.Request) string {
						requestCount++

						if requestCount == 1 {
							return test.firstResponse
						}

						return inProgressLaterTimeout
					})
					client := NewClient(Config{HTTPClient: &http.Client{Transport: transport, Timeout: 30 * time.Second}})
					start := time.Now()

					res, err := client.AwaitMeasurement(context.Background(), measurementID)

					assert.Nil(t, res)
					assert.EqualError(t, err, timeoutError)
					assert.ErrorIs(t, err, context.DeadlineExceeded)
					assert.Equal(t, test.timeout+measurementPollInterval, time.Since(start))
					assert.Equal(t, int(test.timeout/measurementPollInterval)+2, requestCount)
				})
			})
		}
	})

	t.Run("allows a completed response at exactly the timeout limit", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			requestCount := 0
			requestAtLimit := int(awaitMeasurementDefaultTimeout/measurementPollInterval) + 1
			transport := roundTripFunc(func(_ *http.Request) string {
				requestCount++

				if requestCount == requestAtLimit {
					return finishedResponse
				}

				return inProgressResponse
			})
			client := NewClient(Config{HTTPClient: &http.Client{Transport: transport, Timeout: 30 * time.Second}})
			start := time.Now()

			res, err := client.AwaitMeasurement(context.Background(), measurementID)

			if assert.NoError(t, err) && assert.NotNil(t, res) {
				assert.Equal(t, MeasurementStatusFinished, res.Status)
			}

			assert.Equal(t, awaitMeasurementDefaultTimeout, time.Since(start))
			assert.Equal(t, requestAtLimit, requestCount)
		})
	})

	t.Run("counts the initial request time before checking completion", func(t *testing.T) {
		initialRequestDuration := 5*time.Second + awaitMeasurementTimeoutBuffer + time.Nanosecond

		for _, test := range []struct {
			name     string
			response string
			finished bool
		}{
			{
				name:     "times out an in-progress response",
				response: inProgressTimeoutResponse,
			},
			{
				name:     "returns a finished response beyond the limit",
				response: finishedTimeoutResponse,
				finished: true,
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					requestCount := 0
					transport := roundTripFunc(func(_ *http.Request) string {
						requestCount++
						time.Sleep(initialRequestDuration)

						return test.response
					})
					client := NewClient(Config{HTTPClient: &http.Client{Transport: transport, Timeout: 30 * time.Second}})
					start := time.Now()

					res, err := client.AwaitMeasurement(context.Background(), measurementID)

					if test.finished {
						if assert.NoError(t, err) && assert.NotNil(t, res) {
							assert.Equal(t, measurementID, res.ID)
							assert.Equal(t, MeasurementStatusFinished, res.Status)
						}
					} else {
						assert.Nil(t, res)
						assert.EqualError(t, err, timeoutError)
						assert.ErrorIs(t, err, context.DeadlineExceeded)
					}

					assert.Equal(t, initialRequestDuration, time.Since(start))
					assert.Equal(t, 1, requestCount)
				})
			})
		}
	})

	t.Run("honors context cancellation while waiting to poll", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			requestCount := 0
			transport := roundTripFunc(func(_ *http.Request) string {
				requestCount++

				return inProgressResponse
			})
			client := NewClient(Config{HTTPClient: &http.Client{Transport: transport, Timeout: 30 * time.Second}})
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(measurementPollInterval/2, cancel)
			start := time.Now()

			res, err := client.AwaitMeasurement(ctx, measurementID)

			assert.Nil(t, res)
			assert.ErrorIs(t, err, context.Canceled)
			assert.Equal(t, measurementPollInterval/2, time.Since(start))
			assert.Equal(t, 1, requestCount)
		})
	})

	t.Run("honors an earlier caller deadline while waiting to poll", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			requestCount := 0
			transport := roundTripFunc(func(_ *http.Request) string {
				requestCount++

				return inProgressTimeoutResponse
			})
			client := NewClient(Config{HTTPClient: &http.Client{Transport: transport, Timeout: 30 * time.Second}})
			ctx, cancel := context.WithTimeout(context.Background(), measurementPollInterval/2)
			defer cancel()
			start := time.Now()

			res, err := client.AwaitMeasurement(ctx, measurementID)

			assert.Nil(t, res)
			assert.ErrorIs(t, err, context.DeadlineExceeded)
			assert.Equal(t, measurementPollInterval/2, time.Since(start))
			assert.Equal(t, 1, requestCount)
		})
	})
}

type roundTripFunc func(*http.Request) string

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(f(request))),
	}, nil
}

func generateServer(json string, statusCode int) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Date", defaultDate)
		w.WriteHeader(statusCode)
		_, err := w.Write([]byte(json))

		if err != nil {
			panic(err)
		}
	}))

	APIURL = server.URL

	return server
}

func generateServerAuthorized(json string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			w.Header().Set("Date", defaultDate)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error": {"type": "unauthorized", "message": "Unauthorized."}}`))

			return
		}

		w.WriteHeader(http.StatusAccepted)
		_, err := w.Write([]byte(json))

		if err != nil {
			panic(err)
		}
	}))

	APIURL = server.URL

	return server
}
