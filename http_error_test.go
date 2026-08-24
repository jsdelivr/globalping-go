package globalping

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/stretchr/testify/assert"
)

type errorEndpoint struct {
	name           string
	call           func(context.Context, Client) error
	assertDetailed func(*testing.T, error)
}

func errorEndpoints() []errorEndpoint {
	return []errorEndpoint{
		{
			name: "create measurement",
			call: func(ctx context.Context, client Client) error {
				_, err := client.CreateMeasurement(ctx, &MeasurementCreate{
					Type:   MeasurementTypePing,
					Target: "example.com",
				})

				return err
			},
			assertDetailed: func(t *testing.T, err error) {
				var detailedErr *MeasurementError
				assert.ErrorAs(t, err, &detailedErr)
			},
		},
		{
			name: "get measurement",
			call: func(ctx context.Context, client Client) error {
				_, err := client.GetMeasurementRaw(ctx, "measurement-id")

				return err
			},
			assertDetailed: func(t *testing.T, err error) {
				var detailedErr *MeasurementError
				assert.ErrorAs(t, err, &detailedErr)
			},
		},
		{
			name: "probes",
			call: func(ctx context.Context, client Client) error {
				_, err := client.Probes(ctx)

				return err
			},
			assertDetailed: func(t *testing.T, err error) {
				var detailedErr *ProbesError
				assert.ErrorAs(t, err, &detailedErr)
			},
		},
		{
			name: "limits",
			call: func(ctx context.Context, client Client) error {
				_, err := client.Limits(ctx)

				return err
			},
			assertDetailed: func(t *testing.T, err error) {
				var detailedErr *LimitsError
				assert.ErrorAs(t, err, &detailedErr)
			},
		},
	}
}

func Test_HTTPError_FallbackBodies(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "empty"},
		{name: "plain text", body: "upstream unavailable"},
		{name: "malformed JSON", body: `{"error":`},
		{name: "HTML", body: `<html><body>Bad Gateway</body></html>`},
		{name: "unexpected JSON", body: `{"result":"unexpected"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("X-Error-Source", "test")
				w.WriteHeader(http.StatusBadGateway)
				_, err := w.Write([]byte(test.body))
				assert.NoError(t, err)
			}))
			defer server.Close()
			setAPIURL(t, server.URL)

			client := NewClient(Config{})
			_, err := client.CreateMeasurement(t.Context(), &MeasurementCreate{
				Type:   MeasurementTypePing,
				Target: "example.com",
			})

			var httpErr *HTTPError

			if assert.ErrorAs(t, err, &httpErr) {
				assert.Equal(t, http.StatusBadGateway, httpErr.StatusCode)
				assert.Equal(t, "test", httpErr.Header.Get("X-Error-Source"))
			}

			var measurementErr *MeasurementError
			assert.NotErrorAs(t, err, &measurementErr)
		})
	}
}

func Test_HTTPError_AllEndpoints(t *testing.T) {
	for _, endpoint := range errorEndpoints() {
		t.Run(endpoint.name, func(t *testing.T) {
			server := newErrorServer(t, "temporarily unavailable", false)
			defer server.Close()

			err := endpoint.call(t.Context(), NewClient(Config{}))

			var httpErr *HTTPError

			if assert.ErrorAs(t, err, &httpErr) {
				assert.Equal(t, http.StatusServiceUnavailable, httpErr.StatusCode)
				assert.Equal(t, "test", httpErr.Header.Get("X-Error-Source"))
			}
		})
	}
}

func Test_HTTPError_ResponseReadFailure(t *testing.T) {
	readErr := errors.New("response read failed")

	for _, endpoint := range errorEndpoints() {
		t.Run(endpoint.name, func(t *testing.T) {
			transport := errorRoundTripFunc(func(_ *http.Request) *http.Response {
				return &http.Response{
					StatusCode: http.StatusServiceUnavailable,
					Header: http.Header{
						"X-Error-Source": []string{"test"},
					},
					Body: io.NopCloser(errorReader{err: readErr}),
				}
			})
			client := NewClient(Config{HTTPClient: &http.Client{Transport: transport}})

			err := endpoint.call(t.Context(), client)

			var httpErr *HTTPError

			if assert.ErrorAs(t, err, &httpErr) {
				assert.Equal(t, http.StatusServiceUnavailable, httpErr.StatusCode)
				assert.Equal(t, "test", httpErr.Header.Get("X-Error-Source"))
			}

			assert.ErrorIs(t, err, readErr)
		})
	}
}

func Test_HTTPError_DetailedErrors(t *testing.T) {
	for _, endpoint := range errorEndpoints() {
		t.Run(endpoint.name, func(t *testing.T) {
			for _, test := range []struct {
				name string
				body string
			}{
				{
					name: "complete envelope",
					body: `{"error":{"type":"service_unavailable","message":"Try again later."}}`,
				},
				{name: "incomplete envelope", body: `{"error":{}}`},
			} {
				t.Run(test.name, func(t *testing.T) {
					server := newErrorServer(t, test.body, false)
					defer server.Close()

					err := endpoint.call(t.Context(), NewClient(Config{}))

					endpoint.assertDetailed(t, err)

					var httpErr *HTTPError

					if assert.ErrorAs(t, err, &httpErr) {
						assert.Equal(t, http.StatusServiceUnavailable, httpErr.StatusCode)
						assert.Equal(t, "test", httpErr.Header.Get("X-Error-Source"))
					}
				})
			}
		})
	}
}

func Test_MeasurementError_Brotli(t *testing.T) {
	for _, endpoint := range errorEndpoints()[:2] {
		t.Run(endpoint.name, func(t *testing.T) {
			server := newErrorServer(t, `{"error":{"type":"service_unavailable","message":"Try again later."}}`, true)
			defer server.Close()

			err := endpoint.call(t.Context(), NewClient(Config{}))

			var detailedErr *MeasurementError

			if assert.ErrorAs(t, err, &detailedErr) {
				assert.Equal(t, "service_unavailable", detailedErr.Type)
				assert.Equal(t, "Try again later.", detailedErr.Message)
			}
		})
	}
}

func Test_HTTPError_CorruptBrotliErrorBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "br")
		w.Header().Set("X-Error-Source", "test")
		w.WriteHeader(http.StatusBadGateway)
		_, err := w.Write([]byte("not a Brotli stream"))
		assert.NoError(t, err)
	}))
	defer server.Close()
	setAPIURL(t, server.URL)

	client := NewClient(Config{})
	_, err := client.GetMeasurementRaw(t.Context(), "measurement-id")

	var httpErr *HTTPError

	if assert.ErrorAs(t, err, &httpErr) {
		assert.Equal(t, http.StatusBadGateway, httpErr.StatusCode)
		assert.Equal(t, "test", httpErr.Header.Get("X-Error-Source"))
	}

	assert.Error(t, errors.Unwrap(err))
}

func setAPIURL(t *testing.T, url string) {
	t.Helper()

	previousAPIURL := APIURL
	t.Cleanup(func() { APIURL = previousAPIURL })
	APIURL = url
}

func newErrorServer(t *testing.T, body string, compressed bool) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Error-Source", "test")

		if compressed {
			assert.Equal(t, "br", r.Header.Get("Accept-Encoding"))
			w.Header().Set("Content-Encoding", "br")
		}

		w.WriteHeader(http.StatusServiceUnavailable)

		if compressed {
			writer := brotli.NewWriter(w)
			_, err := writer.Write([]byte(body))
			assert.NoError(t, err)
			assert.NoError(t, writer.Close())

			return
		}

		_, err := w.Write([]byte(body))
		assert.NoError(t, err)
	}))

	setAPIURL(t, server.URL)

	return server
}

type errorRoundTripFunc func(*http.Request) *http.Response

func (f errorRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request), nil
}

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}
