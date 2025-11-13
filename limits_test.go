package globalping

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Limits(t *testing.T) {
	expectedResponse := &LimitsResponse{
		RateLimits: RateLimits{
			Measurements: MeasurementsLimits{
				Create: MeasurementsCreateLimits{
					Type:      CreateLimitTypeUser,
					Limit:     1000,
					Remaining: 999,
					Reset:     600,
				},
			},
		},
		Credits: CreditLimits{
			Remaining: 1000,
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/limits" && r.Method == http.MethodGet {
			assert.Equal(t, "Bearer tok3n", r.Header.Get("Authorization"))
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

	client := NewClient(Config{
		AuthToken: "tok3n",
	})

	res, err := client.Limits(t.Context())
	assert.Nil(t, err)
	assert.Equal(t, expectedResponse, res)
}
