package globalping

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_DefaultUserAgentIncludesVersion(t *testing.T) {
	var userAgent string
	client := NewClient(Config{
		HTTPClient: &http.Client{
			Transport: roundTripFunc(func(request *http.Request) string {
				userAgent = request.Header.Get("User-Agent")

				return `{}`
			}),
		},
	})

	_, err := client.Limits(t.Context())

	assert.NoError(t, err)
	assert.Equal(t, "globalping-go/"+Version+" (https://github.com/jsdelivr/globalping-go)", userAgent)
}
