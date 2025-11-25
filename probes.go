package globalping

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
)

func (c *client) Probes(ctx context.Context) (*ProbesResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", APIURL+"/probes", nil)
	if err != nil {
		return nil, err
	}

	token := c.authToken.Load()
	if token != nil {
		req.Header.Set("Authorization", "Bearer "+*token)
	}

	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		b, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}

		resErr := &ProbesErrorResponse{
			Error: &ProbesError{
				StatusCode: res.StatusCode,
				Header:     res.Header,
			},
		}

		err = json.Unmarshal(b, resErr)
		if err != nil {
			return nil, err
		}
		return nil, resErr.Error
	}

	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	probes := &ProbesResponse{}
	err = json.Unmarshal(b, probes)
	if err != nil {
		return nil, err
	}

	return probes, nil
}
