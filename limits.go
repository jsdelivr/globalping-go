package globalping

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
)

func (c *client) Limits(ctx context.Context) (*LimitsResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", APIURL+"/limits", nil)
	if err != nil {
		return nil, err
	}

	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
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

		resErr := &LimitsErrorResponse{
			Error: &LimitsError{
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

	limits := &LimitsResponse{}
	err = json.Unmarshal(b, limits)
	if err != nil {
		return nil, err
	}

	return limits, nil
}
