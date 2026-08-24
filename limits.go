package globalping

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
)

func (c *client) Limits(ctx context.Context) (*LimitsResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, APIURL+"/limits", nil)

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

	defer func() {
		_ = res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		b, err := io.ReadAll(res.Body)

		if err != nil {
			return nil, newHTTPErrorWithCause(res.StatusCode, res.Header, err)
		}

		resErr := &LimitsErrorResponse{}

		err = json.Unmarshal(b, resErr)

		if err != nil || resErr.Error == nil {
			return nil, newHTTPError(res.StatusCode, res.Header)
		}

		resErr.Error.StatusCode = res.StatusCode
		resErr.Error.Header = res.Header

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
