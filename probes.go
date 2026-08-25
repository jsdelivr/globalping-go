package globalping

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
)

func (c *client) Probes(ctx context.Context) (*ProbesResponse, error) {
	req, err := c.newRequest(ctx, http.MethodGet, APIURL+"/probes", nil)

	if err != nil {
		return nil, err
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

		resErr := &ProbesErrorResponse{}

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

	probes := &ProbesResponse{}
	err = json.Unmarshal(b, probes)

	if err != nil {
		return nil, err
	}

	return probes, nil
}
