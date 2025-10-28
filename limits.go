package globalping

import (
	"context"
	"encoding/json"
	"net/http"
)

func (c *client) Limits(ctx context.Context) (*LimitsResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.apiURL+"/limits", nil)
	if err != nil {
		return nil, &LimitsError{Message: "failed to create request - please report this bug"}
	}
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, &LimitsError{Message: "failed to get token: " + err.Error()}
	}
	if token != nil {
		req.Header.Set("Authorization", token.TokenType+" "+token.AccessToken)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &LimitsError{Message: "request failed - please try again later"}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errResp := &LimitsErrorResponse{
			Error: &LimitsError{
				Code:    resp.StatusCode,
				Type:    "unexpected_status_code",
				Message: "unexpected status code: " + resp.Status,
			},
		}
		json.NewDecoder(resp.Body).Decode(errResp)
		return nil, errResp.Error
	}
	limits := &LimitsResponse{}
	err = json.NewDecoder(resp.Body).Decode(limits)
	if err != nil {
		return nil, &LimitsError{Message: "invalid format returned - please report this bug"}
	}
	return limits, nil
}
