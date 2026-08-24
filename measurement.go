package globalping

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/andybalholm/brotli"
)

const (
	awaitMeasurementDefaultTimeout = 45 * time.Second
	awaitMeasurementTimeoutBuffer  = 10 * time.Second
	measurementPollInterval        = 500 * time.Millisecond
)

func (c *client) CreateMeasurement(ctx context.Context, measurement *MeasurementCreate) (*MeasurementCreateResponse, error) {
	if measurement == nil {
		return nil, errors.New("measurement is required")
	}

	data, err := json.Marshal(measurement)

	if err != nil {
		return nil, err
	}

	req, err := c.newRequest(ctx, http.MethodPost, APIURL+"/measurements", bytes.NewBuffer(data))

	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept-Encoding", "br")
	req.Header.Set("Content-Type", "application/json")

	res, err := c.http.Do(req)

	if err != nil {
		return nil, err
	}

	defer func() {
		_ = res.Body.Close()
	}()

	if res.StatusCode != http.StatusAccepted {
		b, err := io.ReadAll(res.Body)

		if err != nil {
			return nil, err
		}

		resErr := &MeasurementErrorResponse{
			Error: &MeasurementError{
				StatusCode: res.StatusCode,
				Header:     res.Header,
			},
		}

		err = json.Unmarshal(b, resErr)

		if err != nil {
			return nil, err
		}

		if resErr.Error == nil {
			resErr.Error = &MeasurementError{
				StatusCode: res.StatusCode,
				Header:     res.Header,
			}
		}

		resErr.Error.Links = resErr.Links

		return nil, resErr.Error
	}

	var bodyReader io.Reader = res.Body

	if res.Header.Get("Content-Encoding") == "br" {
		bodyReader = brotli.NewReader(bodyReader)
	}

	b, err := io.ReadAll(bodyReader)

	if err != nil {
		return nil, err
	}

	result := &MeasurementCreateResponse{}
	err = json.Unmarshal(b, result)

	if err != nil {
		return nil, err
	}

	return result, nil
}

func (c *client) GetMeasurement(ctx context.Context, id string) (*Measurement, error) {
	respBytes, err := c.GetMeasurementRaw(ctx, id)

	if err != nil {
		return nil, err
	}

	m := &Measurement{}
	err = json.Unmarshal(respBytes, m)

	if err != nil {
		return nil, err
	}

	return m, nil
}

func (c *client) AwaitMeasurement(ctx context.Context, id string) (*Measurement, error) {
	start := time.Now()

	respBytes, err := c.GetMeasurementRaw(ctx, id)

	if err != nil {
		return nil, err
	}

	m := &Measurement{}
	err = json.Unmarshal(respBytes, m)

	if err != nil {
		return nil, err
	}

	maxDuration := awaitMeasurementDefaultTimeout

	if m.Timeout != 0 {
		maxDuration = time.Duration(m.Timeout)*time.Second + awaitMeasurementTimeoutBuffer
	}

	for m.Status == MeasurementStatusInProgress {
		if time.Since(start) > maxDuration {
			return nil, fmt.Errorf("timed out waiting for measurement %s to finish", id)
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(measurementPollInterval):
		}

		respBytes, err := c.GetMeasurementRaw(ctx, id)

		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(respBytes, m)

		if err != nil {
			return nil, err
		}
	}

	return m, nil
}

func (c *client) GetMeasurementRaw(ctx context.Context, id string) ([]byte, error) {
	req, err := c.newRequest(ctx, http.MethodGet, APIURL+"/measurements/"+id, nil)

	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept-Encoding", "br")

	etag := c.getETag(id)

	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	res, err := c.http.Do(req)

	if err != nil {
		return nil, err
	}

	defer func() {
		_ = res.Body.Close()
	}()

	if res.StatusCode == http.StatusNotModified {
		b := c.getCachedResponse(id)

		if b == nil {
			return nil, &MeasurementError{
				Type:    "cache_error",
				Message: "cached response unavailable",
			}
		}

		return b, nil
	}

	if res.StatusCode != http.StatusOK {
		b, err := io.ReadAll(res.Body)

		if err != nil {
			return nil, err
		}

		resErr := &MeasurementErrorResponse{
			Error: &MeasurementError{
				StatusCode: res.StatusCode,
				Header:     res.Header,
			},
		}

		err = json.Unmarshal(b, resErr)

		if err != nil {
			return nil, err
		}

		if resErr.Error == nil {
			resErr.Error = &MeasurementError{
				StatusCode: res.StatusCode,
				Header:     res.Header,
			}
		}

		resErr.Error.Links = resErr.Links

		return nil, resErr.Error
	}

	var bodyReader io.Reader = res.Body

	if res.Header.Get("Content-Encoding") == "br" {
		bodyReader = brotli.NewReader(bodyReader)
	}

	b, err := io.ReadAll(bodyReader)

	if err != nil {
		return nil, err
	}

	// save etag and response to cache
	c.cacheResponse(id, res.Header.Get("ETag"), b)

	return b, nil
}

func DecodePingTimings(timings json.RawMessage) ([]PingTiming, error) {
	t := []PingTiming{}
	err := json.Unmarshal(timings, &t)

	if err != nil {
		return nil, &MeasurementError{Message: "invalid timings format returned (ping)"}
	}

	return t, nil
}

func DecodePingStats(stats json.RawMessage) (*PingStats, error) {
	s := &PingStats{}
	err := json.Unmarshal(stats, s)

	if err != nil {
		return nil, &MeasurementError{Message: "invalid stats format returned"}
	}

	return s, nil
}

func DecodeTracerouteHops(hops json.RawMessage) ([]TracerouteHop, error) {
	t := []TracerouteHop{}
	err := json.Unmarshal(hops, &t)

	if err != nil {
		return nil, &MeasurementError{Message: "invalid hops format returned"}
	}

	return t, nil
}

func DecodeDNSAnswers(answers json.RawMessage) ([]DNSAnswer, error) {
	a := []DNSAnswer{}
	err := json.Unmarshal(answers, &a)

	if err != nil {
		return nil, &MeasurementError{Message: "invalid answers format returned"}
	}

	return a, nil
}

func DecodeTraceDNSHops(hops json.RawMessage) ([]TraceDNSHop, error) {
	t := []TraceDNSHop{}
	err := json.Unmarshal(hops, &t)

	if err != nil {
		return nil, &MeasurementError{Message: "invalid hops format returned"}
	}

	return t, nil
}

func DecodeDNSTimings(timings json.RawMessage) (*DNSTimings, error) {
	t := &DNSTimings{}
	err := json.Unmarshal(timings, t)

	if err != nil {
		return nil, &MeasurementError{Message: "invalid timings format returned (other)"}
	}

	return t, nil
}

func DecodeMTRHops(hops json.RawMessage) ([]MTRHop, error) {
	t := []MTRHop{}
	err := json.Unmarshal(hops, &t)

	if err != nil {
		return nil, &MeasurementError{Message: "invalid hops format returned"}
	}

	return t, nil
}

func DecodeHTTPHeaders(headers json.RawMessage) (map[string]string, error) {
	h := map[string]string{}
	err := json.Unmarshal(headers, &h)

	if err != nil {
		return nil, &MeasurementError{Message: "invalid headers format returned"}
	}

	return h, nil
}

func DecodeHTTPTimings(timings json.RawMessage) (*HTTPTimings, error) {
	t := &HTTPTimings{}
	err := json.Unmarshal(timings, t)

	if err != nil {
		return nil, &MeasurementError{Message: "invalid timings format returned (other)"}
	}

	return t, nil
}
