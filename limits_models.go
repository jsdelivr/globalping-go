package globalping

// https://globalping.io/docs/api.globalping.io#get-/v1/limits

type LimitsResponse struct {
	RateLimits RateLimits   `json:"rateLimit"`
	Credits    CreditLimits `json:"credits"` // Only for authenticated requests
}

type RateLimits struct {
	Measurements MeasurementsLimits `json:"measurements"`
}

type MeasurementsLimits struct {
	Create MeasurementsCreateLimits `json:"create"`
}

type CreateLimitType string

const (
	CreateLimitTypeIP   CreateLimitType = "ip"
	CreateLimitTypeUser CreateLimitType = "user"
)

type MeasurementsCreateLimits struct {
	Type      CreateLimitType `json:"type"`
	Limit     int64           `json:"limit"`
	Remaining int64           `json:"remaining"`
	Reset     int64           `json:"reset"`
}

type CreditLimits struct {
	Remaining int64 `json:"remaining"`
}

type LimitsError struct {
	Code    int    `json:"-"`
	Type    string `json:"type"`
	Message string `json:"message"`
}

func (e *LimitsError) Error() string {
	return e.Message
}

type LimitsErrorResponse struct {
	Error *LimitsError `json:"error"`
}
