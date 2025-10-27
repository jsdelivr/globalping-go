# Globalping Go API Client

The official Go client for the [Globalping API](https://globalping.io/docs/api.globalping.io).

## Installation

To install the client, run the following command:

```bash
go get github.com/jsdelivr/globalping-go
```

## Usage

To use the client, import it into your Go code:

```go
import "github.com/jsdelivr/globalping-go"

func main() {
	ctx := context.Background()

	client := globalping.NewClient(globalping.Config{
		UserAgent: "<your_user_agent>",
		AuthToken: &globalping.Token{
			AccessToken: "<your_access_token>",
			Expiry:      time.Now().Add(math.MaxInt64),
		},
	})

	o := &globalping.MeasurementCreate{
		Type:   globalping.MeasurementTypePing,
		Target: "google.com",
		Limit:  1,
		Locations: []globalping.Locations{
			{
				Magic: "world",
			},
		},
	}

	res, err := client.CreateMeasurement(ctx, o)
	if err != nil {
		fmt.Println(err)
		return
	}

	measurement, err := client.AwaitMeasurement(ctx, res.ID)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%+v\n", measurement)
}
```
