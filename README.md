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
  client := globalping.NewClient(globalping.Config{
    AuthToken: "<your_access_token>", // Optional
  })
}
```

### Create Measurement

Creates a new measurement with the set parameters. The measurement runs asynchronously, and you can retrieve its current state using GetMeasurement() or wait for its final state using AwaitMeasurement().

```go
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
```

### Get a measurement

Returns the current state of the measurement.

```go
  measurement, err := client.GetMeasurement(ctx, res.ID)
  if err != nil {
    fmt.Println(err)
    return
  }

  fmt.Printf("%+v\n", measurement)
```

### Await a measurement

Similar to GetMeasurement(), but keeps polling the API until the measurement is finished, and returns its final state.

```go
  measurement, err := client.AwaitMeasurement(ctx, res.ID)
  if err != nil {
    fmt.Println(err)
    return
  }

  fmt.Printf("%+v\n", measurement)
```

### Get raw measurement bytes

Returns the raw measurement bytes.

```go
  b, err := client.GetMeasurementRaw(ctx, res.ID)
  if err != nil {
    fmt.Println(err)
    return
  }
```

### Probes

Returns a list of all probes currently online and their metadata, such as location and assigned tags.

```go
  probes, err := client.Probes(ctx)
  if err != nil {
    fmt.Println(err)
    return
  }

  fmt.Printf("%+v\n", probes)
```

### Get rate limits

Returns rate limits for the current user (if authenticated) or IP address (if not authenticated).

```go
  limits, err := client.Limits(ctx)
  if err != nil {
    fmt.Println(err)
    return
  }

  fmt.Printf("%+v\n", limits)
```

### Error handling

API errors are returned as `*globalping.MeasurementError` instances. You can access the error code and headers using the `StatusCode` and `Header` fields.

```go
  measurement, err := client.GetMeasurement(ctx, res.ID)
  if err != nil {
    if measurementErr, ok := err.(*globalping.MeasurementError); ok {
      // measurementErr.StatusCode
      // measurementErr.Header
    } else {
      fmt.Println(err)
    }
  }
```

### Advanced configuration

`AuthToken`

A user authentication token obtained from [https://dash.globalping.io](https://dash.globalping.io) or via OAuth (currently available only to official Globalping apps).

`UserAgent`

Refers to this library by default. If you build another open-source project based on this library, you should override this value to point to your project instead.

`CacheExpireSeconds`

Specifies the expiration time for cached measurements in seconds. 0 means no expiration.

`HTTPClient`

Custom HTTP client to use for requests.
