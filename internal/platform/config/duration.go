package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Duration is a time.Duration written in configuration documents as a Go
// duration string, for example "30s", "1m30s" or "250ms". Negative values
// are refused; zero means "use the default" wherever a default exists.
type Duration time.Duration

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// String returns the Go duration string.
func (d Duration) String() string { return time.Duration(d).String() }

// MarshalJSON writes the duration as a string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// UnmarshalJSON reads a duration string. Bare numbers are refused, so a
// value such as 30 (seconds? nanoseconds?) cannot be misread.
func (d *Duration) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		return nil // leaves the zero value: "use the default"
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New(`config: a duration must be a string such as "30s"`)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("config: %q is not a duration (use for example \"30s\" or \"2m\")", s)
	}
	if v < 0 {
		return fmt.Errorf("config: duration %q must not be negative", s)
	}
	*d = Duration(v)
	return nil
}
