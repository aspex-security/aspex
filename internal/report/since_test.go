package report

import (
	"testing"
	"time"
)

func TestSinceFlag(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{24 * time.Hour, "1d"}, // a whole day reads as days, never 24h0m0s
		{7 * 24 * time.Hour, "7d"},
		{48 * time.Hour, "2d"},
		{36 * time.Hour, "36h"},
		{3 * time.Hour, "3h"},
		{90 * time.Minute, "90m"},
		{2*time.Hour + 30*time.Minute, "150m"},
		{45 * time.Second, "45s"},
	}
	for _, c := range cases {
		if got := SinceFlag(c.d); got != c.want {
			t.Errorf("SinceFlag(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}
