package version

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// CheckLatest queries the GitHub Releases API for the latest Aspex release and
// returns the version string if it differs from the currently running version.
// Returns "" if the check fails, the user is already on the latest version, or
// the ASPEX_NO_UPDATE_CHECK environment variable is set.
func CheckLatest() string {
	if os.Getenv("ASPEX_NO_UPDATE_CHECK") != "" {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/repos/aspex-security/aspex/releases/latest", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "aspex/"+Version)

	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&release); err != nil {
		return ""
	}

	latest := strings.TrimPrefix(release.TagName, "v")
	if latest != "" && latest != Version {
		return latest
	}
	return ""
}
