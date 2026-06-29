package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Finding holds the data for a single alert notification.
type Finding struct {
	Severity string
	RuleID   string
	Tool     string
	Server   string
	Detail   string
	Client   string
}

// Send posts a finding to the webhook URL. It detects Slack webhook URLs
// (hooks.slack.com) and formats them as Slack blocks; otherwise it sends
// generic JSON. Non-blocking: fires in a goroutine, logs errors to stderr.
func Send(webhookURL string, f Finding) {
	go func() {
		if err := send(webhookURL, f); err != nil {
			fmt.Fprintf(os.Stderr, "notify: webhook error: %v\n", err)
		}
	}()
}

// isPrivateIP returns true if the IP falls in an RFC1918 or link-local range.
func isPrivateIP(ip net.IP) bool {
	private := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
	}
	for _, cidr := range private {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// validateWebhookURL rejects non-HTTPS URLs and URLs that resolve to private/link-local ranges.
// Localhost/127.0.0.1 are allowed for testing purposes.
func validateWebhookURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}
	host := u.Hostname()
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return nil // allowed for local testing
	}
	if u.Scheme != "https" {
		return fmt.Errorf("webhook URL must use HTTPS, got %q", u.Scheme)
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("cannot resolve webhook host %q: %w", host, err)
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip != nil && isPrivateIP(ip) {
			return fmt.Errorf("webhook host %q resolves to private/link-local address %s", host, addr)
		}
	}
	return nil
}

func send(webhookURL string, f Finding) error {
	if err := validateWebhookURL(webhookURL); err != nil {
		return err
	}

	client := &http.Client{Timeout: 10 * time.Second}

	u, _ := url.Parse(webhookURL)
	if u.Host == "hooks.slack.com" {
		return sendSlack(client, webhookURL, f)
	}
	return sendGeneric(client, webhookURL, f)
}

// sendSlack posts a richly formatted Slack blocks message.
func sendSlack(client *http.Client, webhookURL string, f Finding) error {
	sevEmoji := ":warning:"
	if strings.ToUpper(f.Severity) == "CRITICAL" {
		sevEmoji = ":rotating_light:"
	}

	header := fmt.Sprintf("%s *[%s]* `%s` — %s", sevEmoji, strings.ToUpper(f.Severity), f.RuleID, f.Tool)
	body := fmt.Sprintf("*Server:* %s\n*Detail:* %s", f.Server, f.Detail)
	if f.Client != "" {
		body += fmt.Sprintf("\n*Client:* %s", f.Client)
	}

	payload := map[string]interface{}{
		"blocks": []interface{}{
			map[string]interface{}{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": header,
				},
			},
			map[string]interface{}{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": body,
				},
			},
			map[string]interface{}{
				"type": "divider",
			},
		},
	}

	return postJSON(client, webhookURL, "", payload)
}

// sendGeneric posts a plain JSON event payload.
func sendGeneric(client *http.Client, rawURL string, f Finding) error {
	// Extract optional ?token= query param and use as Bearer token.
	var token string
	u, err := url.Parse(rawURL)
	if err == nil {
		token = u.Query().Get("token")
		if token != "" {
			q := u.Query()
			q.Del("token")
			u.RawQuery = q.Encode()
			rawURL = u.String()
		}
	}

	payload := map[string]interface{}{
		"event":     "finding",
		"severity":  f.Severity,
		"rule_id":   f.RuleID,
		"tool":      f.Tool,
		"server":    f.Server,
		"detail":    f.Detail,
		"client":    f.Client,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	return postJSON(client, rawURL, token, payload)
}

func postJSON(client *http.Client, targetURL, bearerToken string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %d from %s", resp.StatusCode, targetURL)
	}
	return nil
}
