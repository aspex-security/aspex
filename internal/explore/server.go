package explore

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
)

//go:embed ui.html
var uiHTML []byte

// Handler serves the UI and the dataset. The dataset is computed once, at
// startup; explore is an ephemeral process, not a daemon.
func Handler(ds Dataset) http.Handler {
	mux := http.NewServeMux()
	data, _ := json.Marshal(ds)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Write(uiHTML)
	})
	mux.HandleFunc("/api/dataset", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(data)
	})
	// Loopback-only guard even if someone proxies to it: refuse non-local Hosts.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host != "127.0.0.1" && host != "localhost" && host != "[::1]" && host != "::1" {
			http.Error(w, "aspex explore serves loopback only", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// Listen binds to the loopback interface only. port 0 picks a free port.
// It never binds 0.0.0.0; there is no flag to change that.
func Listen(port int) (net.Listener, string, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, "", err
	}
	addr := ln.Addr().String()
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		ln.Close()
		return nil, "", fmt.Errorf("refusing to serve on non-loopback address %s", addr)
	}
	return ln, "http://" + addr, nil
}
