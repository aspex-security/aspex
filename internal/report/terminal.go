// Package report implements the terminal, JSON, and other output reporters.
package report

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/aspex-security/aspex/internal/inspect"
	"github.com/aspex-security/aspex/internal/rules"
	"github.com/aspex-security/aspex/internal/score"
)

// ANSI escape codes.
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorYellow  = "\033[33m"
	colorGreen   = "\033[32m"
	colorCyan    = "\033[36m"
	colorBlue    = "\033[34m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
	colorPurple  = "\033[35m"
	colorBrPurple = "\033[95m"
	colorBrRed   = "\033[91m"
	colorBrYellow = "\033[93m"
	colorBrGreen = "\033[92m"
	clearLine    = "\r\033[K"
)

// ScanReport is the full data for an aspex-scan terminal render.
type ScanReport struct {
	Version         string
	ElapsedMS       int64
	Servers         []*inspect.Server
	Scores          []score.ServerScore
	Overall         score.OverallScore
	DiscoveryErrors []string
	NoColor         bool
	HTMLPath        string // path to HTML report if one was written
	LogPath         string // path to JSON log if one was written
}

// Spinner shows an animated progress indicator on stderr during scanning.
type Spinner struct {
	mu      sync.Mutex
	msg     string
	done    chan struct{}
	noColor bool
}

// NewSpinner creates and starts an animated spinner writing to w.
func NewSpinner(initial string, noColor bool) *Spinner {
	s := &Spinner{
		msg:     initial,
		done:    make(chan struct{}),
		noColor: noColor,
	}
	go s.run()
	return s
}

func (s *Spinner) run() {
	if s.noColor {
		return
	}
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	i := 0
	for {
		select {
		case <-s.done:
			fmt.Fprintf(writerStderr, "%s", clearLine)
			return
		case <-time.After(80 * time.Millisecond):
			s.mu.Lock()
			msg := s.msg
			s.mu.Unlock()
			fmt.Fprintf(writerStderr, "\r  \033[35m%s\033[0m  \033[2m%s\033[0m", frames[i%len(frames)], msg)
			i++
		}
	}
}

// Update changes the spinner message.
func (s *Spinner) Update(msg string) {
	s.mu.Lock()
	s.msg = msg
	s.mu.Unlock()
}

// Stop clears the spinner line.
func (s *Spinner) Stop() {
	if s.noColor {
		return
	}
	close(s.done)
	time.Sleep(20 * time.Millisecond)
}

// writerStderr is used by the spinner; set to os.Stderr by the caller via init.
// We use a package-level var so spinner does not import os directly.
var writerStderr io.Writer = io.Discard

// SetSpinnerOutput sets the writer the spinner writes to (should be os.Stderr).
func SetSpinnerOutput(w io.Writer) {
	writerStderr = w
}

// scoreBar renders a health-bar where filled blocks represent the score.
// 12/100 = tiny sliver, 100/100 = full bar. Empty = dangerous, full = safe.
func scoreBar(score int, width int, c colorFn, band string) string {
	filled := (score * width) / 100
	if filled > width {
		filled = width
	}
	col := severityBandColor(band)
	bar := c(col+colorBold, strings.Repeat("█", filled)) +
		c(colorDim, strings.Repeat("░", width-filled))
	return bar
}

// sectionLine renders a labeled horizontal rule.
func sectionLine(label string, c colorFn, col string) string {
	const width = 62
	spaces := width - len(label) - 2
	if spaces < 4 {
		spaces = 4
	}
	return fmt.Sprintf("  %s %s",
		c(col+colorBold, label),
		c(colorDim, strings.Repeat("─", spaces)),
	)
}

// PrintScanReport writes the aspex-scan terminal report to w.
func PrintScanReport(w io.Writer, r ScanReport) {
	c := newColorizer(r.NoColor)

	// Header.
	fmt.Fprintf(w, "\n  %s  %s  %s\n\n",
		c(colorPurple+colorBold, "◆"),
		c(colorBold, "Aspex"),
		c(colorDim, "v"+r.Version),
	)

	// Count totals.
	toolCount := 0
	for _, srv := range r.Servers {
		toolCount += srv.ToolCount()
	}
	totalFindings := r.Overall.Critical + r.Overall.High + r.Overall.Medium + r.Overall.Low

	// Summary box.
	elapsed := fmt.Sprintf("%.1fs", float64(r.ElapsedMS)/1000)
	bandCol := severityBandColor(r.Overall.Band)
	bar := scoreBar(r.Overall.Score, 24, c, r.Overall.Band)

	fmt.Fprintf(w, "  %s\n", c(colorDim, "╭─────────────────────────────────────────────────────────────╮"))
	fmt.Fprintf(w, "  %s  %s  %s  %s  %s\n",
		c(colorDim, "│"),
		c(bandCol+colorBold, fmt.Sprintf("%3d / 100", r.Overall.Score)),
		bar,
		c(bandCol+colorBold, r.Overall.Band)+" "+c(colorDim, "(100 = safe)"),
		c(colorDim, "│"),
	)
	meta := fmt.Sprintf("  %d servers · %d tools · %d findings · %ds elapsed", len(r.Servers), toolCount, totalFindings, r.ElapsedMS/1000)
	padding := 63 - len(meta)
	if padding < 1 {
		padding = 1
	}
	fmt.Fprintf(w, "  %s%s%s%s\n",
		c(colorDim, "│"),
		c(colorDim, meta),
		strings.Repeat(" ", padding),
		c(colorDim, "│"),
	)

	// Severity breakdown in box.
	sevLine := "  "
	if r.Overall.Critical > 0 {
		sevLine += c(colorBrRed, fmt.Sprintf("%d critical", r.Overall.Critical)) + "  "
	}
	if r.Overall.High > 0 {
		sevLine += c(colorBrYellow, fmt.Sprintf("%d high", r.Overall.High)) + "  "
	}
	if r.Overall.Medium > 0 {
		sevLine += c(colorYellow, fmt.Sprintf("%d medium", r.Overall.Medium)) + "  "
	}
	if r.Overall.Low > 0 {
		sevLine += c(colorBlue, fmt.Sprintf("%d low", r.Overall.Low))
	}
	sevPad := 63 - len(stripANSI(sevLine))
	if sevPad < 1 {
		sevPad = 1
	}
	fmt.Fprintf(w, "  %s%s%s%s\n",
		c(colorDim, "│"),
		sevLine,
		strings.Repeat(" ", sevPad),
		c(colorDim, "│"),
	)
	fmt.Fprintf(w, "  %s\n\n", c(colorDim, "╰─────────────────────────────────────────────────────────────╯"))
	_ = elapsed

	// Group servers by worst severity.
	var criticals, highs, mediums, oks []serverResult
	for i, srv := range r.Servers {
		sc := r.Scores[i]
		worst := rules.SeverityInfo
		for _, f := range sc.Findings {
			if f.Severity > worst {
				worst = f.Severity
			}
		}
		sr := serverResult{srv, sc}
		switch {
		case worst >= rules.SeverityCritical:
			criticals = append(criticals, sr)
		case worst >= rules.SeverityHigh:
			highs = append(highs, sr)
		case worst >= rules.SeverityMedium:
			mediums = append(mediums, sr)
		default:
			oks = append(oks, sr)
		}
	}

	printServerSection(w, c, "CRITICAL", colorBrRed, criticals)
	printServerSection(w, c, "HIGH", colorBrYellow, highs)
	printServerSection(w, c, "MEDIUM", colorYellow, mediums)

	// OK servers: compact list.
	if len(oks) > 0 {
		fmt.Fprintf(w, "%s\n\n", sectionLine("OK", c, colorBrGreen))
		for _, sr := range oks {
			fmt.Fprintf(w, "  %s  %-28s  %s  %s\n",
				c(colorBrGreen, "○"),
				sr.srv.Entry.Name,
				c(colorDim, sr.srv.Entry.Client),
				c(colorBrGreen+colorDim, "100 / 100"),
			)
		}
		fmt.Fprintln(w)
	}

	// Discovery warnings.
	if len(r.DiscoveryErrors) > 0 {
		fmt.Fprintf(w, "  %s\n", c(colorYellow, "Warnings"))
		for _, e := range r.DiscoveryErrors {
			fmt.Fprintf(w, "    %s %s\n", c(colorYellow, "▸"), e)
		}
		fmt.Fprintln(w)
	}

	// Footer.
	fmt.Fprintf(w, "  %s\n", c(colorDim, strings.Repeat("─", 62)))
	if r.HTMLPath != "" {
		fmt.Fprintf(w, "  %s %s\n",
			c(colorDim, "Report:"),
			c(colorPurple, "file://"+r.HTMLPath),
		)
	}
	if r.LogPath != "" {
		fmt.Fprintf(w, "  %s  %s\n",
			c(colorDim, "Log:"),
			c(colorPurple, "file://"+r.LogPath),
		)
	}
	if r.HTMLPath != "" || r.LogPath != "" {
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "  %s\n", c(colorDim, "This scanned 1 machine."))
	fmt.Fprintf(w, "  %s %s\n\n",
		c(colorDim, "Continuous fleet-wide monitoring and enforcement by Onyx Security:"),
		c(colorPurple, "https://onyx.security"),
	)
}

type serverResult struct {
	srv *inspect.Server
	sc  score.ServerScore
}

func printServerSection(w io.Writer, c colorFn, label, col string, servers []serverResult) {
	if len(servers) == 0 {
		return
	}
	fmt.Fprintf(w, "%s\n\n", sectionLine(label, c, col))
	for _, sr := range servers {
		printServerBlock(w, c, col, sr.srv, sr.sc)
	}
}

func printServerBlock(w io.Writer, c colorFn, col string, srv *inspect.Server, sc score.ServerScore) {
	// Server name line.
	scoreStr := fmt.Sprintf("%d / 100", sc.Score)
	namePad := 42 - len(srv.Entry.Name) - len(srv.Entry.Client)
	if namePad < 1 {
		namePad = 1
	}
	fmt.Fprintf(w, "  %s  %s%s%s  %s  %s\n",
		c(col, "◉"),
		c(colorBold, srv.Entry.Name),
		strings.Repeat(" ", namePad),
		c(colorDim, srv.Entry.Client),
		c(colorDim, "·"),
		c(col+colorBold, scoreStr),
	)

	if len(sc.Findings) == 0 {
		fmt.Fprintln(w)
		return
	}

	fmt.Fprintln(w)
	for _, f := range sc.Findings {
		printFinding(w, c, f)
	}
}

func printFinding(w io.Writer, c colorFn, f rules.Finding) {
	sevCol := findingSeverityColor(f.Severity)
	sevLabel := fmt.Sprintf("%-8s", f.Severity.String())

	fmt.Fprintf(w, "     %s  %s  %s\n",
		c(sevCol+colorBold, sevLabel),
		c(colorPurple, f.RuleID),
		c(colorBold, f.Name),
	)
	if f.Detail != "" {
		// Wrap detail at 58 chars.
		for _, line := range wrapText(f.Detail, 58) {
			fmt.Fprintf(w, "     %s %s\n", c(colorDim, "│"), c(colorDim, line))
		}
	}
	if f.Mapping != "" {
		fmt.Fprintf(w, "     %s %s\n", c(colorDim, "│"), c(colorDim+colorPurple, f.Mapping))
	}
	if f.Fix != "" {
		fmt.Fprintf(w, "     %s %s %s\n", c(colorDim, "╰"), c(colorCyan, "fix:"), f.Fix)
	}
	fmt.Fprintln(w)
}

// PrintTraceReport (stub for trace_terminal.go compatibility).

func wrapText(s string, width int) []string {
	if len(s) <= width {
		return []string{s}
	}
	var lines []string
	words := strings.Fields(s)
	line := ""
	for _, w := range words {
		if len(line)+len(w)+1 > width {
			if line != "" {
				lines = append(lines, line)
			}
			line = w
		} else {
			if line == "" {
				line = w
			} else {
				line += " " + w
			}
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// stripANSI removes ANSI escape sequences for length calculation.
func stripANSI(s string) string {
	out := strings.Builder{}
	inEsc := false
	for _, ch := range s {
		if ch == '\033' {
			inEsc = true
			continue
		}
		if inEsc {
			if ch == 'm' {
				inEsc = false
			}
			continue
		}
		out.WriteRune(ch)
	}
	return out.String()
}

func severityBandColor(band string) string {
	switch band {
	case score.BandHighRisk:
		return colorBrRed
	case score.BandAtRisk:
		return colorBrYellow
	case score.BandNeedsReview:
		return colorYellow
	default:
		return colorBrGreen
	}
}

func findingSeverityColor(s rules.Severity) string {
	switch s {
	case rules.SeverityCritical:
		return colorBrRed
	case rules.SeverityHigh:
		return colorBrYellow
	case rules.SeverityMedium:
		return colorYellow
	case rules.SeverityLow:
		return colorBlue
	default:
		return colorDim
	}
}

type colorFn func(color, text string) string

func newColorizer(noColor bool) colorFn {
	if noColor {
		return func(_, text string) string { return text }
	}
	return func(color, text string) string {
		if color == "" {
			return text
		}
		return color + text + colorReset
	}
}
