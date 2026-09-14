package report

import (
	"html/template"
	"io"
	"strings"
)

// WriteHTMLScan writes a self-contained HTML security report to w.
func WriteHTMLScan(w io.Writer, scan JSONScanOutput) error {
	return htmlTmpl.Execute(w, scan)
}

var htmlFuncs = template.FuncMap{
	"split": strings.Split,
	"slice": func(s string, start, end int) string {
		r := []rune(s)
		if end > len(r) {
			end = len(r)
		}
		if start >= len(r) {
			return "??"
		}
		return strings.ToUpper(string(r[start:end]))
	},
	"mul": func(a, b int) int { return a * b },
	"div": func(total, part int) int {
		if total == 0 {
			return 0
		}
		return part / total
	},
	"bandColor": func(band string) string {
		switch band {
		case "HIGH RISK":
			return "#ef4444"
		case "AT RISK":
			return "#f97316"
		case "NEEDS REVIEW":
			return "#eab308"
		default:
			return "#22c55e"
		}
	},
	"bandGlow": func(band string) string {
		switch band {
		case "HIGH RISK":
			return "0 0 32px rgba(239,68,68,0.25)"
		case "AT RISK":
			return "0 0 32px rgba(249,115,22,0.20)"
		case "NEEDS REVIEW":
			return "0 0 32px rgba(234,179,8,0.18)"
		default:
			return "0 0 32px rgba(34,197,94,0.18)"
		}
	},
	"sevColor": func(sev string) string {
		switch strings.ToUpper(sev) {
		case "CRITICAL":
			return "#ef4444"
		case "HIGH":
			return "#f97316"
		case "MEDIUM":
			return "#eab308"
		case "LOW":
			return "#60a5fa"
		default:
			return "#6b7280"
		}
	},
	"sevBg": func(sev string) string {
		switch strings.ToUpper(sev) {
		case "CRITICAL":
			return "rgba(239,68,68,0.12)"
		case "HIGH":
			return "rgba(249,115,22,0.12)"
		case "MEDIUM":
			return "rgba(234,179,8,0.10)"
		case "LOW":
			return "rgba(96,165,250,0.10)"
		default:
			return "rgba(107,114,128,0.10)"
		}
	},
	// gaugeAngle fills the arc proportional to the score (health-bar model).
	// 12/100 = small colored arc, 100/100 = full circle. Empty = dangerous, full = safe.
	"gaugeAngle": func(score int) int {
		return (score * 360) / 100
	},
	"totalFindings": func(scan JSONScanOutput) int {
		n := 0
		for _, s := range scan.Servers {
			n += len(s.Findings)
		}
		return n
	},
	"lower": strings.ToLower,
	"sub":   func(a, b int) int { return a - b },
	"blastColor": func(level string) string {
		switch strings.ToUpper(level) {
		case "HIGH":
			return "#ef4444"
		case "MEDIUM":
			return "#f97316"
		case "LOW":
			return "#eab308"
		default:
			return "#22c55e"
		}
	},
}

var htmlTmpl = template.Must(template.New("scan").Funcs(htmlFuncs).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Agent Security Scan · Aspex</title>
<style>
:root {
  --bg:       #080a0f;
  --surface:  #0d1018;
  --surface2: #131720;
  --border:   #1c2130;
  --border2:  #242c3d;
  --text:     #e2e8f0;
  --muted:    #64748b;
  --brand:      #ec3013;
  --brand-dark: #ae1800;
  --brand-light:#ff9783;
  --brand-dim:  rgba(236,48,19,0.14);
  --red:      #ef4444;
  --orange:   #f97316;
  --yellow:   #eab308;
  --blue:     #60a5fa;
  --green:    #22c55e;
  --mono:     'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', sans-serif;
  font-size: 14px;
  line-height: 1.6;
  min-height: 100vh;
}

/* ── Sticky header ── */
.topbar {
  position: sticky;
  top: 0;
  z-index: 100;
  background: rgba(8,10,15,0.92);
  backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 20px;
  padding: 10px 28px;
  flex-wrap: wrap;
}
.topbar-brand {
  display: flex;
  align-items: center;
  gap: 8px;
  font-weight: 700;
  font-size: 13px;
  letter-spacing: 0.02em;
  color: #fff;
  flex-shrink: 0;
}
.topbar-mark {
  width: 22px;
  height: 22px;
  background: var(--brand);
  border-radius: 5px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 11px;
  font-weight: 900;
  color: #fff;
}
.topbar-score {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-shrink: 0;
}
.topbar-score-num {
  font-size: 18px;
  font-weight: 800;
  font-variant-numeric: tabular-nums;
}
.topbar-band {
  padding: 2px 9px;
  border-radius: 999px;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.07em;
  text-transform: uppercase;
  color: #fff;
}
.topbar-sep { width: 1px; height: 20px; background: var(--border2); flex-shrink: 0; }
.topbar-stats {
  display: flex;
  gap: 16px;
  font-size: 12px;
  color: var(--muted);
  flex-wrap: wrap;
}
.topbar-stats strong { color: var(--text); font-weight: 600; }

/* Filter pills */
.filters {
  display: flex;
  gap: 6px;
  margin-left: auto;
  flex-wrap: wrap;
}
.filter-btn {
  padding: 4px 12px;
  border-radius: 999px;
  border: 1px solid var(--border2);
  background: transparent;
  color: var(--muted);
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  cursor: pointer;
  transition: all 0.15s;
}
.filter-btn:hover, .filter-btn.active {
  background: var(--brand-dim);
  border-color: var(--brand);
  color: var(--text);
}
.filter-btn[data-sev="critical"].active { background: rgba(239,68,68,0.12); border-color: var(--red); color: var(--red); }
.filter-btn[data-sev="high"].active    { background: rgba(249,115,22,0.12); border-color: var(--orange); color: var(--orange); }
.filter-btn[data-sev="medium"].active  { background: rgba(234,179,8,0.10); border-color: var(--yellow); color: var(--yellow); }
.filter-btn[data-sev="low"].active     { background: rgba(96,165,250,0.10); border-color: var(--blue); color: var(--blue); }

/* ── Hero ── */
.hero {
  max-width: 960px;
  margin: 0 auto;
  padding: 48px 28px 32px;
  display: flex;
  gap: 40px;
  align-items: center;
  flex-wrap: wrap;
}
.gauge-wrap {
  position: relative;
  width: 136px;
  height: 136px;
  flex-shrink: 0;
}
.gauge-ring {
  width: 136px;
  height: 136px;
  border-radius: 50%;
  position: relative;
}
.gauge-ring::before {
  content: '';
  position: absolute;
  inset: 0;
  border-radius: 50%;
  background: conic-gradient(var(--gauge-color, #ef4444) var(--gauge-deg, 0deg), #1c2130 0deg);
}
.gauge-ring::after {
  content: '';
  position: absolute;
  inset: 14px;
  border-radius: 50%;
  background: var(--bg);
}
.gauge-text {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  z-index: 1;
  pointer-events: none;
}
.gauge-num {
  font-size: 32px;
  font-weight: 800;
  line-height: 1;
  font-variant-numeric: tabular-nums;
}
.gauge-denom {
  font-size: 11px;
  color: var(--muted);
  margin-top: 1px;
}

.hero-info { flex: 1; min-width: 200px; }
.hero-band {
  display: inline-block;
  padding: 5px 14px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: #fff;
  margin-bottom: 16px;
}
.hero-stats {
  display: grid;
  grid-template-columns: repeat(4, auto);
  gap: 4px 24px;
  width: fit-content;
}
.stat-item { display: flex; flex-direction: column; gap: 2px; }
.stat-num {
  font-size: 26px;
  font-weight: 800;
  line-height: 1;
  font-variant-numeric: tabular-nums;
}
.stat-lbl {
  font-size: 10px;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.07em;
}

/* Severity bar */
.sev-bar {
  margin-top: 20px;
  height: 5px;
  border-radius: 9999px;
  background: var(--border);
  overflow: hidden;
  display: flex;
  width: 100%;
  max-width: 360px;
}
.sev-bar-seg { height: 100%; transition: width 0.6s cubic-bezier(.4,0,.2,1); }

/* ── Server list ── */
.server-list {
  max-width: 960px;
  margin: 0 auto;
  padding: 0 28px 60px;
}

.section-label {
  display: flex;
  align-items: center;
  gap: 10px;
  margin: 28px 0 12px;
}
.section-label-text {
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
}
.section-label-line {
  flex: 1;
  height: 1px;
  background: var(--border);
}

.server-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  margin-bottom: 16px;
  overflow: hidden;
  transition: border-color 0.15s;
}
.server-card:hover { border-color: var(--border2); }
.server-card-left-bar {
  position: relative;
}
.server-card-left-bar::before {
  content: '';
  position: absolute;
  left: 0;
  top: 0;
  bottom: 0;
  width: 3px;
  border-radius: 3px 0 0 3px;
  background: var(--bar-color, #6b7280);
}

.server-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 20px 16px 24px;
  gap: 12px;
  flex-wrap: wrap;
  cursor: pointer;
  user-select: none;
}
.server-header:hover .server-name { color: #fff; }
.server-left { display: flex; align-items: center; gap: 14px; }
.server-icon {
  width: 36px;
  height: 36px;
  border-radius: 8px;
  background: var(--surface2);
  border: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: center;
  font-family: var(--mono);
  font-size: 13px;
  font-weight: 700;
  color: var(--muted);
  flex-shrink: 0;
  text-transform: uppercase;
}
.server-name {
  font-size: 15px;
  font-weight: 700;
  color: #f1f5f9;
  transition: color 0.1s;
}
.server-meta {
  display: flex;
  gap: 8px;
  margin-top: 2px;
  align-items: center;
  flex-wrap: wrap;
}
.meta-chip {
  padding: 1px 7px;
  border-radius: 4px;
  background: var(--surface2);
  border: 1px solid var(--border);
  font-size: 10px;
  color: var(--muted);
  font-family: var(--mono);
}
.server-right { display: flex; align-items: center; gap: 12px; flex-shrink: 0; }
.server-score-num {
  font-size: 22px;
  font-weight: 800;
  font-variant-numeric: tabular-nums;
}
.server-score-denom {
  font-size: 12px;
  color: var(--muted);
}
.server-chevron {
  color: var(--muted);
  font-size: 11px;
  transition: transform 0.2s;
}
.server-card.open .server-chevron { transform: rotate(180deg); }

.findings-list {
  border-top: 1px solid var(--border);
  display: none;
}
.server-card.open .findings-list { display: block; }

.finding {
  display: flex;
  gap: 16px;
  padding: 16px 20px 16px 24px;
  border-bottom: 1px solid var(--border);
  transition: background 0.1s;
}
.finding:last-child { border-bottom: none; }
.finding:hover { background: rgba(255,255,255,0.015); }
.finding-left { flex-shrink: 0; display: flex; flex-direction: column; gap: 6px; align-items: flex-start; padding-top: 2px; }
.sev-badge {
  padding: 3px 8px;
  border-radius: 5px;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.07em;
  text-transform: uppercase;
  white-space: nowrap;
  color: #fff;
}
.rule-id {
  font-family: var(--mono);
  font-size: 10px;
  color: var(--brand);
  white-space: nowrap;
}
.finding-body { flex: 1; min-width: 0; }
.finding-name {
  font-weight: 600;
  font-size: 14px;
  color: #f1f5f9;
  margin-bottom: 6px;
}
.finding-detail {
  font-size: 12px;
  color: var(--muted);
  line-height: 1.55;
  margin-bottom: 10px;
}
.framework-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
  margin-bottom: 10px;
}
.framework-tag {
  padding: 2px 7px;
  border-radius: 4px;
  background: var(--brand-dim);
  border: 1px solid rgba(236,48,19,0.30);
  font-size: 10px;
  color: var(--brand-light);
  font-family: var(--mono);
  white-space: nowrap;
}
.fix-block {
  background: rgba(0,0,0,0.3);
  border: 1px solid var(--border);
  border-left: 3px solid var(--brand);
  border-radius: 0 6px 6px 0;
  padding: 10px 14px;
}
.fix-label {
  font-size: 9px;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--brand);
  margin-bottom: 4px;
}
.fix-text {
  font-size: 12px;
  color: #94a3b8;
  line-height: 1.5;
  font-family: var(--mono);
}

.no-findings {
  padding: 28px 24px;
  text-align: center;
  color: var(--muted);
  font-size: 13px;
}
.no-findings-icon { font-size: 20px; margin-bottom: 6px; opacity: 0.5; }

/* OK server compact card */
.ok-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 12px 20px;
  margin-bottom: 8px;
  display: flex;
  align-items: center;
  gap: 12px;
}
.ok-dot {
  width: 8px; height: 8px;
  border-radius: 50%;
  background: var(--green);
  flex-shrink: 0;
}
.ok-name { font-weight: 600; font-size: 13px; }
.ok-meta { font-size: 11px; color: var(--muted); margin-left: auto; }

/* ── Footer ── */
.footer {
  border-top: 1px solid var(--border);
  padding: 24px 28px;
  max-width: 960px;
  margin: 0 auto;
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 12px;
}
.footer-brand { font-size: 12px; color: var(--muted); }
.footer-link { color: var(--brand); text-decoration: none; font-size: 12px; }
.footer-link:hover { text-decoration: underline; }

/* ── Attack paths (the headline: composed cross-server paths) ── */
.paths {
  max-width: 960px;
  margin: 0 auto;
  padding: 8px 28px 0;
}
.path-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-left: 3px solid var(--path-color, var(--red));
  border-radius: 10px;
  margin-bottom: 14px;
  overflow: hidden;
}
.path-head {
  display: flex;
  align-items: flex-start;
  gap: 14px;
  padding: 16px 20px 12px;
  flex-wrap: wrap;
}
.path-title { flex: 1; min-width: 200px; }
.path-name { font-size: 15px; font-weight: 700; color: #f1f5f9; }
.path-desc { font-size: 12.5px; color: var(--muted); margin-top: 4px; line-height: 1.5; }
.path-badges { display: flex; flex-direction: column; gap: 6px; align-items: flex-end; flex-shrink: 0; }
.path-servers {
  display: flex; flex-wrap: wrap; gap: 6px;
  padding: 0 20px 14px;
}
.path-server-chip {
  padding: 2px 9px; border-radius: 5px;
  background: var(--surface2); border: 1px solid var(--border2);
  font-family: var(--mono); font-size: 11px; color: var(--text);
}
.path-flow {
  background: rgba(0,0,0,0.28);
  border-top: 1px solid var(--border);
  padding: 16px 20px;
}
.flow-step {
  display: flex; align-items: flex-start; gap: 12px;
  font-size: 12.5px; line-height: 1.5;
  padding: 3px 0;
}
.flow-node {
  flex-shrink: 0; width: 18px; text-align: center;
  color: var(--path-color, var(--red)); font-weight: 700;
  font-family: var(--mono);
}
.flow-text { color: #cbd5e1; }
.path-foot {
  display: grid; grid-template-columns: 1fr 1fr; gap: 1px;
  background: var(--border);
  border-top: 1px solid var(--border);
}
.path-foot > div { background: var(--surface); padding: 12px 20px; }
.path-foot-label {
  font-size: 9px; font-weight: 700; letter-spacing: 0.1em;
  text-transform: uppercase; color: var(--muted); margin-bottom: 4px;
}
.path-foot-text { font-size: 12px; color: #94a3b8; line-height: 1.5; }
.path-impact .path-foot-text { color: var(--brand-light); }
@media (max-width: 640px) { .path-foot { grid-template-columns: 1fr; } }

/* ── Blast radius panel ── */
.blast {
  max-width: 960px;
  margin: 0 auto;
  padding: 4px 28px 0;
}
.blast-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 16px 20px;
  display: flex;
  gap: 20px;
  align-items: center;
  flex-wrap: wrap;
}
.blast-level {
  display: flex; flex-direction: column; gap: 2px; flex-shrink: 0;
  padding-right: 20px; border-right: 1px solid var(--border);
}
.blast-level-num { font-size: 22px; font-weight: 800; line-height: 1; }
.blast-level-lbl { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.07em; }
.blast-reasons { display: flex; flex-direction: column; gap: 5px; flex: 1; min-width: 240px; }
.blast-reason { display: flex; align-items: flex-start; gap: 9px; font-size: 12.5px; line-height: 1.45; }
.blast-reason.on  { color: #cbd5e1; }
.blast-reason.off { color: var(--muted); }
.blast-mark { flex-shrink: 0; font-weight: 700; width: 14px; text-align: center; }
.blast-reason.on .blast-mark  { color: var(--brand); }
.blast-reason.off .blast-mark { color: var(--border2); }

/* Score-cap note under the hero gauge */
.cap-note {
  max-width: 960px; margin: -8px auto 0; padding: 0 28px;
  font-size: 12px; color: var(--muted);
}
.cap-note strong { color: var(--brand-light); font-weight: 600; }

/* Print */
@media print {
  .topbar { position: static; }
  .filters { display: none; }
  .server-chevron { display: none; }
  .findings-list { display: block !important; }
  .server-card { break-inside: avoid; }
  .path-card, .blast-card { break-inside: avoid; }
}

/* Responsive */
@media (max-width: 640px) {
  .hero { padding: 28px 16px 20px; }
  .server-list { padding: 0 16px 40px; }
  .hero-stats { grid-template-columns: repeat(2, auto); }
  .topbar { padding: 8px 16px; }
  .filters { display: none; }
}
</style>
</head>
<body>
{{$total := totalFindings .}}

<!-- Topbar -->
<header class="topbar">
  <div class="topbar-brand">
    <div class="topbar-mark">A</div>
    Aspex
  </div>
  <div class="topbar-score">
    <span class="topbar-score-num" style="color: {{bandColor .Overall.Band}};">{{.Overall.Score}}</span>
    <span style="color:var(--muted); font-size:13px;">/ 100</span>
    <span class="topbar-band" style="background: {{bandColor .Overall.Band}};">{{.Overall.Band}}</span>
  </div>
  <div class="topbar-sep"></div>
  <div class="topbar-stats">
    <span><strong>{{len .Servers}}</strong> servers</span>
    <span><strong>{{$total}}</strong> findings</span>
    {{if .Overall.Critical}}<span style="color:var(--red);"><strong>{{.Overall.Critical}}</strong> critical</span>{{end}}
    {{if .Overall.High}}<span style="color:var(--orange);"><strong>{{.Overall.High}}</strong> high</span>{{end}}
  </div>
  <div class="filters">
    <button class="filter-btn active" data-sev="all" onclick="filter('all',this)">All</button>
    {{if .Overall.Critical}}<button class="filter-btn" data-sev="critical" onclick="filter('critical',this)">Critical</button>{{end}}
    {{if .Overall.High}}<button class="filter-btn" data-sev="high" onclick="filter('high',this)">High</button>{{end}}
    {{if .Overall.Medium}}<button class="filter-btn" data-sev="medium" onclick="filter('medium',this)">Medium</button>{{end}}
    {{if .Overall.Low}}<button class="filter-btn" data-sev="low" onclick="filter('low',this)">Low</button>{{end}}
  </div>
</header>

<!-- Hero -->
<section class="hero">
  <div class="gauge-wrap">
    <div class="gauge-ring" style="--gauge-color: {{bandColor .Overall.Band}}; --gauge-deg: {{gaugeAngle .Overall.Score}}deg; box-shadow: {{bandGlow .Overall.Band}};"></div>
    <div class="gauge-text">
      <span class="gauge-num" style="color: {{bandColor .Overall.Band}};">{{.Overall.Score}}</span>
      <span class="gauge-denom">/ 100</span>
      <span style="font-size:9px;color:var(--muted);margin-top:2px;letter-spacing:0.05em;">SECURITY SCORE</span>
    </div>
  </div>
  <div class="hero-info">
    <div class="hero-band" style="background: {{bandColor .Overall.Band}}; box-shadow: {{bandGlow .Overall.Band}};">{{.Overall.Band}}</div>
    <div class="hero-stats">
      {{if .Overall.Critical}}
      <div class="stat-item">
        <span class="stat-num" style="color:var(--red);">{{.Overall.Critical}}</span>
        <span class="stat-lbl">Critical</span>
      </div>
      {{end}}
      {{if .Overall.High}}
      <div class="stat-item">
        <span class="stat-num" style="color:var(--orange);">{{.Overall.High}}</span>
        <span class="stat-lbl">High</span>
      </div>
      {{end}}
      {{if .Overall.Medium}}
      <div class="stat-item">
        <span class="stat-num" style="color:var(--yellow);">{{.Overall.Medium}}</span>
        <span class="stat-lbl">Medium</span>
      </div>
      {{end}}
      {{if .Overall.Low}}
      <div class="stat-item">
        <span class="stat-num" style="color:var(--blue);">{{.Overall.Low}}</span>
        <span class="stat-lbl">Low</span>
      </div>
      {{end}}
      <div class="stat-item">
        <span class="stat-num" style="color:var(--text);">{{len .Servers}}</span>
        <span class="stat-lbl">Servers</span>
      </div>
    </div>
    {{if gt $total 0}}
    <div class="sev-bar">
      {{if .Overall.Critical}}<div class="sev-bar-seg" style="width:{{mul .Overall.Critical 100 | div $total}}%; background:var(--red);"></div>{{end}}
      {{if .Overall.High}}<div class="sev-bar-seg" style="width:{{mul .Overall.High 100 | div $total}}%; background:var(--orange);"></div>{{end}}
      {{if .Overall.Medium}}<div class="sev-bar-seg" style="width:{{mul .Overall.Medium 100 | div $total}}%; background:var(--yellow);"></div>{{end}}
      {{if .Overall.Low}}<div class="sev-bar-seg" style="width:{{mul .Overall.Low 100 | div $total}}%; background:var(--blue);"></div>{{end}}
    </div>
    {{end}}
  </div>
</section>

{{if .ScoreCapReason}}
<div class="cap-note">Score capped: <strong>{{.ScoreCapReason}}</strong></div>
{{end}}

{{if .BlastRadius}}
<section class="blast">
  <div class="section-label" style="max-width:none;padding:0;">
    <span class="section-label-text">Blast radius</span>
    <span class="section-label-line"></span>
  </div>
  <div class="blast-card">
    <div class="blast-level">
      <span class="blast-level-num" style="color: {{blastColor .BlastRadius.Level}};">{{.BlastRadius.Level}}</span>
      <span class="blast-level-lbl">reach</span>
    </div>
    <div class="blast-reasons">
      {{range .BlastRadius.Why}}
      <div class="blast-reason {{if .Present}}on{{else}}off{{end}}">
        <span class="blast-mark">{{if .Present}}✓{{else}}·{{end}}</span>
        <span>{{.Text}}</span>
      </div>
      {{end}}
    </div>
  </div>
</section>
{{end}}

{{if .AttackPaths}}
<section class="paths">
  <div class="section-label" style="max-width:none;padding:0;">
    <span class="section-label-text">Attack paths</span>
    <span class="section-label-line"></span>
    <span class="section-label-text" style="color:var(--muted);">{{len .AttackPaths}}</span>
  </div>
  {{range .AttackPaths}}
  <div class="path-card" style="--path-color: {{sevColor .Severity}};">
    <div class="path-head">
      <div class="path-title">
        <div class="path-name">{{.Name}}</div>
        {{if .Description}}<div class="path-desc">{{.Description}}</div>{{end}}
      </div>
      <div class="path-badges">
        <span class="sev-badge" style="background: {{sevColor .Severity}};">{{.Severity}}</span>
        <span class="rule-id">{{.ID}}{{if .Confidence}} · confidence {{.Confidence}}{{end}}</span>
      </div>
    </div>
    {{if .Servers}}
    <div class="path-servers">
      {{range .Servers}}<span class="path-server-chip">{{.}}</span>{{end}}
    </div>
    {{end}}
    {{if .Steps}}
    <div class="path-flow">
      {{range $i, $s := .Steps}}
      <div class="flow-step">
        <span class="flow-node">{{if eq $i 0}}◆{{else}}↓{{end}}</span>
        <span class="flow-text">{{$s}}</span>
      </div>
      {{end}}
    </div>
    {{end}}
    {{if or .Impact .Remediation}}
    <div class="path-foot">
      {{if .Impact}}
      <div class="path-impact">
        <div class="path-foot-label">Impact</div>
        <div class="path-foot-text">{{.Impact}}</div>
      </div>
      {{end}}
      {{if .Remediation}}
      <div>
        <div class="path-foot-label">What removes it</div>
        <div class="path-foot-text">{{.Remediation}}</div>
      </div>
      {{end}}
    </div>
    {{end}}
  </div>
  {{end}}
</section>
{{end}}

<!-- Server cards -->
<main class="server-list">

{{range .Servers}}
{{$hasFinding := gt (len .Findings) 0}}
{{$worstSev := ""}}
{{range .Findings}}{{if eq $worstSev ""}}{{$worstSev = .Severity}}{{end}}{{end}}

<div class="server-card server-card-left-bar {{if $hasFinding}}open{{end}}"
     style="--bar-color: {{if $hasFinding}}{{sevColor $worstSev}}{{else}}var(--green){{end}};"
     data-server="{{.Name}}">

  <div class="server-header" onclick="toggleCard(this.parentElement)">
    <div class="server-left">
      <div class="server-icon">{{slice .Name 0 2}}</div>
      <div>
        <div class="server-name">{{.Name}}</div>
        <div class="server-meta">
          {{if .Client}}<span class="meta-chip">{{.Client}}</span>{{end}}
          {{if .StaticOnly}}<span class="meta-chip">static only</span>{{end}}
          {{if .Findings}}<span class="meta-chip">{{len .Findings}} finding{{if gt (len .Findings) 1}}s{{end}}</span>{{end}}
        </div>
      </div>
    </div>
    <div class="server-right">
      <div>
        <span class="server-score-num" style="color: {{bandColor .Band}};">{{.Score}}</span>
        <span class="server-score-denom"> / 100</span>
      </div>
      {{if $hasFinding}}<div class="server-chevron">▾</div>{{end}}
    </div>
  </div>

  {{if $hasFinding}}
  <div class="findings-list">
    {{range .Findings}}
    <div class="finding" data-sev="{{lower .Severity}}">
      <div class="finding-left">
        <span class="sev-badge" style="background: {{sevColor .Severity}};">{{.Severity}}</span>
        <span class="rule-id">{{.RuleID}}</span>
      </div>
      <div class="finding-body">
        <div class="finding-name">{{.Name}}</div>
        {{if .Detail}}<div class="finding-detail">{{.Detail}}</div>{{end}}
        {{if .Mapping}}
        <div class="framework-tags">
          {{range split .Mapping ", "}}<span class="framework-tag">{{.}}</span>{{end}}
        </div>
        {{end}}
        {{if .Fix}}
        <div class="fix-block">
          <div class="fix-label">Recommended fix</div>
          <div class="fix-text">{{.Fix}}</div>
        </div>
        {{end}}
      </div>
    </div>
    {{end}}
  </div>
  {{else}}
  <div class="findings-list" style="display:block;">
    <div class="no-findings">
      <div class="no-findings-icon">✓</div>
      No security findings detected.
    </div>
  </div>
  {{end}}
</div>
{{end}}

</main>

<footer class="footer" style="max-width:960px;">
  <span class="footer-brand">Generated by <strong>aspex-scan</strong> v{{.Version}}</span>
  <a href="https://github.com/aspex-security/aspex" class="footer-link" target="_blank">github.com/aspex-security/aspex ↗</a>
</footer>

<script>
function toggleCard(card) {
  card.classList.toggle('open');
}

function filter(sev, btn) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.finding').forEach(f => {
    f.style.display = (sev === 'all' || f.dataset.sev === sev) ? 'flex' : 'none';
  });
  // Show/hide server cards based on whether they have visible findings.
  document.querySelectorAll('.server-card').forEach(card => {
    if (sev === 'all') {
      card.style.display = '';
      return;
    }
    const visible = card.querySelectorAll('.finding[style*="flex"]').length;
    const hasType = card.querySelectorAll('.finding[data-sev="' + sev + '"]').length;
    card.style.display = hasType ? '' : 'none';
  });
}

// Animate score gauge on load.
window.addEventListener('load', function() {
  document.querySelectorAll('.gauge-ring').forEach(function(el) {
    const targetDeg = getComputedStyle(el).getPropertyValue('--gauge-deg').trim();
    el.style.setProperty('--gauge-deg', '0deg');
    requestAnimationFrame(function() {
      el.style.transition = 'background 1s cubic-bezier(.4,0,.2,1)';
      setTimeout(function() {
        el.style.setProperty('--gauge-deg', targetDeg);
      }, 100);
    });
  });
});
</script>
</body>
</html>
`))
