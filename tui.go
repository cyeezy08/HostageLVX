// tui.go — interactive TUI mode for hostage (v2 — with ASCII banner)
//
// Activated with `hostage -tui @subs.txt`. Wraps the existing ScanHost
// primitive with a bubbletea interface: ASCII logo header, live target
// table, streaming findings, progress bar, summary.
//
// v2 changes:
//   - Big ASCII logo banner at the top (same art as text mode)
//   - Brand line "LEVIATHAN · OFFENSIVE OPERATIONS"
//   - Animated tagline cycle in the header
//   - Compact mode (auto-engages when terminal < 24 rows)
//   - Stats badges row (CVEs indexed · fingerprints · scope)
//
// Windows notes:
//   - VT mode is enabled at init() time by vt_windows.go, so ANSI colors
//     and the alt-screen buffer work in cmd.exe / Windows Terminal / PowerShell.
//   - bubbletea also calls SetConsoleMode itself; the double-enable is idempotent.
package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ─── styles ──────────────────────────────────────────────────────────

var (
	tuiBrand = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#ffffff")).
			Background(lipgloss.Color("#00d9ff")).
			Padding(0, 1)

	tuiMuted = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#cfe8ef"))

	tuiPanel = lipgloss.NewStyle().
			Border(lipgloss.ThickBorder()).
			BorderForeground(lipgloss.Color("#00d9ff")).
			Padding(0, 1)

	tuiPanelRed = lipgloss.NewStyle().
			Border(lipgloss.ThickBorder()).
			BorderForeground(lipgloss.Color("#ffffff")).
			Padding(0, 1)

	tuiTakeover = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00d9ff")).
			Bold(true)

	tuiAlive = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7ef9d6"))

	tuiNoDns = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#dfeaf0"))

	tuiLikely = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#dff7ff"))

	tuiDim = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#5d7078"))

	tuiAccent = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00d9ff"))

	tuiLogo = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#00d9ff")).
		Bold(true)

	tuiLogoDim = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#8ecae6"))

	tuiTagline = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#dff7ff")).
			Bold(true)
)

// ─── ASCII logo ────────────────────────────────────────────────────────

const logoArt = `
    __  ______  ______________   ____________
   / / / / __ \/ ___/_  __/   | / ____/ ____/
  / /_/ / / / /\__ \ / / / /| |/ / __/ __/   
 / __  / /_/ /___/ // / / ___ / /_/ / /___   
/_/ /_/\____//____//_/ /_/  |_|\____/_____/   
`

// Animated taglines cycle in the header — gives the screenshot motion
var taglines = []string{
	"BUILT FOR EXPOSURE.",
	"DANGLING DNS. CUT QUICK.",
	"21 FINGERPRINTS. NO NOISE.",
	"LEVIATHAN.AC // RAPID TAKEOVER CHECK.",
	"RAPID TAKEOVER CHECK.",
}

// ─── tea messages ────────────────────────────────────────────────────

type findingMsg struct{ f *Finding }
type doneMsg struct{}
type tickMsg time.Time

type demoTickMsg time.Time

// ─── model ───────────────────────────────────────────────────────────

type tuiModel struct {
	targets  []string
	threads  int
	timeout  time.Duration
	resolver string
	wildcard bool

	findings map[string]*Finding
	order    []string

	stream chan *Finding
	done   chan struct{}

	spinner   spinner.Model
	startTime time.Time
	quit      bool
	width     int
	height    int
	tagline   string
	tagIdx    int
	tagTick   int
}

func newTUIModel(targets []string, threads int, timeout time.Duration, resolver string, wildcard bool) tuiModel {
	sp := spinner.New()
	sp.Spinner = spinner.MiniDot
	sp.Style = tuiAccent

	return tuiModel{
		targets:   targets,
		threads:   threads,
		timeout:   timeout,
		resolver:  resolver,
		wildcard:  wildcard,
		findings:  make(map[string]*Finding),
		order:     append([]string(nil), targets...),
		stream:    make(chan *Finding, threads*2),
		done:      make(chan struct{}),
		spinner:   sp,
		startTime: time.Now(),
		tagline:   taglines[0],
	}
}

func (m tuiModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		waitForFinding(m.stream, m.done),
		tickTagline(),
	)
}

// ─── update ───────────────────────────────────────────────────────────

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			m.quit = true
			return m, tea.Quit
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case tickMsg:
		m.tagTick++
		if m.tagTick >= 8 { // cycle every 8 ticks (~2s)
			m.tagTick = 0
			m.tagIdx = (m.tagIdx + 1) % len(taglines)
			m.tagline = taglines[m.tagIdx]
		}
		return m, tickTagline()

	case findingMsg:
		m.findings[msg.f.Host] = msg.f
		return m, waitForFinding(m.stream, m.done)

	case doneMsg:
		return m, tea.Quit
	}
	return m, nil
}

// ─── view ────────────────────────────────────────────────────────────

func (m tuiModel) View() string {
	if m.quit {
		return ""
	}

	compact := m.height > 0 && m.height < 24

	var b strings.Builder

	// ─── logo header (skipped in compact mode) ───
	if !compact {
		// red gradient on the logo — first 2 lines dim, last 3 bright
		lines := strings.Split(logoArt, "\n")
		for i, ln := range lines {
			if i < 2 {
				b.WriteString(tuiLogoDim.Render(ln))
			} else {
				b.WriteString(tuiLogo.Render(ln))
			}
			b.WriteString("\n")
		}

		// brand line
		brand := tuiBrand.Render(" LEVIATHAN.AC ") +
			tuiMuted.Render(" // ") +
			tuiBrand.Render(" HOSTAGE LVX ")
		b.WriteString(brand)
		b.WriteString("\n")

		// animated tagline
		b.WriteString(tuiTagline.Render("  " + m.tagline))
		b.WriteString("\n\n")
	}

	// ─── meta line ───
	meta := tuiMuted.Render(fmt.Sprintf(
		"v%s · %d fingerprints · authorized scope only · %s resolver",
		version, len(Fingerprints), m.resolver))
	b.WriteString(meta)
	b.WriteString("\n\n")

	// ─── status + progress ───
	completed := len(m.findings)
	total := len(m.targets)
	pct := 0
	if total > 0 {
		pct = completed * 100 / total
	}
	elapsed := time.Since(m.startTime).Round(time.Second)

	status := fmt.Sprintf(" %s scanning %d targets · %d workers · %s timeout",
		m.spinner.View(), total, m.threads, m.timeout)
	b.WriteString(tuiMuted.Render(status))
	b.WriteString("\n")

	barWidth := 40
	if m.width > 20 && m.width-30 < barWidth {
		barWidth = m.width - 30
		if barWidth < 10 {
			barWidth = 10
		}
	}
	filled := barWidth * pct / 100
	if filled > barWidth {
		filled = barWidth
	}
	bar := tuiAccent.Render(strings.Repeat("█", filled)) +
		tuiDim.Render(strings.Repeat("░", barWidth-filled))
	progress := fmt.Sprintf(" [%s] %d/%d · %d%% · %s elapsed",
		bar, completed, total, pct, elapsed)
	b.WriteString(progress)
	b.WriteString("\n\n")

	// ─── targets table ───
	rows := make([]string, 0, len(m.order))
	maxVisible := 12
	if compact {
		maxVisible = 6
	}
	if len(m.order) > maxVisible {
		// show first N-1 + last with ellipsis
		for i := 0; i < maxVisible-1; i++ {
			rows = append(rows, m.renderTargetLine(m.order[i]))
		}
		rows = append(rows, tuiDim.Render(fmt.Sprintf(" ... %d more targets", len(m.order)-maxVisible+1)))
	} else {
		for _, host := range m.order {
			rows = append(rows, m.renderTargetLine(host))
		}
	}
	table := tuiPanel.Render(strings.Join(rows, "\n"))
	b.WriteString(table)
	b.WriteString("\n\n")

	// ─── takeover findings stream (only shows takeovers) ───
	takeovers := []*Finding{}
	for _, f := range m.findings {
		if f.TakeoverCapable() {
			takeovers = append(takeovers, f)
		}
	}
	sort.SliceStable(takeovers, func(i, j int) bool {
		return takeovers[i].Host < takeovers[j].Host
	})

	if len(takeovers) > 0 {
		findingsLines := make([]string, 0, len(takeovers)*4)
		findingsLines = append(findingsLines,
			tuiTakeover.Render(fmt.Sprintf(" ⚠  %d TAKEOVER CANDIDATES", len(takeovers))))
		findingsLines = append(findingsLines, "")
		for _, f := range takeovers {
			findingsLines = append(findingsLines,
				fmt.Sprintf(" ✗ %s  %s",
					tuiTakeover.Render(f.Host),
					tuiMuted.Render("→ "+f.Service)))
			if f.Note != "" {
				findingsLines = append(findingsLines,
					fmt.Sprintf("   %s %s",
						tuiMuted.Render("note"),
						tuiDim.Render(f.Note)))
			}
			findingsLines = append(findingsLines, "")
		}
		// trim trailing empty line
		findingsLines = findingsLines[:len(findingsLines)-1]
		b.WriteString(tuiPanelRed.Render(strings.Join(findingsLines, "\n")))
		b.WriteString("\n\n")
	}

	// ─── summary + footer ───
	counts := map[string]int{}
	for _, f := range m.findings {
		counts[string(f.Verdict)]++
	}
	summary := fmt.Sprintf(" %d scanned · %d alive · %d no_dns · %d takeover · %d likely",
		completed,
		counts["alive"],
		counts["no_dns"],
		counts["takeover"],
		counts["likely"])
	b.WriteString(tuiMuted.Render(summary))
	b.WriteString("\n")
	b.WriteString(tuiDim.Render(" [q] quit"))
	b.WriteString("\n")

	return b.String()
}

func (m tuiModel) renderTargetLine(host string) string {
	f, done := m.findings[host]
	if !done {
		return fmt.Sprintf(" %s %-44s %s",
			m.spinner.View(),
			host,
			tuiDim.Render("scanning..."))
	}

	switch f.Verdict {
	case "takeover":
		svc := f.Service
		if svc == "" {
			svc = "?"
		}
		return fmt.Sprintf(" ✗ %-44s %s  %s",
			host,
			tuiTakeover.Render("TAKEOVER"),
			tuiMuted.Render(svc))
	case "alive":
		extra := ""
		if f.IP != "" {
			extra = f.IP
		}
		if f.Service != "" {
			if extra != "" {
				extra += "  "
			}
			extra += f.Service
		}
		return fmt.Sprintf(" ✓ %-44s %s  %s",
			host,
			tuiAlive.Render("ALIVE"),
			tuiMuted.Render(extra))
	case "no_dns":
		return fmt.Sprintf(" ○ %-44s %s",
			host,
			tuiNoDns.Render("NO_DNS"))
	case "likely":
		return fmt.Sprintf(" ? %-44s %s",
			host,
			tuiLikely.Render("LIKELY"))
	default:
		return fmt.Sprintf(" · %-44s %s",
			host,
			tuiMuted.Render(string(f.Verdict)))
	}
}

// ─── tea commands ─────────────────────────────────────────────────────

func waitForFinding(stream chan *Finding, done chan struct{}) tea.Cmd {
	return func() tea.Msg {
		select {
		case f, ok := <-stream:
			if !ok {
				return doneMsg{}
			}
			return findingMsg{f: f}
		case <-done:
			return doneMsg{}
		}
	}
}

func tickTagline() tea.Cmd {
	return tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// ─── live demo model ───────────────────────────────────────────────────

type demoModel struct {
	label     string
	status    string
	width     int
	height    int
	started   time.Time
	targets   []string
	results   map[string]*Finding
	cycles    int
	lastEvent string
	lastSeen  string
	current   int
}

func demoFinding(host string, idx int) *Finding {
	verdicts := []Verdict{"alive", "likely", "no_dns", "takeover", "alive"}
	v := verdicts[idx%len(verdicts)]
	f := &Finding{Host: host, Verdict: v}

	switch v {
	case Verdict("takeover"):
		f.Service = []string{"Heroku", "CloudFront", "Netlify", "Vercel"}[idx%4]
		f.Note = "match by service pattern; claim can be validated via origin mismatch"
	case Verdict("alive"):
		f.Service = []string{"nginx", "cloudflare", "Express", "Apache"}[idx%4]
		f.IP = fmt.Sprintf("10.%d.%d.%d", (idx+2)%255, (idx*3)%255, (idx*7)%255)
	case Verdict("likely"):
		f.Service = "generic"
		f.Note = "404 response without strong service fingerprint"
	case Verdict("no_dns"):
		f.Service = "none"
		f.Note = "resolver returned no answer"
	}

	return f
}

func (m demoModel) Init() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return demoTickMsg(t)
	})
}

func (m demoModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "esc" || msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	case demoTickMsg:
		m.cycles++
		m.current = (m.current + 1) % len(m.targets)
		host := m.targets[m.current]
		m.results[host] = demoFinding(host, m.cycles)
		m.lastEvent = fmt.Sprintf("%s · %s · %s",
			host,
			string(m.results[host].Verdict),
			m.results[host].Service)
		m.lastSeen = time.Now().Format(time.Kitchen)
		return m, tea.Tick(650*time.Millisecond, func(t time.Time) tea.Msg {
			return demoTickMsg(t)
		})
	}
	return m, nil
}

func (m demoModel) View() string {
	if m.width == 0 {
		m.width = 100
	}
	if m.height == 0 {
		m.height = 30
	}

	var b strings.Builder
	b.WriteString(tuiBrand.Render(brandHeader("LEVIATHAN.AC")))
	b.WriteString("\n")
	b.WriteString(tuiTagline.Render("  LIVE SWARM // HOSTAGE LVX // RAPID TAKEOVER CHECK"))
	b.WriteString("\n\n")

	counts := map[string]int{}
	for _, f := range m.results {
		if f == nil {
			continue
		}
		counts[string(f.Verdict)]++
	}
	cards := []string{
		fmt.Sprintf("%s  %d", tuiAccent.Render("scanned"), len(m.results)),
		fmt.Sprintf("%s  %d", tuiAlive.Render("alive"), counts["alive"]),
		fmt.Sprintf("%s  %d", tuiTakeover.Render("takeovers"), counts["takeover"]),
		fmt.Sprintf("%s  %d", tuiLikely.Render("likely"), counts["likely"]),
		fmt.Sprintf("%s  %s", tuiMuted.Render("runtime"), runtimePlatform()),
	}
	b.WriteString(strings.Join(cards, "   "))
	b.WriteString("\n\n")

	rows := make([]string, 0, len(m.targets))
	for i, host := range m.targets {
		f, ok := m.results[host]
		if !ok {
			rows = append(rows, fmt.Sprintf(" %s %-30s %s  %s",
				"…",
				host,
				tuiMuted.Render("QUEUED"),
				tuiDim.Render("awaiting scan")))
			continue
		}
		label := "ALIVE"
		color := tuiAlive.Render(label)
		symbol := "✓"
		switch f.Verdict {
		case Verdict("takeover"):
			label = "TAKEOVER"
			color = tuiTakeover.Render(label)
			symbol = "✗"
		case Verdict("likely"):
			label = "LIKELY"
			color = tuiLikely.Render(label)
			symbol = "?"
		case Verdict("no_dns"):
			label = "NO_DNS"
			color = tuiNoDns.Render(label)
			symbol = "○"
		}
		rows = append(rows, fmt.Sprintf(" %s %-30s %s  %s",
			symbol,
			host,
			color,
			tuiMuted.Render(f.Service)))
		if i == m.current {
			rows[len(rows)-1] += " " + tuiAccent.Render("↠ live")
		}
	}
	b.WriteString(tuiPanel.Render(strings.Join(rows, "\n")))
	b.WriteString("\n\n")

	feed := []string{}
	for _, host := range m.targets {
		if f, ok := m.results[host]; ok && f.TakeoverCapable() {
			feed = append(feed, fmt.Sprintf(" %s • %s • %s",
				tuiTakeover.Render(host),
				tuiMuted.Render(string(f.Verdict)),
				tuiDim.Render(f.Service)))
		}
	}
	if len(feed) == 0 {
		feed = append(feed, " no takeover candidates yet")
	}
	b.WriteString(tuiPanel.Render(strings.Join(feed, "\n")))
	b.WriteString("\n")
	b.WriteString(tuiMuted.Render(fmt.Sprintf(" last event · %s · %s", m.lastEvent, m.lastSeen)))
	b.WriteString("\n")
	b.WriteString(tuiDim.Render(" [q] quit"))
	return b.String()
}

func runtimePlatform() string {
	return strings.ToUpper(strings.TrimSpace(os.Getenv("GOOS")))
}

func runDemoTUI() int {
	m := demoModel{
		targets:  demoTargets(),
		results:  map[string]*Finding{},
		started:  time.Now(),
		lastSeen: time.Now().Format(time.Kitchen),
		label:    "LEVIATHAN.AC",
		status:   "active",
	}
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "hostage: demo tui error: %v\n", err)
		return 2
	}
	return 0
}

// ─── public entrypoint ────────────────────────────────────────────────

func runTUI(targets []string, threads int, timeout time.Duration, dnsServer, resolverMethod string, wildcard bool) int {
	res := NewResolver(dnsServer, resolverMethod, timeout)
	reg := NewWildcardRegistry(res, !wildcard)
	reg.Build(context.Background(), targets, timeout)

	m := newTUIModel(targets, threads, timeout, resolverMethod, wildcard)

	go func() {
		sem := make(chan struct{}, max(1, threads))
		var wg sync.WaitGroup
		for _, host := range targets {
			wg.Add(1)
			go func(host string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				f := ScanHost(context.Background(), host, res, timeout)
				m.stream <- f
			}(host)
		}
		wg.Wait()
		close(m.stream)
	}()

	p := tea.NewProgram(m, tea.WithAltScreen())
	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "hostage: tui error: %v\n", err)
		return 2
	}

	mm, ok := finalModel.(tuiModel)
	if !ok {
		fmt.Fprintf(os.Stderr, "hostage: tui state assertion failed\n")
		return 2
	}

	findings := make([]*Finding, 0, len(mm.findings))
	for _, f := range mm.findings {
		findings = append(findings, f)
	}
	reg.Apply(findings)
	sort.SliceStable(findings, func(i, j int) bool {
		return sevIndex(findings[i].Verdict) < sevIndex(findings[j].Verdict)
	})

	fmt.Println()
	fmt.Println(Render(findings, false))

	for _, f := range findings {
		if f.TakeoverCapable() {
			return 1
		}
	}
	return 0
}
