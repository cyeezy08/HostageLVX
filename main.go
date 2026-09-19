package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

var version = "dev"

var Fingerprints = map[string]string{
	"Heroku":       "No such app",
	"GitHub Pages": "There isn't a GitHub Pages site here",
	"Cloudflare":   "Error 1000",
}

type Verdict string

type Finding struct {
	Host    string
	Verdict Verdict
	Service string
	Note    string
	IP      string
	CNAME   string
	Status  int
	Server  string
	Tech    []string
}

func (f *Finding) TakeoverCapable() bool {
	if f == nil {
		return false
	}
	return f.Verdict == Verdict("takeover")
}

func sevIndex(v Verdict) int {
	switch v {
	case Verdict("takeover"):
		return 0
	case Verdict("likely"):
		return 1
	case Verdict("alive"):
		return 2
	case Verdict("no_dns"):
		return 3
	default:
		return 4
	}
}

type Resolver struct{}

func NewResolver(dnsServer, resolverMethod string, timeout time.Duration) *Resolver {
	return &Resolver{}
}

type WildcardRegistry struct{}

func NewWildcardRegistry(res *Resolver, useCanary bool) *WildcardRegistry {
	return &WildcardRegistry{}
}

func (r *WildcardRegistry) Build(ctx context.Context, targets []string, timeout time.Duration) {}

func (r *WildcardRegistry) Apply(findings []*Finding) {}

func ScanHost(ctx context.Context, host string, res *Resolver, timeout time.Duration) *Finding {
	return &Finding{
		Host:    host,
		Verdict: Verdict("alive"),
		Service: "generic",
		IP:      "127.0.0.1",
	}
}

func Render(findings []*Finding, compact bool) string {
	if len(findings) == 0 {
		return "[=] 0 scanned"
	}
	sort.SliceStable(findings, func(i, j int) bool { return sevIndex(findings[i].Verdict) < sevIndex(findings[j].Verdict) })

	var lines []string
	for _, f := range findings {
		if f == nil {
			continue
		}
		line := fmt.Sprintf("[%s] %s", strings.ToUpper(string(f.Verdict)), f.Host)
		if f.Service != "" {
			line += fmt.Sprintf(" (%s)", f.Service)
		}
		if f.Note != "" {
			line += " - " + f.Note
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func demoTargets() []string {
	return []string{
		"api.example.com",
		"admin.example.com",
		"legacy.example.com",
		"staging.example.com",
		"cdn.example.com",
		"shop.example.com",
	}
}

func brandHeader(name string) string {
	brand := strings.TrimSpace(strings.ToUpper(name))
	if brand == "" {
		brand = "LEVIATHAN.AC"
	}
	return fmt.Sprintf(" %s // HOSTAGE LVX // LIVE SWARM OPS ", brand)
}

func main() {
	var (
		tui          bool
		demoMode     bool
		fingerprints bool
		jsonl        bool
		silent       bool
		noColor      bool
		showVersion  bool
		outFile      string
		threads      int
		timeout      float64
		resolver     string
		dnsServer    string
		noWildcard   bool
	)

	fs := flag.NewFlagSet("hostage", flag.ContinueOnError)
	fs.BoolVar(&tui, "tui", false, "run interactive TUI")
	fs.BoolVar(&demoMode, "demo", false, "run a live demo board")
	fs.BoolVar(&fingerprints, "fingerprints", false, "print fingerprint database and exit")
	fs.BoolVar(&jsonl, "json", false, "write JSONL output")
	fs.BoolVar(&silent, "silent", false, "only print confirmed takeover candidates")
	fs.BoolVar(&noColor, "no-color", false, "disable color")
	fs.BoolVar(&showVersion, "V", false, "print version and exit")
	fs.StringVar(&outFile, "o", "", "write output to file")
	fs.IntVar(&threads, "t", 50, "concurrent workers")
	fs.Float64Var(&timeout, "timeout", 8.0, "per-request timeout in seconds")
	fs.StringVar(&resolver, "resolver", "doh", "resolver mode")
	fs.StringVar(&dnsServer, "dns-server", "", "custom UDP resolver")
	fs.BoolVar(&noWildcard, "no-wildcard-check", false, "disable wildcard detection")
	fs.SetOutput(os.Stderr)

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	if showVersion {
		fmt.Println(version)
		return
	}

	if fingerprints {
		for name, pattern := range Fingerprints {
			fmt.Printf("%s: %s\n", name, pattern)
		}
		return
	}

	if demoMode {
		os.Exit(runDemoTUI())
	}

	if len(fs.Args()) == 0 {
		fmt.Fprintln(os.Stderr, "hostage: no targets supplied")
		os.Exit(2)
	}

	wildcard := !noWildcard
	if tui {
		code := runTUI(fs.Args(), threads, time.Duration(timeout*float64(time.Second)), dnsServer, resolver, wildcard)
		os.Exit(code)
	}

	results := make([]*Finding, 0, len(fs.Args()))
	for _, target := range fs.Args() {
		results = append(results, ScanHost(context.Background(), target, NewResolver(dnsServer, resolver, time.Duration(timeout*float64(time.Second))), time.Duration(timeout*float64(time.Second))))
	}

	if jsonl {
		for _, item := range results {
			fmt.Printf("%s\n", item.Host)
		}
		return
	}

	if silent {
		for _, item := range results {
			if item.TakeoverCapable() {
				fmt.Println(item.Host)
			}
		}
		return
	}

	if outFile != "" {
		if err := os.WriteFile(outFile, []byte(Render(results, false)), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "hostage: %v\n", err)
			os.Exit(2)
		}
		return
	}

	fmt.Println(Render(results, false))
}
