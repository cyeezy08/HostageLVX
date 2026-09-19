package main

import (
    "context"
    "flag"
    "fmt"
    "io"
    "os"
    "sort"
    "strings"
    "sync"
    "time"
)

const version = "0.3.0"

const banner = ` _   _ _____ _____            _      ___  ___
| | | |_   _|  ___| __ ___  _| |    / _ \/ __|
| |_| | | | | |_ | '__/ _ \(_)_|   | | | \__ \
|  _  | | | |  _|| | | (_) | _     | |_| |___) |
|_| |_| |_| |_|  |_|  \___/(_)     \___/|____/`

func printBanner(color bool) {
    shades := []string{Red, "\033[38;5;202m", "\033[38;5;208m", "\033[38;5;214m", "\033[38;5;220m"}
    for i, ln := range strings.Split(banner, "\n") {
        if color {
            fmt.Println(shades[i%len(shades)] + ln + Reset)
        } else {
            fmt.Println(ln)
        }
    }
    fmt.Println()
    fmt.Println("  " + Paint("leviathan.ac", Bold+Red, color) + Paint(" - rapid dangling-DNS & takeover engine", Dim, color))
    fmt.Println("  " + Paint(fmt.Sprintf("v%s - %d fingerprints - authorized scope only", version, len(Fingerprints)), Dim, color))
    fmt.Println()
}

func main() {
    var (
        threads    = flag.Int("t", 50, "concurrent workers")
        timeoutS   = flag.Float64("timeout", 8.0, "per-request DNS/HTTP timeout (seconds)")
        resolver   = flag.String("resolver", "doh", "doh (rapid, 1-query chains) or system")
        dnsServer  = flag.String("dns-server", "", "custom UDP resolver IP (forces system mode)")
        asJSON     = flag.Bool("json", false, "JSONL output, one finding per line (PD-style)")
        silent     = flag.Bool("silent", false, "only print TAKEOVER/LIKELY hits")
        outFile    = flag.String("o", "", "save findings to file (JSONL with -json, text otherwise)")
        showFPs    = flag.Bool("fingerprints", false, "print the fingerprint database and exit")
        noColor    = flag.Bool("no-color", false, "disable colored output")
        noWildcard = flag.Bool("no-wildcard-check", false, "skip wildcard-DNS canary detection")
        showVer    = flag.Bool("V", false, "print version and exit")
    )
    flag.Parse()

    if *showVer {
        fmt.Println("hostage", version)
        return
    }
    if *showFPs {
        fmt.Printf("hostage v%s - fingerprint database\n\n", version)
        fmt.Println(RenderFingerprints(ColorEnabled(*noColor)))
        return
    }

    timeout := time.Duration(*timeoutS * float64(time.Second))

    targets := ParseTargets(flag.Args(), os.Stdin)
    if len(targets) == 0 {
        if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice == 0 {
            targets = ParseTargets([]string{"-"}, os.Stdin)
        }
    }
    if len(targets) == 0 {
        flag.Usage()
        fmt.Fprintln(os.Stderr, "\nerror: no targets (hosts, @file, stdin pipe)")
        os.Exit(2)
    }

    findings, reg := Run(targets, *threads, timeout, *dnsServer, *resolver, !*noWildcard)

    color := ColorEnabled(*noColor)
    var sink io.Writer = os.Stdout
    if *outFile != "" {
        fh, err := os.Create(*outFile)
        if err != nil {
            fmt.Fprintln(os.Stderr, "hostage: cannot create output file:", err)
            os.Exit(2)
        }
        defer fh.Close()
        sink = fh
    }

    switch {
    case *asJSON:
        WriteJSONL(findings, sink)
    case *silent:
        for _, f := range findings {
            if f.TakeoverCapable() {
                fmt.Fprintln(sink, HotLine(f, color && sink == os.Stdout))
            }
        }
    default:
        if sink == os.Stdout {
            if color {
                printBanner(true)
            }
            if n := reg.ActiveCanaries(); n > 0 {
                fmt.Println(Paint(fmt.Sprintf("  wildcard canaries: %d zone(s) - parking noise auto-nulled", n), Dim, color))
            }
            fmt.Println(Render(findings, color))
        } else {
            fmt.Fprint(sink, Render(findings, false)+"\n")
            fmt.Printf("results saved to %s\n", *outFile)
        }
    }

    for _, f := range findings {
        if f.TakeoverCapable() {
            os.Exit(1)
        }
    }
}

func Run(targets []string, threads int, timeout time.Duration, dnsServer, resolverMethod string, wildcard bool) ([]*Finding, *WildcardRegistry) {
    res := NewResolver(dnsServer, resolverMethod, timeout)
    reg := NewWildcardRegistry(res, !wildcard)
    reg.Build(context.Background(), targets, timeout)

    findings := make([]*Finding, len(targets))
    sem := make(chan struct{}, max(1, threads))
    var wg sync.WaitGroup
    for i, host := range targets {
        wg.Add(1)
        go func(i int, host string) {
            defer wg.Done()
            sem <- struct{}{}
            defer func() { <-sem }()
            findings[i] = ScanHost(context.Background(), host, res, timeout)
        }(i, host)
    }
    wg.Wait()

    reg.Apply(findings)
    sort.SliceStable(findings, func(i, j int) bool {
        si, sj := sevIndex(findings[i].Verdict), sevIndex(findings[j].Verdict)
        if si != sj {
            return si < sj
        }
        return findings[i].Host < findings[j].Host
    })
    return findings, reg
}

func max(a, b int) int {
    if a > b {
        return a
    }
    return b
}