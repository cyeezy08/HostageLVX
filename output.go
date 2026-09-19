package main

import (
    "encoding/json"
    "fmt"
    "io"
    "os"
    "strings"
)

const (
    Reset  = "\033[0m"
    Bold   = "\033[1m"
    Dim    = "\033[2m"
    Red    = "\033[31m"
    Green  = "\033[32m"
    Yellow = "\033[33m"
    Cyan   = "\033[36m"
)

func Paint(text, code string, enabled bool) string {
    if !enabled {
        return text
    }
    return code + text + Reset
}

func ColorEnabled(noColor bool) bool {
    if noColor || os.Getenv("NO_COLOR") != "" {
        return false
    }
    if fi, err := os.Stdout.Stat(); err == nil {
        return fi.Mode()&os.ModeCharDevice != 0
    }
    return false
}

var marks = map[Verdict]struct{ mark, color string }{
    Takeover: {"[!]", Red},
    Likely:   {"[~]", Yellow},
    Dangling: {"[-]", Cyan},
    Alive:    {"[.]", Green},
    Wildcard: {"[w]", Dim},
    Error:    {"[x]", Dim},
    NoDNS:    {"[Â·]", Dim},
}

func HotLine(f *Finding, color bool) string {
    m := marks[f.Verdict]
    route := ""
    if f.CNAME != "" {
        route = "  ->  " + f.CNAME
    }
    extra := ""
    if f.Service != "" {
        extra = "  [" + f.Service + "]"
    }
    return Paint(m.mark, m.color, color) + " " +
        Paint(fmt.Sprintf("%-9s", f.Verdict), m.color, color) + " " + f.Host + route + extra
}

func Render(findings []*Finding, color bool) string {
    var lines []string
    counts := map[Verdict]int{}
    for _, f := range findings {
        counts[f.Verdict]++
    }
    width := 4
    for _, f := range findings {
        if len(f.Host) > width {
            width = len(f.Host)
        }
    }

    for _, f := range findings {
        m := marks[f.Verdict]
        route := ""
        if f.CNAME != "" {
            route = "  ->  " + f.CNAME
        } else if len(f.IPs) > 0 {
            route = "  ->  " + f.IPs[0]
        }
        lines = append(lines, fmt.Sprintf("%s %s %s%s",
            Paint(m.mark, m.color, color),
            Paint(fmt.Sprintf("%-9s", f.Verdict), m.color, color),
            pad(f.Host, width), route))

        var detail []string
        if f.Service != "" {
            detail = append(detail, f.Service)
        }
        if len(f.Tech) > 0 {
            detail = append(detail, strings.Join(f.Tech, ", "))
        }
        if f.Evidence != "" {
            detail = append(detail, f.Evidence)
        }
        if len(detail) > 0 {
            lines = append(lines, Paint("      "+strings.Join(detail, " - "), Dim, color))
        }
        if f.Note != "" && (f.Verdict == Takeover || f.Verdict == Likely) {
            lines = append(lines, Paint("      claim: "+f.Note, Dim, color))
        }
    }

    parts := []string{fmt.Sprintf("%d scanned", len(findings))}
    for _, v := range Severity {
        if counts[v] > 0 {
            m := marks[v]
            parts = append(parts, Paint(fmt.Sprintf("%d %s", counts[v], v), m.color, color))
        }
    }
    lines = append(lines, "", "  "+strings.Join(parts, " - "))
    return strings.Join(lines, "\n")
}

func pad(s string, w int) string {
    if len(s) >= w {
        return s
    }
    return s + strings.Repeat(" ", w-len(s))
}

func WriteJSONL(findings []*Finding, w io.Writer) error {
    enc := json.NewEncoder(w)
    for _, f := range findings {
        if err := enc.Encode(f); err != nil {
            return err
        }
    }
    return nil
}

func RenderFingerprints(color bool) string {
    var lines []string
    for _, fp := range Fingerprints {
        tag := "protected      "
        tc := Cyan
        if fp.Vulnerable {
            tag = "TAKEOVER-CAPABLE"
            tc = Red
        }
        suffixes := ""
        for i, re := range fp.CNAMEs {
            if i == 2 {
                break
            }
            if i > 0 {
                suffixes += ", "
            }
            suffixes += strings.TrimSuffix(strings.TrimPrefix(re.String(), "^(?:"), ")$")
        }
        lines = append(lines, fmt.Sprintf("  %-22s %s  %s", fp.Service, Paint(tag, tc, color), suffixes))
    }
    lines = append(lines, "", fmt.Sprintf("  %d fingerprints - derived from public takeover research", len(Fingerprints)))
    return strings.Join(lines, "\n")
}