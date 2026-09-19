package main

import (
    "bufio"
    "fmt"
    "io"
    "os"
    "strings"
)

func ParseTargets(raw []string, stdin io.Reader) []string {
    var items []string
    for _, chunk := range raw {
        switch {
        case chunk == "-":
            items = append(items, readLines(stdin)...)
        case strings.HasPrefix(chunk, "@"):
            f, err := os.Open(strings.TrimPrefix(chunk, "@"))
            if err != nil {
                fmt.Fprintf(os.Stderr, "hostage: %v\n", err)
                continue
            }
            items = append(items, readLines(f)...)
            f.Close()
        default:
            items = append(items, strings.Split(chunk, ",")...)
        }
    }

    seen := make(map[string]struct{})
    var out []string
    for _, item := range items {
        t := strings.TrimRight(strings.TrimSpace(item), ".")
        if t == "" || strings.HasPrefix(t, "#") {
            continue
        }
        if strings.Contains(t, "/") {
            t = strings.TrimPrefix(strings.TrimPrefix(t, "https://"), "http://")
            if i := strings.Index(t, "/"); i >= 0 {
                t = t[:i]
            }
        }
        if _, dup := seen[t]; dup {
            continue
        }
        seen[t] = struct{}{}
        out = append(out, t)
    }
    return out
}

func readLines(r io.Reader) []string {
    var lines []string
    sc := bufio.NewScanner(r)
    sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
    for sc.Scan() {
        lines = append(lines, sc.Text())
    }
    return lines
}