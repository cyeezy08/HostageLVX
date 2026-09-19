package main

import (
    "context"
    "encoding/json"
    "errors"
    "io"
    "net"
    "net/http"
    "net/url"
    "strings"
    "time"
)

const (
    maxChain     = 8
    chainLoopCap = 16
)

type DNSResult struct {
    Host     string
    Chain    []string
    IPs      []string
    NXDomain bool
    Err      string
    Resolver string
}

type Resolver struct {
    method  string // "doh" or "system"
    server  string // optional custom UDP resolver IP
    r       *net.Resolver
    timeout time.Duration
}

func NewResolver(server, method string, timeout time.Duration) *Resolver {
    res := &Resolver{timeout: timeout}
    res.method = "doh"
    if method == "system" {
        res.method = "system"
    }
    if server != "" { // explicit custom server = respect it fully
        res.method = "system"
        res.server = server
    }
    if res.method == "system" {
        if res.server != "" {
            d := &net.Dialer{Timeout: timeout}
            res.r = &net.Resolver{
                PreferGo: true,
                Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
                    return d.DialContext(ctx, network, net.JoinHostPort(res.server, "53"))
                },
            }
        } else {
            res.r = net.DefaultResolver
        }
    }
    return res
}

func (r *Resolver) provenance() string {
    if r.server == "" {
        return "system"
    }
    return "udp:" + r.server
}

func isNX(err error) bool {
    var dnsErr *net.DNSError
    return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// --- rapid path: DoH JSON. one recursive A query returns the FULL CNAME
// chain plus terminal A records in a single response ------------------------

var dohEndpoints = []string{"https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"}

type dohAnswer struct {
    Type int    `json:"type"`
    Data string `json:"data"`
}
type dohResponse struct {
    Status int         `json:"Status"`
    Answer []dohAnswer `json:"Answer"`
}

func dohHost(ep string) string {
    return strings.TrimPrefix(strings.TrimPrefix(ep, "https://"), "http://")
}

func (r *Resolver) dohQuery(ctx context.Context, host string) *DNSResult {
    res := &DNSResult{Host: host}
    q := url.Values{}
    q.Set("name", host)
    q.Set("type", "A")
    var lastErr string
    for _, ep := range dohEndpoints {
        req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep+"?"+q.Encode(), nil)
        if err != nil {
            lastErr = err.Error()
            continue
        }
        req.Header.Set("Accept", "application/dns-json")
        req.Header.Set("User-Agent", userAgent)
        resp, err := probeClient.Do(req) // pooled transport = keep-alive
        if err != nil {
            lastErr = err.Error()
            continue
        }
        var dr dohResponse
        err = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&dr)
        resp.Body.Close()
        if err != nil {
            lastErr = err.Error()
            continue
        }
        res.Resolver = "doh:" + dohHost(ep)
        if dr.Status == 3 {
            res.NXDomain = true
            return res
        }
        seen := map[string]bool{}
        for _, a := range dr.Answer {
            switch a.Type {
            case 5:
                t := strings.TrimSuffix(strings.ToLower(a.Data), ".")
                if t != "" && t != host && !seen[t] {
                    seen[t] = true
                    res.Chain = append(res.Chain, t)
                    if len(res.Chain) >= maxChain {
                        break
                    }
                }
            case 1:
                res.IPs = append(res.IPs, a.Data)
            }
        }
        return res
    }
    res.Err = "doh failed: " + lastErr
    return res
}

// --- fallback: system resolver with manual chain walking -------------------

func (r *Resolver) systemChain(ctx context.Context, host string) *DNSResult {
    res := &DNSResult{Host: host, Resolver: r.provenance()}
    ctx, cancel := context.WithTimeout(ctx, r.timeout*3)
    defer cancel()

    cur := host
    seen := map[string]bool{cur: true}
    for hops := 0; hops < chainLoopCap; hops++ {
        hctx, hcancel := context.WithTimeout(ctx, r.timeout)
        target, err := r.r.LookupCNAME(hctx, cur)
        hcancel()
        if err != nil {
            if isNX(err) {
                res.NXDomain = true
                return res
            }
            res.Err = err.Error()
            return res
        }
        target = strings.TrimSuffix(strings.ToLower(target), ".")
        if target == "" || target == cur || seen[target] {
            break
        }
        seen[target] = true
        res.Chain = append(res.Chain, target)
        if len(res.Chain) >= maxChain {
            break
        }
        cur = target
    }

    actx, acancel := context.WithTimeout(ctx, r.timeout)
    defer acancel()
    ips, err := r.r.LookupHost(actx, cur)
    if err != nil {
        if isNX(err) {
            res.NXDomain = true
            return res
        }
        if res.Err == "" {
            res.Err = err.Error()
        }
        return res
    }
    res.IPs = ips
    return res
}

func (r *Resolver) ResolveChain(ctx context.Context, host string) *DNSResult {
    host = strings.ToLower(strings.TrimRight(host, "."))
    if r.method == "doh" {
        res := r.dohQuery(ctx, host)
        if res.Err == "" {
            return res
        }
        // all DoH endpoints failed -> system fallback
    }
    return r.systemChain(ctx, host)
}