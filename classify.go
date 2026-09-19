package main

import (
    "context"
    "fmt"
    "time"
)

type Verdict string

const (
    Takeover Verdict = "TAKEOVER"
    Likely   Verdict = "LIKELY"
    Dangling Verdict = "DANGLING"
    Alive    Verdict = "ALIVE"
    Wildcard Verdict = "WILDCARD"
    Error    Verdict = "ERROR"
    NoDNS    Verdict = "NO_DNS"
)

var Severity = []Verdict{Takeover, Likely, Dangling, Wildcard, Alive, Error, NoDNS}

func sevIndex(v Verdict) int {
    for i, s := range Severity {
        if s == v {
            return i
        }
    }
    return len(Severity)
}

type Finding struct {
    Host     string   `json:"host"`
    Verdict  Verdict  `json:"verdict"`
    Service  string   `json:"service,omitempty"`
    Tech     []string `json:"tech,omitempty"`
    CNAME    string   `json:"cname,omitempty"`
    Chain    []string `json:"chain,omitempty"`
    IPs      []string `json:"ips,omitempty"`
    Status   int      `json:"status,omitempty"`
    Evidence string   `json:"evidence,omitempty"`
    Note     string   `json:"note,omitempty"`
    Resolver string   `json:"resolver,omitempty"`
    BodyHash string   `json:"body_hash,omitempty"`
}

func (f *Finding) TakeoverCapable() bool { return f.Verdict == Takeover || f.Verdict == Likely }

func truncate(s string, n int) string {
    if len(s) <= n {
        return s
    }
    return s[:n]
}

func Classify(host string, res *DNSResult, p *ProbeResult) *Finding {
    cname := ""
    if len(res.Chain) > 0 {
        cname = res.Chain[0]
    }
    fp := FingerprintByCNAME(cname)

    nxd := res.NXDomain
    noAnswer := len(res.Chain) == 0 && len(res.IPs) == 0 && !nxd && res.Err == ""
    if (nxd || noAnswer) && len(res.Chain) == 0 {
        return &Finding{Host: host, Verdict: NoDNS, Evidence: "no DNS answer", Resolver: res.Resolver}
    }

    if p != nil && p.OK {
        if bfp, sig := BodyFirstMatch(p.Status, p.Headers, p.Body); bfp != nil &&
            (fp == nil || fp.Service == bfp.Service) {
            v := Dangling
            if bfp.Vulnerable {
                v = Takeover
            }
            return &Finding{
                Host: host, Verdict: v, Service: bfp.Service, CNAME: cname,
                Chain: res.Chain, IPs: res.IPs, Status: p.Status,
                Evidence: fmt.Sprintf("body signature %q (HTTP %d)", truncate(sig.Body, 60), p.Status),
                Note:     bfp.Note, Resolver: res.Resolver,
            }
        }
    }

    if fp != nil {
        if p != nil && p.OK {
            if sig := fp.SignatureMatch(p.Status, p.Headers, p.Body); sig != nil {
                v := Dangling
                if fp.Vulnerable {
                    v = Takeover
                }
                return &Finding{
                    Host: host, Verdict: v, Service: fp.Service, CNAME: cname,
                    Chain: res.Chain, IPs: res.IPs, Status: p.Status,
                    Evidence: fmt.Sprintf("signature %q (HTTP %d)", truncate(sig.Body, 60), p.Status),
                    Note:     fp.Note, Resolver: res.Resolver,
                }
            }
            if containsInt(fp.DanglingStatus, p.Status) {
                v := Dangling
                if fp.Vulnerable {
                    v = Likely
                }
                return &Finding{
                    Host: host, Verdict: v, Service: fp.Service, CNAME: cname,
                    Chain: res.Chain, IPs: res.IPs, Status: p.Status,
                    Evidence: fmt.Sprintf("HTTP %d on %s without confirming signature", p.Status, fp.Service),
                    Note:     fp.Note + " - verify manually", Resolver: res.Resolver,
                }
            }
            return &Finding{
                Host: host, Verdict: Alive, Service: fp.Service, CNAME: cname,
                Chain: res.Chain, IPs: res.IPs, Status: p.Status,
                Evidence: fmt.Sprintf("served by %s (HTTP %d)", fp.Service, p.Status),
                Resolver: res.Resolver,
            }
        }
        if nxd {
            v := Dangling
            if fp.Vulnerable {
                v = Likely
            }
            return &Finding{
                Host: host, Verdict: v, Service: fp.Service, CNAME: cname, Chain: res.Chain,
                Evidence: fmt.Sprintf("CNAME to %s but target NXDOMAIN", fp.Service),
                Note:     fp.Note, Resolver: res.Resolver,
            }
        }
        if p == nil || !p.OK {
            v := Dangling
            if fp.Vulnerable {
                v = Likely
            }
            errMsg := "no probe"
            if p != nil {
                errMsg = truncate(p.Err, 80)
            }
            return &Finding{
                Host: host, Verdict: v, Service: fp.Service, CNAME: cname, Chain: res.Chain,
                Evidence: fmt.Sprintf("CNAME to %s but probe failed: %s", fp.Service, errMsg),
                Note:     fp.Note, Resolver: res.Resolver,
            }
        }
    }

    if p != nil && p.OK {
        return &Finding{
            Host: host, Verdict: Alive, CNAME: cname, Chain: res.Chain, IPs: res.IPs,
            Status: p.Status, Evidence: fmt.Sprintf("serving content (HTTP %d)", p.Status),
            Resolver: res.Resolver,
        }
    }
    if nxd || noAnswer {
        return &Finding{Host: host, Verdict: NoDNS, Evidence: "no DNS answer", Resolver: res.Resolver}
    }
    errMsg := "probe failed"
    if p != nil {
        errMsg = truncate(p.Err, 120)
    }
    return &Finding{Host: host, Verdict: Error, CNAME: cname, Chain: res.Chain,
        Evidence: errMsg, Resolver: res.Resolver}
}

func ScanHost(ctx context.Context, host string, res *Resolver, timeout time.Duration) (f *Finding) {
    defer func() {
        if r := recover(); r != nil {
            f = &Finding{Host: host, Verdict: Error, Evidence: fmt.Sprintf("internal: %v", r)}
        }
    }()
    dr := res.ResolveChain(ctx, host)
    var p *ProbeResult
    if len(dr.Chain) > 0 || len(dr.IPs) > 0 {
        p = Probe(ctx, host, timeout)
    }
    f = Classify(host, dr, p)
    if p != nil && p.OK {
        f.BodyHash = BodyHash(p.Body)
        f.Tech = detectTech(p.Headers, p.Body)
    }
    return f
}