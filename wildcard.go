package main

import (
    "context"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "strings"
    "time"
)

var multilabelSuffixes = map[string]bool{
    "co.uk": true, "org.uk": true, "gov.uk": true, "ac.uk": true, "me.uk": true,
    "com.au": true, "net.au": true, "org.au": true,
    "co.nz": true, "net.nz": true, "org.nz": true,
    "com.br": true, "com.mx": true, "com.ar": true, "com.co": true,
    "co.jp": true, "co.in": true, "co.za": true, "co.kr": true,
    "com.sg": true, "com.my": true, "com.hk": true, "com.tr": true,
    "com.cn": true, "com.tw": true, "com.ph": true, "com.vn": true,
}

func ParentOf(host string) string {
    host = strings.TrimRight(strings.ToLower(host), ".")
    labels := strings.Split(host, ".")
    if len(labels) <= 2 {
        return host
    }
    last2 := strings.Join(labels[len(labels)-2:], ".")
    if multilabelSuffixes[last2] && len(labels) >= 3 {
        return strings.Join(labels[len(labels)-3:], ".")
    }
    return last2
}

func BodyHash(body string) string {
    if body == "" {
        return ""
    }
    sum := sha256.Sum256([]byte(body))
    return hex.EncodeToString(sum[:])[:16]
}

func randNonce(n int) string {
    const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    b := make([]byte, n)
    rand.Read(b)
    for i := range b {
        b[i] = chars[int(b[i])%len(chars)]
    }
    return string(b)
}

type Canary struct {
    Parent   string
    Nonce    string
    Resolves bool
    Hash     string
    Status   int
}

type WildcardRegistry struct {
    resolver *Resolver
    minGroup int
    nonceLen int
    disabled bool
    Canaries map[string]*Canary
}

func NewWildcardRegistry(res *Resolver, disabled bool) *WildcardRegistry {
    return &WildcardRegistry{
        resolver: res, minGroup: 3, nonceLen: 14, disabled: disabled,
        Canaries: map[string]*Canary{},
    }
}

func (w *WildcardRegistry) Build(ctx context.Context, hosts []string, timeout time.Duration) {
    if w.disabled {
        return
    }
    groups := map[string][]string{}
    for _, h := range hosts {
        p := ParentOf(h)
        groups[p] = append(groups[p], h)
    }
    for parent, members := range groups {
        if len(members) < w.minGroup {
            continue
        }
        nonce := randNonce(w.nonceLen)
        nonceHost := nonce + "." + parent
        res := w.resolver.ResolveChain(ctx, nonceHost)
        if len(res.Chain) > 0 || len(res.IPs) > 0 {
            c := &Canary{Parent: parent, Nonce: nonce, Resolves: true}
            if p := Probe(ctx, nonceHost, timeout); p != nil && p.OK {
                c.Hash = BodyHash(p.Body)
                c.Status = p.Status
            }
            w.Canaries[parent] = c
        } else {
            w.Canaries[parent] = &Canary{Parent: parent, Nonce: nonce}
        }
    }
}

func (w *WildcardRegistry) isWildcarded(host string) bool {
    c, ok := w.Canaries[ParentOf(host)]
    return ok && c.Resolves
}

func (w *WildcardRegistry) ActiveCanaries() int {
    n := 0
    for _, c := range w.Canaries {
        if c.Resolves {
            n++
        }
    }
    return n
}

func (w *WildcardRegistry) Apply(findings []*Finding) int {
    downgraded := 0
    for _, f := range findings {
        if !w.isWildcarded(f.Host) {
            continue
        }
        c := w.Canaries[ParentOf(f.Host)]
        switch f.Verdict {
        case NoDNS:
            f.Verdict = Wildcard
            f.Evidence = fmt.Sprintf("wildcard zone: %s.%s resolves", c.Nonce, c.Parent)
            downgraded++
        case Likely:
            f.Evidence += " | wildcard zone active - verify against canary"
        case Alive, Error:
            if c.Hash != "" && f.BodyHash != "" && f.BodyHash == c.Hash {
                f.Verdict = Wildcard
                f.Evidence = "body identical to wildcard canary " + f.Evidence
                downgraded++
            }
        }
    }
    return downgraded
}