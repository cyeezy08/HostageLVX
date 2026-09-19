package main

import (
    "context"
    "crypto/tls"
    "io"
    "net"
    "net/http"
    "time"
)

const (
    maxBody   = 64 * 1024
    userAgent = "hostage/0.3 (subdomain takeover scanner; single-request probe)"
)

type ProbeResult struct {
    OK       bool
    Status   int
    Headers  http.Header
    Body     string
    FinalURL string
    Scheme   string
    Err      string
    Elapsed  time.Duration
}

var probeClient = &http.Client{
    Transport: &http.Transport{
        Proxy: http.ProxyFromEnvironment,
        DialContext: (&net.Dialer{
            Timeout:   8 * time.Second,
            KeepAlive: 30 * time.Second,
        }).DialContext,
        TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
        MaxIdleConns:          200,
        MaxIdleConnsPerHost:   8,
        IdleConnTimeout:       60 * time.Second,
        TLSHandshakeTimeout:   8 * time.Second,
        ResponseHeaderTimeout: 8 * time.Second,
    },
    CheckRedirect: func(req *http.Request, via []*http.Request) error {
        if len(via) >= 10 {
            return http.ErrUseLastResponse
        }
        return nil
    },
}

func Probe(ctx context.Context, host string, timeout time.Duration) *ProbeResult {
    started := time.Now()
    res := &ProbeResult{}
    for _, scheme := range []string{"https", "http"} {
        ctxReq, cancel := context.WithTimeout(ctx, timeout)
        req, err := http.NewRequestWithContext(ctxReq, http.MethodGet, scheme+"://"+host, nil)
        if err != nil {
            cancel()
            res.Err = err.Error()
            continue
        }
        req.Header.Set("User-Agent", userAgent)
        req.Header.Set("Accept", "*/*")

        resp, err := probeClient.Do(req)
        cancel()
        if err != nil {
            res.Err = err.Error()
            continue
        }
        body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
        resp.Body.Close()

        res.OK = true
        res.Status = resp.StatusCode
        res.Headers = resp.Header
        res.Body = string(body)
        res.FinalURL = resp.Request.URL.String()
        res.Scheme = scheme
        res.Elapsed = time.Since(started)
        return res
    }
    res.Elapsed = time.Since(started)
    return res
}