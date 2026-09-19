package main

import (
    "net/http"
    "strings"
)

// detectTech: light tech fingerprinting from response headers + body.
// Deliberately conservative â€” only high-confidence markers.
func detectTech(h http.Header, body string) []string {
    var out []string
    add := func(s string) {
        s = strings.TrimSpace(s)
        if s == "" {
            return
        }
        for _, t := range out {
            if strings.EqualFold(t, s) {
                return
            }
        }
        out = append(out, s)
    }
    if v := h.Get("Server"); v != "" {
        add(v)
    }
    if v := h.Get("X-Powered-By"); v != "" {
        add(v)
    }
    if h.Get("Cf-Ray") != "" || h.Get("Cf-Cache-Status") != "" {
        add("Cloudflare")
    }
    if h.Get("X-Vercel-Id") != "" {
        add("Vercel")
    }
    if h.Get("X-Amz-Cf-Id") != "" || h.Get("X-Amz-Cf-Pop") != "" {
        add("CloudFront")
    }
    if h.Get("X-Shopify-Stage") != "" {
        add("Shopify")
    }
    if h.Get("X-Github-Request-Id") != "" {
        add("GitHub")
    }
    if v := h.Get("X-Served-By"); strings.Contains(strings.ToLower(v), "cache-") {
        add("Fastly")
    }
    if h.Get("X-Drupal-Cache") != "" {
        add("Drupal")
    }
    if v := h.Get("X-Generator"); v != "" {
        add(v)
    }
    low := strings.ToLower(body)
    if strings.Contains(low, "wp-content") || strings.Contains(low, "wp-json") {
        add("WordPress")
    }
    return out
}