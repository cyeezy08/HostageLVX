# .devcontainer/Dockerfile
# Codespace base image — Go 1.22 + DNS/recon tooling for testing hostage.
FROM mcr.microsoft.com/devcontainers/go:1.22

# DNS / HTTP / pipe utilities useful when iterating on a takeover scanner
RUN apt-get update && apt-get install -y --no-install-recommends \
        dnsutils \
        httpie \
        jq \
        bind9-host \
        ca-certificates \
        curl \
        unzip \
        git \
    && rm -rf /var/lib/apt/lists/*

# Install ProjectDiscovery toolset (subfinder, httpx) for fixture generation
# so contributors can spin up real subdomain lists against their own scope
# without leaving the codespace.
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest

WORKDIR /workspace
