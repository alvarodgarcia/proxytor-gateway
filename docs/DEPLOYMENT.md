# Deployment Guide

ProxyTor Gateway is designed for Debian 12.

## Basic deployment

```bash
sudo bash scripts/install.sh
Default ports
9050/tcp - Tor SOCKS
9051/tcp - Tor ControlPort, localhost only
8118/tcp - Privoxy HTTP proxy
8088/tcp - ProxyTor dashboard/API

Do not expose these ports directly to the Internet.
