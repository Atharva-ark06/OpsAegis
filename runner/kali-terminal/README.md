# OpsAegis Kali Web Terminal

This service runs a browser-accessible Kali Rolling shell for authenticated OpsAegis team members.

## Runtime

- Base image: official `kalilinux/kali-rolling`
- Browser terminal: `ttyd`
- Internal listen port: `7681` (Railway `PORT`)
- Persistent workspace: `/workspace`
- Shell UID: unprivileged `opsaegis` user (UID 10001)
- Initial tools: Nmap, curl, wget, Git, Python 3, DNS utilities, whois, netcat, jq and tmux

## Railway deployment

Deploy this directory as a separate service in the existing OpsAegis production environment:

- Root directory: `/runner/kali-terminal`
- Dockerfile: `Dockerfile`
- Private networking endpoint: `kali-terminal`
- `PORT=7681`
- Attach a Railway volume at `/workspace`
- Do **not** generate a public domain or TCP proxy for this service.

The frontend Nginx service proxies `/terminal/` to `http://kali-terminal.railway.internal:7681/` only after an API authorization subrequest succeeds.

## Access control

The terminal container has no independent public login. It is reachable only through the frontend's authenticated reverse proxy. The API mints a five-minute, HttpOnly, Secure-in-production, SameSite=Strict cookie after checking the current OpsAegis user record. Each terminal request is authorized again by the API. Only active administrators and analysts are permitted; viewers are denied.

The terminal runs as a non-root Linux user. The team shares the same container and persistent `/workspace` directory; shell sessions are separate, but files are not per-user isolated. Do not store personal credentials, private keys or unrelated sensitive material in this shared workspace.

## Safe-use boundary

Use the terminal only for administration, training, CTFs and security testing of systems for which the team has explicit authorization. This workspace is a general-purpose shell, not a target scanner approval workflow. Do not use it to bypass OpsAegis target-registration, Nuclei or Shannon authorization controls.
