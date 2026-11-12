FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PORT=7681 \
    HOME=/home/opsaegis

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       bash ca-certificates curl wget git gosu tini ttyd \
       python3 python3-venv python3-pip \
       nmap dnsutils whois netcat-openbsd jq tmux iproute2 procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash --uid 10001 opsaegis \
    && mkdir -p /workspace \
    && chown opsaegis:opsaegis /workspace /home/opsaegis

COPY start.sh /usr/local/bin/opsaegis-kali-start
RUN chmod 0755 /usr/local/bin/opsaegis-kali-start

WORKDIR /workspace
EXPOSE 7681
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/opsaegis-kali-start"]
