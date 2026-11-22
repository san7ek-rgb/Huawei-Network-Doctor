"""Bounded checks against the active gateway and explicit endpoint."""
import ipaddress
import platform
import re
import socket
import statistics
import subprocess

PUBLIC_PROBE = "1.1.1.1"
DNS_PROBE = "example.com"


def ping(address, count=5, payload=None):
    address = str(ipaddress.IPv4Address(address))
    if platform.system() != "Windows":
        raise RuntimeError("Измерение ICMP использует Windows ping.")
    args = ["ping.exe", "-4", "-n", str(count), "-w", "800"]
    if payload is not None:
        args += ["-f", "-l", str(payload)]
    result = subprocess.run(
        args + [address], capture_output=True, timeout=12,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    # Parse only echo-reply rows. The duration unit depends on Windows locale.
    rows = [line for line in result.stdout.splitlines() if re.search(rb"\bTTL\s*=\s*\d+", line, re.I)]
    samples = []
    for row in rows:
        match = re.search(rb"([=<])\s*(\d+)\s*[^0-9\s]+\s+TTL\b", row, re.I)
        if match:
            sign, value = match.groups()
            samples.append(float(value) if sign == b"=" else 0.5)
    replies = len(rows)
    return {
        "sent": count, "replies": replies, "loss_pct": (count - replies) * 100 / count,
        "latency_ms": statistics.mean(samples) if samples else None,
        "jitter_ms": statistics.mean(abs(b - a) for a, b in zip(samples, samples[1:])) if len(samples) > 1 else None,
    }


def mtu_probe(address):
    payloads = (1200, 1372, 1472)
    replies = {payload + 28: ping(address, 2, payload)["replies"] for payload in payloads}
    return {"ipv4_packet_sizes": replies, "target": address}


def resolve(host):
    try:
        return sorted({entry[4][0] for entry in socket.getaddrinfo(host, None)})
    except OSError:
        return []


def endpoint_probe(host, port, transport):
    host = host.strip()
    if not host or not 1 <= port <= 65535 or transport not in {"TCP", "UDP"}:
        raise ValueError("Укажите имя/IP, порт от 1 до 65535 и транспорт.")
    addresses = resolve(host)
    result = {"host": host, "port": port, "transport": transport, "dns": addresses}
    if not addresses:
        result["status"] = "dns_error"
    elif transport == "UDP":
        result["status"] = "udp_requires_handshake"
    else:
        result["status"] = "tcp_failed"
        for address in addresses[:3]:
            try:
                with socket.create_connection((address, port), timeout=2):
                    result["status"] = "tcp_connected"
                break
            except OSError:
                continue
    return result
