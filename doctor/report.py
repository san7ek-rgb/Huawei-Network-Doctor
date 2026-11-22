"""Local history and an allowlisted export that excludes raw inventory."""
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile


def storage():
    return Path(os.getenv("LOCALAPPDATA") or Path.home() / ".local" / "share") / "HuaweiNetworkDoctor"


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with NamedTemporaryFile(mode="w", dir=path.parent, encoding="utf-8", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(data, stream, ensure_ascii=False, indent=2)
        temporary.replace(path)
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def anonymize(snapshot, include_addresses=False):
    endpoint = snapshot.get("endpoint") or {}
    panel = snapshot.get("router") or {}
    result = {key: snapshot.get(key) for key in ("label", "time", "gateway_ping", "internet_ping", "speed")}
    result.update({
        "windows_build": (snapshot.get("windows", {}).get("os") or {}).get("BuildNumber"),
        "dns_ok": bool(snapshot.get("dns")),
        "mtu_trials": (snapshot.get("mtu") or {}).get("ipv4_packet_sizes"),
        "router": {key: panel.get(key) for key in ("vendor", "model_hint", "http_status")},
        "vpn": {key: endpoint.get(key) for key in ("status", "transport")},
        "vpn_log": snapshot.get("vpn_log", {}),
        "tunnel_count": len(snapshot.get("tunnels", [])),
        "unavailable": snapshot.get("windows", {}).get("unavailable", []),
    })
    if include_addresses:
        result["gateway"] = snapshot.get("gateway")
        result["vpn"].update({key: endpoint.get(key) for key in ("host", "port", "dns")})
    return result
