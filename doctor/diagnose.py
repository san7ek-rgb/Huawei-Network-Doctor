import subprocess
import time
from datetime import datetime

from doctor import network, router, vpn, windows


def collect(label, endpoint=None, log_path=None):
    data = windows.inventory()
    gateway = windows.local_gateway(data)

    def check(name, action, fallback=None):
        try:
            return action()
        except (OSError, ValueError, subprocess.SubprocessError):
            data.setdefault("unavailable", []).append(name)
            return fallback

    return {
        "label": label,
        "time": datetime.now().isoformat(timespec="seconds"),
        "windows": data,
        "gateway": gateway,
        "default_route": windows.default_route(data),
        "gateway_ping": check("ICMP шлюза", lambda: network.ping(gateway)) if gateway else None,
        "internet_ping": check("Внешний ICMP", lambda: network.ping(network.PUBLIC_PROBE)),
        "dns": network.resolve(network.DNS_PROBE),
        "mtu": check("MTU", lambda: network.mtu_probe(network.PUBLIC_PROBE), {}),
        "router": check("Панель шлюза", lambda: router.panel(gateway), {}) if gateway else {},
        "tunnels": vpn.adapter_evidence(data),
        "endpoint": check("VPN-сервер", lambda: network.endpoint_probe(*endpoint)) if endpoint else None,
        "vpn_log": check("Журнал VPN", lambda: vpn.log_summary(log_path), {}) if log_path else {},
    }


def wifi_series():
    readings = []
    for index in range(3):
        if index:
            time.sleep(2)
        output = windows.powershell(
            "[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); netsh wlan show interfaces; "
            "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
            timeout=12,
        )
        readings.append(output.splitlines())
    return readings
