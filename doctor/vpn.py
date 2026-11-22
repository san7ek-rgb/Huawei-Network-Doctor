"""Local client evidence and A/B assessment."""
import re
from pathlib import Path

from doctor.windows import TUNNEL

LOG_EVENTS = {
    "dns": r"could not resolve|name resolution|resolve host|no such host",
    "route": r"no route to host|network is unreachable|route addition failed",
    "tcp": r"connection refused|tcp connect.*failed",
    "handshake": r"handshake.*(?:timeout|failed|did not complete)|tls key negotiation failed",
    "connected": r"initialization sequence completed|handshake.*(?:completed|succeeded)",
}
STATUS = {
    "dns_error": "Имя сервера не разрешилось",
    "udp_requires_handshake": "Для UDP нужен результат рукопожатия из журнала VPN",
    "tcp_failed": "Не удалось установить TCP-соединение",
    "tcp_connected": "TCP-соединение установлено",
}


def log_summary(path):
    with Path(path).open("rb") as stream:
        stream.seek(max(0, stream.seek(0, 2) - 512 * 1024))
        raw = stream.read()
    codec = "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
    lines = raw.decode(codec, errors="replace").splitlines()
    events = [event for line in lines for event, pattern in LOG_EVENTS.items()
              if re.search(pattern, line, re.I)]
    protocols = [name for name in ("AmneziaWG", "WireGuard", "OpenVPN", "IKEv2", "XRay")
                 if any(re.search(rf"\b{name}\b", line, re.I) for line in lines)]
    return {
        "events": {event: events.count(event) for event in LOG_EVENTS if event in events},
        "last_event": events[-1] if events else None,
        "protocols": protocols,
    }


def adapter_evidence(data):
    return [adapter for adapter in data.get("adapters", [])
            if TUNNEL.search(adapter["Name"] + " " + adapter["InterfaceDescription"])]


def compare(home, mobile):
    findings = []
    a, b = home.get("endpoint"), mobile.get("endpoint")
    if a and b and all(a[key] == b[key] for key in ("host", "port", "transport")):
        findings.append(f"Дом: {STATUS[a['status']]}. Мобильная сеть: {STATUS[b['status']]}.")
        if a["dns"] != b["dns"]:
            findings.append("DNS-ответы различаются. Проверьте, одинаков ли выбранный адрес сервера.")
        if a["status"] == "tcp_failed" and b["status"] == "tcp_connected":
            findings.append("Разница подтверждена на этапе TCP. Проверьте маршруты, фильтрацию и доступность сервера по этому адресу.")
    else:
        findings.append("Для сравнения транспорта задайте одинаковые имя/IP, порт и транспорт в тестах А и Б.")
    av, bv = home.get("vpn_log", {}), mobile.get("vpn_log", {})
    if av.get("last_event") == "handshake" and bv.get("last_event") == "connected":
        findings.append("В журнале А видна ошибка рукопожатия, в Б — успешное подключение. Сверьте время попыток и профиль VPN.")
    for key, name in (("gateway_ping", "Шлюз"), ("internet_ping", "Внешний узел")):
        first, second = home.get(key), mobile.get(key)
        if first and second:
            findings.append(f"{name}: потери в А {first['loss_pct']:g}%, в Б {second['loss_pct']:g}%.")
    if bool(home.get("dns")) != bool(mobile.get("dns")):
        findings.append("Тестовое DNS-имя разрешилось только в одной сети.")
    def passed_sizes(snapshot):
        return {int(size) for size, replies in
                snapshot.get("mtu", {}).get("ipv4_packet_sizes", {}).items() if replies == 2}

    home_sizes, mobile_sizes = passed_sizes(home), passed_sizes(mobile)
    if home_sizes and mobile_sizes and home_sizes != mobile_sizes:
        findings.append(f"IPv4 до контрольного узла: наибольший прошедший размер в А — "
                        f"{max(home_sizes)}, в Б — {max(mobile_sizes)} байт. "
                        "Сравните путь к самому VPN-серверу.")
    for label, snap in (("А", home), ("Б", mobile)):
        active = [row for row in snap.get("tunnels", []) if str(row["Status"]).lower() == "up"]
        if len(active) > 1:
            findings.append(f"В тесте {label} активны несколько туннелей. Сравните их маршруты IPv4 и IPv6.")
    if home.get("gateway") == mobile.get("gateway") and home.get("gateway"):
        findings.append("Адреса шлюзов совпадают. Убедитесь, что между тестами вы сменили подключение.")
    return findings
