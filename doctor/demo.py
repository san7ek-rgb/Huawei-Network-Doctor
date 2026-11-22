def snapshot(mobile=False):
    gateway = "172.20.10.1" if mobile else "192.168.3.1"
    return {
        "label": "Б · демонстрация" if mobile else "А · демонстрация",
        "time": "2026-01-01T12:00:00",
        "gateway": gateway,
        "windows": {"os": {"Caption": "Windows 11 (симуляция)", "BuildNumber": "26100"}},
        "gateway_ping": {"sent": 5, "replies": 5, "loss_pct": 0, "latency_ms": 2, "jitter_ms": 1},
        "internet_ping": {"sent": 5, "replies": 5, "loss_pct": 0, "latency_ms": 38, "jitter_ms": 5},
        "dns": ["192.0.2.24"],
        "mtu": {"ipv4_packet_sizes": {1228: 2, 1400: 2, 1500: 2 if mobile else 0}},
        "router": {} if mobile else {"vendor": "Huawei", "model_hint": "HG8245H", "http_status": 200},
        "tunnels": [],
        "endpoint": {"host": "vpn.example", "port": 443, "transport": "UDP", "dns": ["192.0.2.10"],
                     "status": "udp_requires_handshake"},
        "vpn_log": {"protocols": ["AmneziaWG"], "last_event": "connected" if mobile else "handshake"},
        "demo": True,
    }
