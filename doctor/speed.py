"""Measure application throughput to Cloudflare over verified HTTPS."""
import time
from urllib.request import ProxyHandler, Request, build_opener

BASE = "https://speed.cloudflare.com"
DOWNLOAD_BYTES = 10_000_000
UPLOAD_BYTES = 2_000_000
LIMIT_SECONDS = 35


def measure():
    client = build_opener(ProxyHandler({}))
    started = time.monotonic()
    received = 0
    with client.open(f"{BASE}/__down?bytes={DOWNLOAD_BYTES}", timeout=8) as reply:
        while received < DOWNLOAD_BYTES:
            if time.monotonic() - started > LIMIT_SECONDS:
                raise TimeoutError("Истекло время скачивания.")
            block = reply.read1(min(65536, DOWNLOAD_BYTES - received))
            if not block:
                break
            received += len(block)
    if received != DOWNLOAD_BYTES:
        raise RuntimeError("Сервис вернул неполный объём данных.")
    download = 8 * received / (time.monotonic() - started) / 1e6
    started = time.monotonic()
    request = Request(
        f"{BASE}/__up", data=b"\0" * UPLOAD_BYTES,
        headers={"Content-Type": "application/octet-stream"}, method="POST",
    )
    with client.open(request, timeout=10) as reply:
        if reply.status != 200:
            raise RuntimeError(f"Измерение отдачи: HTTP {reply.status}.")
        if len(reply.read(1025)) > 1024:
            raise RuntimeError("Неожиданный ответ измерительного сервиса.")
    return {
        "download_mbps": round(download, 2),
        "upload_mbps": round(8 * UPLOAD_BYTES / (time.monotonic() - started) / 1e6, 2),
        "service": "Cloudflare",
    }
