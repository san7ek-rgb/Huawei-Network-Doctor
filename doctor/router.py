"""Discover a gateway panel using only the active IPv4 gateway."""
import http.client
import ipaddress
import re
import ssl

MODEL = re.compile(r"\b(?:HG|EG|HS|B|H|AX|WS)[- ]?\d{2,5}[A-Z0-9-]*\b", re.I)


def identify(body):
    # Candidate model strings are hints, never a source of management capability.
    if not re.search(r"huawei|华为", body, re.I):
        return {"vendor": None, "model_hint": None}
    model = MODEL.search(body)
    return {"vendor": "Huawei", "model_hint": model.group(0) if model else None}


def panel(gateway):
    address = ipaddress.IPv4Address(gateway)
    if not (address.is_private or address in ipaddress.IPv4Network("100.64.0.0/10")):
        return {"attempts": ["Проверяется только локальный адрес шлюза."]}
    attempts = []
    for https in (True, False):
        scheme = "https" if https else "http"
        url = f"{scheme}://{address}/"
        factory = http.client.HTTPSConnection if https else http.client.HTTPConnection
        connection = factory(str(address), timeout=2)
        try:
            connection.request("GET", "/", headers={"Connection": "close"})
            response = connection.getresponse()
            body = response.read(32768).decode("utf-8", errors="replace")
            return {"url": url, "http_status": response.status, "attempts": attempts, **identify(body)}
        except ssl.SSLCertVerificationError:
            return {"url": url, "attempts": ["HTTPS доступен, сертификат не прошёл проверку."]}
        except (OSError, http.client.HTTPException):
            attempts.append(f"{scheme.upper()}: ответа нет.")
        finally:
            connection.close()
    return {"attempts": attempts}
