"""Explicit, reversible IPv4 MTU trials in Windows ActiveStore."""
import json

from doctor.report import storage
from doctor.windows import powershell


def recommendations(snapshot):
    results = [
        "Wi-Fi: сравните уровень сигнала рядом с роутером и на рабочем месте. "
        "Если рядом устойчивее 5 ГГц, сравните задержку и потери. Откат — вернуться к прежней сети.",
        "Канал: если соседние сети занимают тот же канал, сравните другой разрешённый канал. "
        "Возможен краткий разрыв Wi-Fi. Сохраните прежний канал для отката.",
        "Драйвер и прошивка: сверьте модель и версии с сайтом производителя. "
        "Обновление может прервать связь. Заранее проверьте резервную копию и процедуру восстановления.",
    ]
    if not snapshot.get("dns") and (snapshot.get("internet_ping") or {}).get("replies"):
        results.append("DNS: ICMP работает, тестовое имя не разрешилось. Сверьте DNS на обоих подключениях. "
                       "Смена DNS может нарушить локальные имена. Запишите прежние адреса или режим DHCP.")
    trials = {int(size): replies for size, replies in
              snapshot.get("mtu", {}).get("ipv4_packet_sizes", {}).items()}
    if trials.get(1400) == 2 and trials.get(1500) == 0:
        results.append("MTU: на проверенном пути пакеты 1400 байт проходили, а 1500 — нет. "
                       "Проверьте, воспроизводится ли это для VPN-сервера. "
                       "Пробный MTU может снизить пропускную способность. Доступен откат.")
    if len(snapshot.get("tunnels", [])) > 1:
        results.append("VPN: проверьте активность туннелей и метрики маршрутов. "
                       "Отключение туннеля может прервать работу приложений. Откат — подключить его снова.")
    return results


def _read(interface):
    script = (
        "$ErrorActionPreference='Stop'; "
        f"$i = Get-NetIPInterface -InterfaceIndex {int(interface)} -AddressFamily IPv4 -PolicyStore ActiveStore; "
        "$a = Get-NetAdapter -IncludeHidden | Where-Object ifIndex -eq $i.InterfaceIndex; "
        "if (-not $a.InterfaceGuid) { throw 'Adapter not found' }; "
        "@{mtu=$i.NlMtu; adapter=[string]$a.InterfaceGuid} | ConvertTo-Json -Compress"
    )
    return json.loads(powershell(script))


def _write(interface, mtu, expected):
    if not 576 <= mtu <= 9000 or int(interface) < 1:
        raise ValueError("Недопустимое значение MTU или индекса интерфейса.")
    if _read(interface) != expected:
        raise RuntimeError("Интерфейс или MTU изменились. Операция отменена.")
    powershell("$ErrorActionPreference='Stop'; "
               f"Set-NetIPInterface -InterfaceIndex {int(interface)} -AddressFamily IPv4 "
               f"-PolicyStore ActiveStore -NlMtuBytes {int(mtu)}")
    if _read(interface) != {**expected, "mtu": mtu}:
        raise RuntimeError("Не удалось подтвердить изменение MTU.")


def apply(interface, mtu):
    path = storage() / "mtu-backup.json"
    if path.exists():
        raise RuntimeError("Сначала восстановите исходный MTU из существующей копии.")
    before = _read(interface)
    if not 576 <= mtu < before["mtu"] <= 9000:
        raise ValueError("Пробный MTU должен быть меньше текущего и составлять не менее 576 байт.")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as backup:
        json.dump({"index": interface, "before": before, "trial": mtu}, backup)
    _write(interface, mtu, before)


def restore():
    path = storage() / "mtu-backup.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    interface, before = record["index"], record["before"]
    if _read(interface) != before:
        _write(interface, before["mtu"], {**before, "mtu": record["trial"]})
    path.unlink()
