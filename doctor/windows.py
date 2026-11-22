"""Read-only Windows inventory. Structured fields use PowerShell objects."""
import json
import platform
import re
import subprocess

INVENTORY = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$warnings = [Collections.Generic.List[string]]::new()
function Read-Section($name, [scriptblock]$action) {
    try { & $action } catch { $warnings.Add($name) }
}
$os = Read-Section 'Windows' { Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber }
$adapters = @(Read-Section 'Адаптеры' { Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceDescription,ifIndex,@{n='Status';e={[string]$_.Status}},DriverVersion,LinkSpeed })
$ips = @(Read-Section 'IP' { Get-NetIPAddress | Select-Object InterfaceIndex,IPAddress,PrefixLength,AddressFamily })
$interfaces = @(Read-Section 'DHCP и MTU' { Get-NetIPInterface | Select-Object InterfaceIndex,InterfaceAlias,AddressFamily,Dhcp,NlMtu,InterfaceMetric,ConnectionState })
$routes = @(Read-Section 'Маршруты' { Get-NetRoute -PolicyStore ActiveStore | Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric,InterfaceMetric })
$dns = @(Read-Section 'DNS' { Get-DnsClientServerAddress | Select-Object InterfaceIndex,AddressFamily,ServerAddresses })
$wifi = @(Read-Section 'Wi-Fi' {
    $output = netsh wlan show interfaces
    if ($LASTEXITCODE -ne 0) { throw 'WLAN query failed' }
    $output
})
$channels = @(Read-Section 'Каналы Wi-Fi' {
    $output = netsh wlan show networks mode=bssid
    if ($LASTEXITCODE -ne 0) { throw 'WLAN query failed' }
    $output
})
$proxy = Read-Section 'Прокси' {
    $p = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    @{manual=($p.ProxyEnable -eq 1); pac=[bool]$p.AutoConfigURL; winhttp=@(netsh winhttp show proxy)}
}
$clients = @(Read-Section 'Установленные приложения' {
    $paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
             'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
             'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    Get-ItemProperty $paths -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match 'Amnezia|\bINCY\b|WireGuard|OpenVPN' } |
        Select-Object DisplayName,DisplayVersion
})
@{os=$os; adapters=$adapters; ips=$ips; interfaces=$interfaces; routes=$routes;
  dns=$dns; wifi=$wifi; channels=$channels; proxy=$proxy; clients=$clients;
  unavailable=@($warnings.ToArray())} | ConvertTo-Json -Depth 6 -Compress
"""


def powershell(script, timeout=45):
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, check=True, timeout=timeout, encoding="utf-8",
        errors="replace", creationflags=subprocess.CREATE_NO_WINDOW,
    ).stdout.lstrip("\ufeff")


def inventory():
    if platform.system() != "Windows":
        raise RuntimeError("Диагностика доступна на Windows. Для просмотра используйте демонстрацию.")
    data = json.loads(powershell(INVENTORY))
    if not data.get("os"):
        data["os"] = {"Caption": platform.platform()}
    return data


def default_route(data):
    routes = [
        row for row in data.get("routes", [])
        if row["DestinationPrefix"] == "0.0.0.0/0"
    ]
    return min(routes, key=lambda row: row["RouteMetric"] + (row.get("InterfaceMetric") or 0), default={})


def local_gateway(data):
    interfaces = {
        row["ifIndex"]: row for row in data.get("adapters", [])
        if str(row.get("Status", "")).lower() == "up"
        and not TUNNEL.search(row["Name"] + " " + row["InterfaceDescription"])
    }
    routes = [row for row in data.get("routes", []) if row["InterfaceIndex"] in interfaces
              and row["NextHop"] != "0.0.0.0"]
    return default_route({"routes": routes}).get("NextHop")


TUNNEL = re.compile(r"amnezia|\bincy\b|wireguard|wintun|openvpn|tap-windows|vpn|tunnel", re.I)
