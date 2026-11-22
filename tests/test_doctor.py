import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from doctor import demo, diagnose, network, optimize, report, router, speed, vpn, windows


class DoctorTests(unittest.TestCase):
    def test_router_candidates(self):
        self.assertEqual(router.identify("<title>Huawei HG8245H</title>")["model_hint"], "HG8245H")
        self.assertEqual(router.identify("Huawei B535-232")["model_hint"], "B535-232")
        self.assertIsNone(router.identify("ISP station")["model_hint"])

    def test_comparison_and_export(self):
        home, mobile = demo.snapshot(), demo.snapshot(True)
        self.assertTrue(any("ошибка рукопожатия" in line for line in vpn.compare(home, mobile)))
        home["windows"]["wifi"] = ["00:11:22:33:44:55"]
        exported = json.dumps(report.anonymize(home))
        for private in (home["gateway"], home["endpoint"]["host"], "00:11:22:33:44:55"):
            self.assertNotIn(private, exported)

    def test_udp_does_not_attempt_tcp(self):
        with patch.object(network, "resolve", return_value=["192.0.2.10"]), patch.object(
            network.socket, "create_connection"
        ) as connect:
            self.assertEqual(network.endpoint_probe("vpn.example", 443, "UDP")["status"],
                             "udp_requires_handshake")
            connect.assert_not_called()

    def test_gateway_uses_physical_adapter(self):
        data = {"routes": [
            {"DestinationPrefix": "0.0.0.0/0", "NextHop": "10.0.0.1", "RouteMetric": 1, "InterfaceIndex": 2},
            {"DestinationPrefix": "0.0.0.0/0", "NextHop": "192.168.1.254", "RouteMetric": 10, "InterfaceIndex": 5},
        ], "adapters": [
            {"ifIndex": 2, "Name": "WireGuard", "InterfaceDescription": "Tunnel", "Status": "Up"},
            {"ifIndex": 5, "Name": "Wi-Fi", "InterfaceDescription": "Intel", "Status": "Up"},
        ]}
        self.assertEqual(windows.default_route(data)["InterfaceIndex"], 2)
        self.assertEqual(windows.local_gateway(data), "192.168.1.254")

    def test_log_reports_only_indicators(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vpn.log"
            path.write_text("AmneziaWG handshake timeout\nPrivateKey=secret\n", encoding="utf-8")
            result = vpn.log_summary(path)
            self.assertEqual(result["last_event"], "handshake")
            self.assertNotIn("secret", str(result))

    def test_collect_preserves_inventory_when_probe_times_out(self):
        data = {"os": {"Caption": "Windows"}, "unavailable": []}
        with patch.object(windows, "inventory", return_value=data), patch.object(
            network, "ping", side_effect=subprocess.TimeoutExpired("ping", 12)
        ), patch.object(network, "resolve", return_value=[]):
            snapshot = diagnose.collect("А")
        self.assertIsNone(snapshot["internet_ping"])
        self.assertIn("Внешний ICMP", snapshot["windows"]["unavailable"])
        self.assertEqual(snapshot["windows"]["os"]["Caption"], "Windows")

    def test_router_uses_supplied_gateway(self):
        with patch.object(router.http.client, "HTTPSConnection") as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 200
            response.read.return_value = b"<title>Huawei B535-232</title>"
            data = router.panel("192.168.67.254")
        connection.assert_called_once_with("192.168.67.254", timeout=2)
        self.assertEqual(data["url"], "https://192.168.67.254/")
        self.assertEqual(data["model_hint"], "B535-232")

    def test_speed_checks_download_and_uses_post(self):
        download = MagicMock()
        download.read1.side_effect = io.BytesIO(b"1234").read1
        upload = MagicMock(status=200)
        upload.read.return_value = b""
        client = MagicMock()
        client.open.return_value.__enter__.side_effect = [download, upload]
        with patch.object(speed, "build_opener", return_value=client), patch.multiple(
            speed, DOWNLOAD_BYTES=4, UPLOAD_BYTES=3
        ):
            result = speed.measure()
        self.assertGreater(result["download_mbps"], 0)
        request = client.open.call_args.args[0]
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.data, b"\0" * 3)

    def test_mtu_backup_and_restore(self):
        state = {"mtu": 1500, "adapter": "test-guid"}

        def write(index, mtu, expected):
            self.assertEqual(expected, state)
            state["mtu"] = mtu

        with tempfile.TemporaryDirectory() as directory, patch.object(
            optimize, "storage", return_value=Path(directory)
        ), patch.object(optimize, "_read", side_effect=lambda index: state.copy()), patch.object(
            optimize, "_write", side_effect=write
        ):
            optimize.apply(4, 1400)
            self.assertEqual(state["mtu"], 1400)
            self.assertTrue((Path(directory) / "mtu-backup.json").exists())
            optimize.restore()
            self.assertEqual(state["mtu"], 1500)
            self.assertFalse((Path(directory) / "mtu-backup.json").exists())


if __name__ == "__main__":
    unittest.main()
