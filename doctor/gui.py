"""Russian desktop UI for live checks and clearly marked offline examples."""
import ctypes
import json
import platform
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from PySide6.QtCore import QThread, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox, QFileDialog, QFormLayout, QLabel, QLineEdit, QComboBox,
    QMainWindow, QMessageBox, QPlainTextEdit, QPushButton, QSpinBox,
    QTabWidget, QVBoxLayout, QWidget,
)

from doctor import demo, diagnose, optimize, report, speed, vpn, windows


class Job(QThread):
    result = Signal(object)
    error = Signal(str)

    def __init__(self, operation, parent):
        super().__init__(parent)
        self.operation = operation

    def run(self):
        try:
            self.result.emit(self.operation())
        except Exception as error:
            self.error.emit(str(error))


def pretty(data):
    return json.dumps(data, ensure_ascii=False, indent=2)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.live = platform.system() == "Windows"
        self.samples = {}
        self.current = None
        self.job = None
        self.log_path = None
        self.speed_runs = []
        self.setWindowTitle("Huawei Network Doctor")
        self.resize(940, 720)
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        main = self.page("Главная", "Снимок Windows и сети")
        self.button(main, "Проверить текущее подключение", lambda: self.scan("Текущее"), self.live)
        self.button(main, "Загрузить демонстрацию А и Б", self.show_demo)
        self.overview = self.output(main)
        self.overview.setPlainText(
            "Проверяются настройки Windows, шлюз, DNS example.com и ICMP до 1.1.1.1. "
            "По умолчанию настройки не меняются."
            if self.live else "Облачная среда Linux. Доступна демонстрация на симулированных данных."
        )

        panel = self.page("Роутер Huawei", "Веб-панель текущего шлюза")
        self.button(panel, "Открыть в браузере", self.open_panel)
        self.router_info = self.output(panel)
        self.router_info.setPlainText(self.router_guide())

        wizard = self.page("Диагностика VPN", "Сравнение домашнего Wi-Fi и мобильной точки доступа")
        self.explain(wizard, "Подключитесь к домашнему Wi-Fi, повторите попытку VPN и запустите тест А. "
                     "Затем переключитесь на мобильную точку, повторите попытку с тем же профилем и запустите тест Б.")
        form = QFormLayout()
        self.host = QLineEdit()
        self.host.setPlaceholderText("Необязательно")
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(443)
        self.transport = QComboBox()
        self.transport.addItems(["UDP", "TCP"])
        form.addRow("Имя или IP вашего VPN-сервера", self.host)
        form.addRow("Порт", self.port)
        form.addRow("Транспорт", self.transport)
        wizard.addLayout(form)
        self.probe_allowed = QCheckBox("Разрешаю DNS-запрос и, для TCP, подключение к указанному серверу")
        wizard.addWidget(self.probe_allowed)
        self.log_label = QLabel("Журнал не выбран")
        self.button(wizard, "Выбрать журнал последней попытки", self.choose_log, self.live)
        wizard.addWidget(self.log_label)
        self.button(wizard, "Тест А · домашний Wi-Fi", lambda: self.scan("А · домашний Wi-Fi", "home"), self.live)
        self.button(wizard, "Тест Б · мобильная точка", lambda: self.scan("Б · мобильная точка", "mobile"), self.live)
        self.vpn_info = self.output(wizard)

        throughput = self.page("Скорость интернета", "Пропускная способность и качество сигнала")
        self.explain(throughput, "Cloudflare HTTPS: скачивание 10 МБ, отправка 2 МБ. "
                     "Задержка, джиттер и потери берутся из сетевого снимка. "
                     "Скорости приёма и передачи Wi-Fi показывают параметры радиолинии.")
        self.speed_stage = QComboBox()
        self.speed_stage.addItems(["До изменения", "После изменения"])
        throughput.addWidget(self.speed_stage)
        self.button(throughput, "Измерить через Cloudflare", self.run_speed, self.live)
        self.button(throughput, "Снять ряд измерений Wi-Fi", self.run_wifi, self.live)
        self.speed_info = self.output(throughput)

        problems = self.page("Найденные проблемы", "Результаты и гипотезы")
        self.problems = self.output(problems)
        tuning = self.page("Оптимизация", "Рекомендации и пробный MTU IPv4")
        self.advice = self.output(tuning)
        self.explain(tuning, "Для пробного MTU нужен запуск от администратора. "
                     "Изменение действует в текущем сеансе Windows и может прервать связь.")
        controls = QFormLayout()
        self.interface = QSpinBox()
        self.interface.setRange(1, 2_147_483_647)
        self.mtu = QSpinBox()
        self.mtu.setRange(576, 9000)
        self.mtu.setValue(1400)
        controls.addRow("Индекс адаптера из снимка Windows", self.interface)
        controls.addRow("Подтверждённый размер MTU", self.mtu)
        tuning.addLayout(controls)
        self.button(tuning, "Сохранить копию и применить", self.apply_mtu, self.live)
        self.button(tuning, "Восстановить исходный MTU", self.restore_mtu, self.live)

        archive = self.page("История проверок", "Локальная история")
        self.history = QComboBox()
        archive.addWidget(self.history)
        self.button(archive, "Открыть выбранный снимок", self.load_history)
        self.explain(archive, "История содержит сетевые настройки и хранится в профиле пользователя. "
                     "В экспорт попадают только выбранные поля.")
        archive.addStretch()

        export = self.page("Отчёт", "Предпросмотр JSON")
        self.addresses = QCheckBox("Включить адрес шлюза и сведения о VPN-сервере")
        self.addresses.toggled.connect(self.render_report)
        export.addWidget(self.addresses)
        self.pair_report = QCheckBox("Экспортировать пару А и Б, если оба снимка доступны")
        self.pair_report.setChecked(True)
        self.pair_report.toggled.connect(self.render_report)
        export.addWidget(self.pair_report)
        self.button(export, "Сохранить отчёт", self.export)
        self.report_preview = self.output(export)
        self.refresh_history()
        self.statusBar().showMessage("Готово к проверке")

    def page(self, title, heading):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(26, 22, 26, 22)
        lead = QLabel(heading)
        lead.setObjectName("heading")
        layout.addWidget(lead)
        self.tabs.addTab(widget, title)
        return layout

    @staticmethod
    def explain(layout, message):
        label = QLabel(message)
        label.setWordWrap(True)
        layout.addWidget(label)

    @staticmethod
    def button(layout, title, callback, enabled=True):
        button = QPushButton(title)
        button.clicked.connect(callback)
        button.setEnabled(enabled)
        layout.addWidget(button, 0, Qt.AlignmentFlag.AlignLeft)
        return button

    @staticmethod
    def output(layout):
        output = QPlainTextEdit()
        output.setReadOnly(True)
        layout.addWidget(output, 1)
        return output

    def start(self, title, operation, completed):
        if self.job is not None:
            return
        self.tabs.setEnabled(False)
        self.statusBar().showMessage(title)
        self.job = Job(operation, self)
        self.job.result.connect(completed)
        self.job.error.connect(lambda message: QMessageBox.warning(self, "Проверка остановлена", message))
        self.job.finished.connect(self.finish)
        self.job.start()

    def finish(self):
        self.job.deleteLater()
        self.job = None
        self.tabs.setEnabled(True)
        self.statusBar().showMessage("Готово")

    def closeEvent(self, event):
        if self.job is not None:
            event.ignore()
            return
        super().closeEvent(event)

    def choose_log(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите журнал VPN", "", "Журналы (*.log *.txt);;Все файлы (*)")
        if path:
            self.log_path = path
            self.log_label.setText(Path(path).name)

    def scan(self, title, side=None):
        host = self.host.text().strip()
        if side and host and not self.probe_allowed.isChecked():
            QMessageBox.information(self, "Проверка VPN", "Подтвердите проверку сервера или очистите поле адреса.")
            return
        endpoint = (host, self.port.value(), self.transport.currentText()) if host and side else None
        log_path = self.log_path if side else None

        def completed(snapshot):
            if side:
                if any(sample.get("demo") for sample in self.samples.values()):
                    self.samples.clear()
                self.samples[side] = snapshot
                self.log_path = None
                self.log_label.setText("Журнал не выбран")
            self.pair_report.setChecked(bool(side))
            self.persist(snapshot)
            self.show_snapshot(snapshot)

        self.start("Идёт проверка сети…", lambda: diagnose.collect(title, endpoint, log_path), completed)

    def show_demo(self):
        self.samples = {"home": demo.snapshot(), "mobile": demo.snapshot(True)}
        self.show_snapshot(self.samples["home"])

    @staticmethod
    def router_guide():
        return ("Откройте локальную панель и войдите самостоятельно. Найдите модель и версию ПО в разделе "
                "«Система» или «Информация об устройстве». В WLAN проверьте диапазоны, режим, канал и ширину. "
                "В WAN проверьте тип подключения и DNS. В разделе «Безопасность» проверьте наличие VPN "
                "passthrough и правил фильтрации. Названия и доступность разделов зависят от прошивки.")

    def open_panel(self):
        url = ((self.current or {}).get("router") or {}).get("url")
        if url:
            QDesktopServices.openUrl(QUrl(url))
        else:
            QMessageBox.information(self, "Панель роутера", "Выполните живую проверку обнаружения панели.")

    def show_snapshot(self, snapshot):
        self.current = snapshot
        header = "СИМУЛЯЦИЯ\n\n" if snapshot.get("demo") else ""
        probe = snapshot.get("internet_ping") or {}
        self.overview.setPlainText(header + f"{snapshot['label']} · {snapshot['time']}\n"
                                  f"Ответы ICMP от внешнего узла: {probe.get('replies', 'нет данных')}. "
                                  f"DNS: {'есть ответ' if snapshot.get('dns') else 'нет ответа'}.\n\n"
                                  + pretty(snapshot))
        self.router_info.setPlainText(header + pretty(snapshot.get("router", {})) + "\n\n" + self.router_guide())
        endpoint = snapshot.get("endpoint") or {}
        self.vpn_info.setPlainText(header + pretty({
            "clients": snapshot.get("windows", {}).get("clients", []),
            "tunnels": snapshot.get("tunnels", []),
            "endpoint": vpn.STATUS.get(endpoint.get("status"), "Сервер не проверялся"),
            "log": snapshot.get("vpn_log", {}),
        }))
        differences = vpn.compare(self.samples["home"], self.samples["mobile"]) if len(self.samples) == 2 else []
        unavailable = snapshot.get("windows", {}).get("unavailable", [])
        self.problems.setPlainText(header + "\n\n".join(differences + [
            "Недоступные разделы Windows: " + ", ".join(unavailable) if unavailable else
            "Проверьте результаты снимка и выполните оба теста для сравнения."
        ]))
        self.advice.setPlainText(header + "\n\n".join(optimize.recommendations(snapshot)))
        self.render_speed()
        self.render_report()

    def run_wifi(self):
        self.start("Снимаются показатели Wi-Fi…", diagnose.wifi_series, self.render_wifi)

    def render_wifi(self, result):
        self.speed_info.appendPlainText("\nЗамеры сигнала Wi-Fi с интервалом 2 секунды\n" + pretty(result))

    def run_speed(self):
        if QMessageBox.question(self, "Расход трафика", "Разрешить измерение через speed.cloudflare.com?") != QMessageBox.StandardButton.Yes:
            return
        stage = self.speed_stage.currentText()

        def completed(result):
            result.update({"stage": stage, "time": datetime.now().isoformat(timespec="seconds")})
            self.speed_runs.append(result)
            self.pair_report.setChecked(False)
            snapshot = {"label": stage + " · скорость", "time": result["time"], "speed": result}
            self.persist(snapshot)
            self.show_snapshot(snapshot)

        self.start("Идёт измерение пропускной способности…", speed.measure, completed)

    def render_speed(self):
        current = self.current or {}
        windows = current.get("windows", {})
        self.speed_info.setPlainText(pretty({
            "speed_history": self.speed_runs,
            "selected_speed": current.get("speed"),
            "latency_and_loss": current.get("internet_ping"),
            "wifi": windows.get("wifi"),
            "channels": windows.get("channels"),
        }))

    def confirm_admin(self, message):
        if not self.live or not ctypes.windll.shell32.IsUserAnAdmin():
            QMessageBox.information(self, "Права администратора", "Для этой операции перезапустите программу от администратора.")
            return False
        return QMessageBox.question(self, "Подтверждение", message) == QMessageBox.StandardButton.Yes

    def apply_mtu(self):
        index, mtu = self.interface.value(), self.mtu.value()
        snapshot = self.current or {}
        trials = snapshot.get("mtu", {}).get("ipv4_packet_sizes", {})
        if snapshot.get("demo") or not trials or str(mtu) not in {str(k) for k, value in trials.items() if value == 2} or not any(
            int(size) > mtu and value == 0 for size, value in trials.items()
        ):
            QMessageBox.information(self, "Проверка MTU", "Нужен живой замер, где выбранный размер прошёл, а больший не получил ответ.")
            return
        if (snapshot.get("default_route") or {}).get("InterfaceIndex") != index:
            QMessageBox.information(self, "Проверка интерфейса", "Укажите интерфейс маршрута по умолчанию из живого снимка.")
            return
        def change():
            current = windows.default_route(windows.inventory())
            if current != snapshot["default_route"]:
                raise RuntimeError("Маршрут по умолчанию изменился. Выполните повторную диагностику.")
            optimize.apply(index, mtu)

        if self.confirm_admin(f"Сохранить исходный MTU интерфейса {index} и временно установить {mtu}?"):
            self.start("Применяется MTU…", change,
                       lambda _: QMessageBox.information(self, "MTU", "Значение проверено. Исходный MTU сохранён."))

    def restore_mtu(self):
        if self.confirm_admin("Восстановить MTU из локальной резервной копии?"):
            self.start("Восстанавливается MTU…", optimize.restore,
                       lambda _: QMessageBox.information(self, "MTU", "Исходное значение восстановлено."))

    def persist(self, snapshot):
        filename = f"{datetime.now():%Y%m%d-%H%M%S}-{uuid4().hex[:8]}.json"
        try:
            report.save(report.storage() / "history" / filename, snapshot)
        except OSError as error:
            QMessageBox.warning(self, "История недоступна", str(error))
        self.refresh_history()

    def refresh_history(self):
        self.history.clear()
        for path in sorted((report.storage() / "history").glob("*.json"), reverse=True):
            try:
                snapshot = json.loads(path.read_text(encoding="utf-8"))
                self.history.addItem(f"{snapshot['time']} · {snapshot['label']}", str(path))
            except (OSError, ValueError, KeyError):
                continue

    def load_history(self):
        path = self.history.currentData()
        if path:
            try:
                snapshot = json.loads(Path(path).read_text(encoding="utf-8"))
                self.show_snapshot(snapshot)
            except (OSError, ValueError, KeyError) as error:
                QMessageBox.warning(self, "История недоступна", str(error))

    def report_data(self):
        selected = self.samples if self.pair_report.isChecked() and len(self.samples) == 2 else {"selected": self.current}
        return {
            "simulation": any(s.get("demo") for s in selected.values() if s),
            "checks": {key: report.anonymize(s, self.addresses.isChecked()) for key, s in selected.items() if s},
            "comparison": vpn.compare(selected["home"], selected["mobile"]) if len(selected) == 2 else [],
        }

    def render_report(self):
        self.report_preview.setPlainText(pretty(self.report_data()))

    def export(self):
        if not self.current:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить отчёт", "network-report.json", "JSON (*.json)")
        if path:
            try:
                report.save(Path(path), self.report_data())
            except OSError as error:
                QMessageBox.warning(self, "Не удалось сохранить отчёт", str(error))


STYLE = """
QMainWindow, QWidget { background: #f3f6f9; color: #172c3b; font-size: 13px; }
QLabel#heading { font-size: 25px; font-weight: 700; margin-bottom: 8px; }
QPushButton { background: #14666b; color: white; border: 0; border-radius: 6px; padding: 8px 15px; }
QPushButton:hover { background: #0e5458; }
QPushButton:disabled { color: #5e6c75; background: #dde5ec; }
QPlainTextEdit, QLineEdit, QComboBox, QSpinBox { background: white; border: 1px solid #c4d3df; border-radius: 5px; padding: 6px; }
QTabBar::tab { padding: 9px 10px; background: #e4edf4; }
QTabBar::tab:selected { color: #105d61; background: white; font-weight: 700; }
"""
