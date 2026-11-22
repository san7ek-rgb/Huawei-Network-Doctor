import sys

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from doctor.gui import STYLE, MainWindow


def main():
    app = QApplication([sys.argv[0]])
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    window = MainWindow()
    window.show()
    if "--demo" in sys.argv or "--smoke-test" in sys.argv:
        window.show_demo()
    if "--smoke-test" in sys.argv:
        assert window.tabs.count() == 8
        assert '"simulation": true' in window.report_preview.toPlainText()
        QTimer.singleShot(0, app.quit)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
