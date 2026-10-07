import pytest
from PySide6.QtWidgets import QApplication, QMessageBox
from PySide6.QtTest import QTest
from PySide6.QtCore import Qt
from sdes.gui import MainWindow

@pytest.fixture(scope='module')
def app():
    instance=QApplication.instance() or QApplication([])
    yield instance

@pytest.fixture
def window(app):
    widget=MainWindow()
    yield widget
    for worker in widget.workers: worker.wait()
    widget.close()

def test_binary_modes_and_error_does_not_replace_result(window,monkeypatch):
    warnings=[]
    monkeypatch.setattr(QMessageBox,'warning',lambda *args:warnings.append(args[-1]))
    QTest.mouseClick(window.binary_run,Qt.LeftButton)
    assert window.binary_output.text()=='11101000'
    window.binary_input.setText('11101000')
    window.binary_mode.setCurrentIndex(1)
    QTest.mouseClick(window.binary_run,Qt.LeftButton)
    assert window.binary_output.text()=='11010111'
    window.binary_input.setText('x')
    QTest.mouseClick(window.binary_run,Qt.LeftButton)
    assert warnings and window.binary_output.text()=='11010111'

def test_ascii_empty_and_binary_bytes(window):
    window.ascii_plain.setPlainText('Hello\n!')
    window.run_ascii_encrypt()
    assert bytes.fromhex(window.ascii_hex.toPlainText())==window.raw_cipher
    window.run_ascii_decrypt()
    assert window.ascii_plain.toPlainText()=='Hello\n!'
    window.ascii_plain.clear()
    window.run_ascii_encrypt()
    window.run_ascii_decrypt()
    assert window.ascii_plain.toPlainText()==''

def test_background_brute_finishes_with_all_candidates(window,app):
    import time
    window.run_brute()
    assert not window.brute_run.isEnabled()
    deadline=time.monotonic()+15
    while window.brute_result is None and time.monotonic()<deadline:
        QTest.qWait(10)
    assert window.brute_result is not None
    assert '1010000010' in window.brute_result['candidates']
    assert window.brute_progress.value()==1024
    assert window.brute_export.isEnabled()
