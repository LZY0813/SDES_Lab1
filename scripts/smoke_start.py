"""运行真实 run.py 入口，仅为验收给已显示窗口安排正常关闭。"""
from pathlib import Path
import sys
import runpy
from PySide6.QtCore import QTimer

root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'src'))
from sdes.gui import MainWindow
original_show=MainWindow.show
def show_and_close(window):
    original_show(window)
    QTimer.singleShot(800,window.close)
MainWindow.show=show_and_close
try:
    runpy.run_path(str(root/'run.py'),run_name='__main__')
except SystemExit as exc:
    print('Actual run.py entry opened and closed the Qt window; exit code:',exc.code)
    raise
