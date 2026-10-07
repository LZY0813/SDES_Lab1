"""启动真实 Qt 窗口，用 QTest 输入/点击，捕获实时运行界面。

这属于自动化真实 GUI 操作，不代表两位同学已人工验收。
"""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
import json
import time
from datetime import datetime
from io import BytesIO
from PIL import Image
from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox
from PySide6.QtTest import QTest
from PySide6.QtCore import Qt, QBuffer, QIODevice, QTimer
from sdes.gui import MainWindow
from sdes.core import encrypt_ascii

def main():
    app=QApplication(sys.argv)
    window=MainWindow()
    window.show()
    window.raise_()
    window.activateWindow()
    screenshots=ROOT/'results'/'screenshots'
    recordings=ROOT/'results'/'recordings'
    screenshots.mkdir(parents=True,exist_ok=True)
    recordings.mkdir(parents=True,exist_ok=True)
    log=[]
    frames=[]
    times=[]
    capture_methods=set()
    def record(action,passed=True):
        log.append({'at':datetime.now().astimezone().isoformat(),'action':action,'passed':passed})
    def grab():
        # 只捕获本程序窗口的客户区，避免桌面上其他窗口或私人内容进入证据文件。
        pixmap=window.grab()
        capture_methods.add('QWidget.grab：实时运行窗口客户区')
        if pixmap.isNull(): raise RuntimeError('运行窗口捕获失败')
        return pixmap
    def screenshot(name):
        app.processEvents()
        QTest.qWait(200)
        assert grab().save(str(screenshots/name))
        record('实际运行窗口截图 '+name)
    def frame():
        buffer=QBuffer(); buffer.open(QIODevice.WriteOnly)
        grab().save(buffer,'PNG')
        frames.append(Image.open(BytesIO(bytes(buffer.data()))).convert('RGB'))
        times.append(time.perf_counter())
    def type_line(editor,text):
        editor.setFocus()
        QTest.keyClick(editor,Qt.Key_A,Qt.ControlModifier)
        QTest.keyClicks(editor,text,Qt.NoModifier,15)
    def click(button): QTest.mouseClick(button,Qt.LeftButton)
    def wait_for(predicate,seconds=30):
        start=time.perf_counter()
        while not predicate():
            if time.perf_counter()-start>seconds: raise TimeoutError('GUI 后台任务超时')
            QTest.qWait(15)
    QTest.qWait(800)
    type_line(window.binary_input,'11010111')
    type_line(window.binary_key,'1010000010')
    click(window.binary_run)
    assert window.binary_output.text()=='11101000'
    record('二进制加密及中间步骤')
    screenshot('01_binary.png')
    window.binary_mode.setCurrentIndex(1)
    type_line(window.binary_input,'11101000')
    click(window.binary_run)
    assert window.binary_output.text()=='11010111'
    record('二进制解密')
    window.copy(window.binary_output.text())
    assert QApplication.clipboard().text()=='11010111'
    record('剪贴板复制')
    # 捕获错误提示，自动关闭真实弹窗，不阻塞证据采集。
    warnings=[]
    original_warning=QMessageBox.warning
    def warning(parent,title,text):
        warnings.append(text)
        QTimer.singleShot(120,lambda: QApplication.activeModalWidget().accept() if QApplication.activeModalWidget() else None)
        return original_warning(parent,title,text)
    QMessageBox.warning=warning
    type_line(window.binary_input,'00000x01')
    click(window.binary_run)
    assert warnings and '8' in warnings[-1]
    record('非法二进制真实弹窗')
    window.tabs.setCurrentIndex(1)
    click(window.ascii_encrypt_button)
    assert bytes.fromhex(window.ascii_hex.toPlainText())==encrypt_ascii('This is a test!\nS-DES',642)
    screenshot('02_ascii.png')
    click(window.ascii_decrypt_button)
    assert window.ascii_plain.toPlainText()=='This is a test!\nS-DES'
    record('ASCII 换行文本加解密')
    window.ascii_plain.clear()
    click(window.ascii_encrypt_button)
    assert window.ascii_hex.toPlainText()==''
    record('空文本加密')
    window.ascii_plain.setPlainText('中文')
    click(window.ascii_encrypt_button)
    assert 'ASCII' in warnings[-1]
    record('非 ASCII 输入拒绝')
    window.tabs.setCurrentIndex(2)
    window.pairs_input.clear()
    timer=QTimer()
    timer.timeout.connect(frame)
    timer.start(100)
    frame()
    QTest.qWait(300)
    type_line(window.pairs_input,'11010111 11101000')
    QTest.qWait(400)
    frame()
    QTest.mousePress(window.brute_run,Qt.LeftButton)
    frame()
    QTest.qWait(100)
    QTest.mouseRelease(window.brute_run,Qt.LeftButton)
    wait_for(lambda:window.brute_result is not None)
    assert '1010000010' in window.brute_result['candidates']
    assert window.brute_progress.value()==1024
    record('真实点击并完成全部密钥破解')
    QTest.qWait(1800)
    frame()
    timer.stop()
    durations=[max(10,round((times[i+1]-times[i])*1000)) for i in range(len(times)-1)]+[100]
    frames[0].save(recordings/'brute_force.gif',save_all=True,append_images=frames[1:],duration=durations,loop=0)
    (recordings/'capture_metadata.json').write_text(json.dumps({'method':sorted(capture_methods),'interaction':'QTest 自动输入点击真实 Qt 窗口',
        'frame_count':len(frames),'duration_ms':sum(durations),'frame_times_monotonic':times,
        'note':'破解算法没有人为延迟；结果页停留展示。属于自动化真实 GUI 操作，不是人工操作。',
        'brute_result':window.brute_result},ensure_ascii=False,indent=2),encoding='utf-8')
    screenshot('03_brute_force.png')
    # 用真实保存按钮验证导出；选择器返回预定路径，避免无人值守弹窗。
    original_dialog=QFileDialog.getSaveFileName
    QFileDialog.getSaveFileName=lambda *args,**kwargs:(str(ROOT/'results'/'gui_brute_force.json'),'')
    click(window.brute_export)
    assert json.loads((ROOT/'results'/'gui_brute_force.json').read_text(encoding='utf-8'))==window.brute_result
    record('GUI 破解导出按钮；文件路径由自动化提供')
    window.tabs.setCurrentIndex(3)
    click(window.collision_run)
    # 后台运算期间切换页面，验证事件循环仍能处理交互。
    window.tabs.setCurrentIndex(0)
    app.processEvents()
    assert window.tabs.currentIndex()==0
    window.tabs.setCurrentIndex(3)
    wait_for(lambda:window.collision_result is not None)
    assert len(window.collision_result['rows'])==256
    assert window.collision_progress.value()==1024
    record('后台碰撞分析、切页响应和完整统计')
    screenshot('04_collisions.png')
    QFileDialog.getSaveFileName=lambda *args,**kwargs:(str(ROOT/'results'/'gui_collision_statistics.csv'),'')
    click(window.collision_export)
    assert (ROOT/'results'/'gui_collision_statistics.csv').exists()
    record('GUI 碰撞 CSV/JSON 导出按钮；文件路径由自动化提供')
    QFileDialog.getSaveFileName=original_dialog
    QMessageBox.warning=original_warning
    (ROOT/'results'/'gui_test_log.json').write_text(json.dumps(log,ensure_ascii=False,indent=2),encoding='utf-8')
    for worker in window.workers: worker.wait()
    window.close()
    print(json.dumps({'checks':len(log),'all_passed':all(row['passed'] for row in log),'recording_frames':len(frames)},ensure_ascii=False))

if __name__=='__main__': main()
