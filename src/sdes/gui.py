"""四页桌面 GUI；耗时工作在单个后台线程中执行。"""
import json
import sys
from pathlib import Path
from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout,
    QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QPushButton, QProgressBar,
    QFileDialog, QMessageBox, QComboBox)
from .core import parse_bits, crypt, trace, encrypt_ascii, decrypt_ascii, parse_hex
from .analysis import parse_pairs, brute_force, collision_analysis, export_analysis

class Worker(QThread):
    progress = Signal(int)
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, function, parent=None):
        super().__init__(parent)
        self.function = function

    def run(self):
        try:
            self.completed.emit(self.function(self.progress.emit))
        except Exception as exc:
            self.failed.emit(str(exc))

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('信息安全导论 · S-DES 加解密实验')
        self.resize(1080, 820)
        self.workers = []
        self.raw_cipher = b''
        self.brute_result = None
        self.collision_result = None
        root = QWidget()
        layout = QVBoxLayout(root)
        title = QLabel('S-DES 加解密实验室')
        title.setObjectName('title')
        layout.addWidget(title)
        layout.addWidget(QLabel('课程修改版 SBox2  |  8 bit 分组  ·  10 bit 密钥  ·  两轮 Feistel'))
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        self.binary_page()
        self.ascii_page()
        self.brute_page()
        self.collision_page()
        self.status = QLabel('就绪。实验数据在本机计算；候选密钥不等于已确认的原始密钥。')
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.tabs.currentChanged.connect(lambda index: self.status.setText(
            '后台任务运行中，可切换页面。' if any(worker.isRunning() for worker in self.workers)
            else '就绪：'+self.tabs.tabText(index)))
        self.setCentralWidget(root)
        self.setStyleSheet('''
            QMainWindow { background: #f1f5f9; }
            QWidget { font-family: "Microsoft YaHei UI"; font-size: 14px; color: #142b45; }
            QLabel#title { font-size: 26px; font-weight: 700; padding: 10px 0; }
            QTabWidget::pane { border: 1px solid #cbd5e1; background: white; }
            QTabBar::tab { padding: 12px 22px; background: #e2e8f0; }
            QTabBar::tab:selected { background: #0e668d; color: white; }
            QLineEdit, QPlainTextEdit { background: white; border: 1px solid #9bafc3; padding: 7px; selection-background-color: #287ca2; }
            QPushButton { background: #0e668d; color: white; padding: 9px 18px; border-radius: 5px; }
            QPushButton:disabled { background: #94a3b8; }
            QPushButton:hover { background: #125779; }
            QPushButton:pressed { background: #083c56; }
            QProgressBar { border: 1px solid #cbd5e1; text-align: center; min-height: 22px; }
            QProgressBar::chunk { background: #42a8b2; }
        ''')

    def page(self, name):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)
        self.tabs.addTab(widget, name)
        return layout

    def edit(self, layout, label, default=''):
        layout.addWidget(QLabel(label))
        editor = QLineEdit(default)
        layout.addWidget(editor)
        return editor

    def area(self, layout, label, default='', readonly=False):
        layout.addWidget(QLabel(label))
        editor = QPlainTextEdit(default)
        editor.setReadOnly(readonly)
        layout.addWidget(editor)
        return editor

    def button(self, layout, label, callback):
        button = QPushButton(label)
        button.clicked.connect(lambda: self.guarded(callback))
        layout.addWidget(button)
        return button

    def guarded(self, callback):
        try:
            callback()
            self.status.setText('后台任务运行中，可切换页面。' if any(worker.isRunning() for worker in self.workers) else '操作完成。')
        except (ValueError, OSError) as exc:
            self.status.setText(str(exc))
            QMessageBox.warning(self, '请检查输入或文件', str(exc))

    def copy(self, value):
        QApplication.clipboard().setText(value)

    def binary_page(self):
        layout = self.page('01 二进制加解密')
        self.binary_input = self.edit(layout, '输入分组：恰好 8 位二进制', '11010111')
        self.binary_key = self.edit(layout, '密钥：恰好 10 位二进制', '1010000010')
        row = QHBoxLayout()
        self.binary_mode = QComboBox()
        self.binary_mode.addItems(['加密', '解密'])
        row.addWidget(self.binary_mode)
        self.binary_run = self.button(row, '执行', self.run_binary)
        self.button(row, '复制结果', lambda: self.copy(self.binary_output.text()))
        layout.addLayout(row)
        self.binary_output = self.edit(layout, '输出分组（保留前导零）')
        self.binary_output.setReadOnly(True)
        self.binary_trace = self.area(layout, '轮密钥与中间步骤', readonly=True)

    def run_binary(self):
        value = parse_bits(self.binary_input.text(), 8)
        key = parse_bits(self.binary_key.text(), 10)
        result = trace(value, key, self.binary_mode.currentIndex() == 1)
        self.binary_output.setText(result['result'])
        lines=[f"K1 = {result['K1']}    K2 = {result['K2']}",f"IP = {result['IP']}"]
        for index in (1,2):
            stage=result[f'round{index}']
            lines.extend([f"第 {index} 轮：L={stage['L']}  R={stage['R']}",
                f"  EP={stage['EP']}  XOR轮密钥={stage['XOR']}",
                f"  SBox1={stage['SBox1']}  SBox2={stage['SBox2']}  P4={stage['P4']}",
                f"  fk={stage['fk']}"])
            if index==1: lines.append(f"SW = {result['SW']}")
        lines.append(f"IP_inverse → {result['result']}")
        self.binary_trace.setPlainText('\n'.join(lines))

    def ascii_page(self):
        layout = self.page('02 ASCII 字符串')
        self.ascii_key = self.edit(layout, '密钥：10 位二进制', '1010000010')
        self.ascii_plain = self.area(layout, 'ASCII 明文（支持空格、标点和换行）', 'This is a test!\nS-DES')
        row = QHBoxLayout()
        self.ascii_encrypt_button = self.button(row, '明文 → 加密', self.run_ascii_encrypt)
        self.ascii_decrypt_button = self.button(row, '密文 → 解密', self.run_ascii_decrypt)
        self.button(row, '复制十六进制', lambda: self.copy(self.ascii_hex.toPlainText()))
        self.button(row, '导出原始密文字节', self.export_bytes)
        layout.addLayout(row)
        self.ascii_hex = self.area(layout, '十六进制密文（可编辑，解密时读取此处）')
        self.ascii_result = self.area(layout, '结果：明文 / 安全转义显示', readonly=True)

    def run_ascii_encrypt(self):
        self.raw_cipher = encrypt_ascii(self.ascii_plain.toPlainText(), parse_bits(self.ascii_key.text(),10))
        self.ascii_hex.setPlainText(self.raw_cipher.hex(' '))
        self.ascii_result.setPlainText('密文字节转义显示：\n'+repr(self.raw_cipher))

    def run_ascii_decrypt(self):
        data = parse_hex(self.ascii_hex.toPlainText())
        decoded = decrypt_ascii(data, parse_bits(self.ascii_key.text(),10))
        self.ascii_plain.setPlainText(decoded)
        self.ascii_result.setPlainText('解密明文：\n'+decoded+'\n\n转义显示：\n'+repr(decoded))

    def export_bytes(self):
        data = parse_hex(self.ascii_hex.toPlainText())
        path, _ = QFileDialog.getSaveFileName(self, '导出原始密文', 'cipher.bin', '二进制文件 (*.bin)')
        if path:
            Path(path).write_bytes(data)

    def brute_page(self):
        layout = self.page('03 暴力破解')
        self.pairs_input = self.area(layout, '明密文对：每行 8位明文 空格 8位密文（可输入多行）', '11010111 11101000')
        self.pairs_input.setMaximumHeight(130)
        row = QHBoxLayout()
        self.brute_run = self.button(row, '枚举全部 1024 个密钥', self.run_brute)
        self.brute_export = self.button(row, '导出结果 JSON', self.export_brute)
        self.brute_export.setEnabled(False)
        self.button(row, '复制候选', lambda: self.copy('\n'.join((self.brute_result or {}).get('candidates',[]))))
        layout.addLayout(row)
        self.brute_progress = QProgressBar()
        self.brute_progress.setRange(0,1024)
        layout.addWidget(self.brute_progress)
        self.brute_summary = QLabel('尚未执行。全部候选均会保留。')
        self.brute_summary.setWordWrap(True)
        layout.addWidget(self.brute_summary)
        self.brute_output = self.area(layout, '候选密钥与计算记录', readonly=True)

    def launch(self, function, progress, button, receive):
        button.setEnabled(False)
        progress.setValue(0)
        worker = Worker(function, self)
        self.workers.append(worker)
        worker.progress.connect(progress.setValue)
        worker.completed.connect(receive)
        worker.failed.connect(lambda message: self.status.setText('后台任务失败：'+message))
        worker.finished.connect(lambda: button.setEnabled(True))
        worker.start()

    def run_brute(self):
        pairs = parse_pairs(self.pairs_input.toPlainText())
        self.brute_result = None
        self.brute_export.setEnabled(False)
        self.brute_summary.setText('正在枚举全部密钥……')
        self.brute_output.clear()
        self.launch(lambda progress: brute_force(pairs, progress), self.brute_progress, self.brute_run, self.receive_brute)

    def receive_brute(self, result):
        self.brute_result = result
        self.brute_export.setEnabled(True)
        self.brute_summary.setText(f"已检查 1024 / 1024 个密钥；候选 {result['candidate_count']} 个；计算耗时 {result['elapsed_seconds']:.9f} 秒")
        lines=['全部相容候选密钥（不能把首个候选当作原始密钥）：',
               *result['candidates'], '', f"开始时间：{result['started_at']}",
               f"结束时间：{result['finished_at']}",f"单调计时：{result['elapsed_ns']} 纳秒",
               '', '本次明密文约束：', *[f'{p} → {c}' for p,c in result['pairs']]]
        self.brute_output.setPlainText('\n'.join(lines))
        self.status.setText('破解完成；已保留全部候选，可导出完整 JSON。')

    def export_brute(self):
        if self.brute_result is None:
            raise ValueError('请先完成一次破解')
        path, _ = QFileDialog.getSaveFileName(self, '导出破解结果', 'brute_force.json', 'JSON (*.json)')
        if path:
            Path(path).write_text(json.dumps(self.brute_result,ensure_ascii=False,indent=2),encoding='utf-8')

    def collision_page(self):
        layout = self.page('04 碰撞分析')
        intro = QLabel('遍历全部 256 个明文 × 1024 个密钥，同时检查全域等效密钥。\n候选数量分布包含不可达密文（候选数为 0）；导出含完整 256 行统计。')
        intro.setWordWrap(True)
        layout.addWidget(intro)
        row = QHBoxLayout()
        self.collision_run = self.button(row, '执行完整分析', self.run_collision)
        self.collision_export = self.button(row, '导出 CSV + JSON', self.export_collision)
        self.collision_export.setEnabled(False)
        self.button(row, '复制分析', lambda: self.copy(self.collision_output.toPlainText()))
        layout.addLayout(row)
        self.collision_progress = QProgressBar()
        self.collision_progress.setRange(0,1024)
        layout.addWidget(self.collision_progress)
        self.collision_output = self.area(layout, '统计概览与可复现碰撞实例', readonly=True)

    def run_collision(self):
        self.collision_result = None
        self.collision_export.setEnabled(False)
        self.collision_output.setPlainText('正在完整枚举，请稍候……')
        self.launch(collision_analysis, self.collision_progress, self.collision_run, self.receive_collision)

    def receive_collision(self, result):
        self.collision_result = result
        self.collision_export.setEnabled(True)
        counts = [row['distinct_ciphertexts'] for row in result['rows']]
        example=result['example']
        lines=[f"完成：256 个明文 × 1024 个密钥 = {result['encryptions']} 次加密",
               f"不同密文数量范围：{min(counts)}–{max(counts)}",
               f"不同完整映射：{result['unique_mappings']}；全域等效密钥组：{len(result['equivalent_key_groups'])}",
               f"计算耗时：{result['elapsed_seconds']:.6f} 秒",'',
               f"碰撞实例：{example['plaintext']} → {example['ciphertext']}",
               '全部候选：'+', '.join(example['keys']), '',
               '每个固定明文必有密钥碰撞；指定明密文对的候选数需枚举。',
               '增加明密文对只能缩小或保持候选集合，不能保证立即唯一恢复。', '',
               '完整逐明文统计（候选分布见 CSV / JSON 导出）：',
               '明文        不同密文数    碰撞组数    最大组大小    密钥总数']
        lines.extend(f"{row['plaintext']}       {row['distinct_ciphertexts']}          {row['collision_groups']}          {row['max_group_size']}          {row['key_total']}" for row in result['rows'])
        self.collision_output.setPlainText('\n'.join(lines))
        self.status.setText('碰撞分析完成；完整 256 行统计可导出。')

    def export_collision(self):
        if self.collision_result is None:
            raise ValueError('请先完成碰撞分析')
        path, _ = QFileDialog.getSaveFileName(self, '导出完整统计', 'collision_statistics.csv', 'CSV (*.csv)')
        if path:
            export_analysis(self.collision_result,path)

    def closeEvent(self, event):
        if any(worker.isRunning() for worker in self.workers):
            self.status.setText('后台计算尚未结束，请完成后关闭窗口。')
            event.ignore()
        else:
            super().closeEvent(event)

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
