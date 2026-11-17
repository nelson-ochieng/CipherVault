"""CipherVault v2 — offline Qt desktop interface."""
import sys
import tempfile
from pathlib import Path
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFileDialog, QLineEdit, QMessageBox, QProgressBar, QListWidget,
    QCheckBox, QFrame, QAbstractItemView)
from crypto_engine import encrypt_file, decrypt_file
from archive_utils import archive_folder

class DropList(QListWidget):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback
        self.setAcceptDrops(True)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls(): event.acceptProposedAction()
        else: super().dragEnterEvent(event)
    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls(): event.acceptProposedAction()
        else: super().dragMoveEvent(event)
    def dropEvent(self, event):
        paths = [Path(u.toLocalFile()) for u in event.mimeData().urls() if u.isLocalFile()]
        self.callback(paths)
        event.acceptProposedAction()

class Worker(QThread):
    progress = Signal(int)
    status = Signal(str)
    finished_job = Signal(int, int, str)
    def __init__(self, paths, output, password, mode):
        super().__init__()
        self.paths, self.output, self.password, self.mode = paths, output, password, mode
    def run(self):
        ok, errors = 0, []
        total = len(self.paths)
        for index, src in enumerate(self.paths):
            try:
                self.status.emit(f'Processing {src.name} ({index+1}/{total})')
                name = src.name + '.cvlt' if self.mode == 'encrypt' else (src.name[:-5] if src.name.lower().endswith('.cvlt') else src.name + '.decrypted')
                dest = self.output / name
                cb = lambda done, count, i=index: self.progress.emit(int(100 * (i + (done/count if count else 1)) / total))
                if src.is_dir():
                    if self.mode != 'encrypt':
                        raise ValueError('Folders cannot be decrypted directly')
                    with tempfile.TemporaryDirectory(prefix='cv-folder-') as tmp:
                        archive = Path(tmp) / (src.name + '.zip')
                        archive_folder(src, archive)
                        encrypt_file(archive, str(dest), self.password, cb)
                elif self.mode == 'encrypt':
                    encrypt_file(str(src), str(dest), self.password, cb)
                else:
                    decrypt_file(str(src), str(dest), self.password, cb)
                ok += 1
            except (OSError, ValueError) as exc:
                errors.append(f'{src.name}: {exc}')
            self.progress.emit(int((index+1)*100/total))
        self.finished_job.emit(ok, len(errors), '\n'.join(errors))

class CipherVault(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('CipherVault 2.0 | Offline Encryption')
        self.resize(850, 650)
        self.paths = []
        self.worker = None
        central = QWidget()
        self.setCentralWidget(central)
        main = QVBoxLayout(central)
        main.setContentsMargins(32, 28, 32, 28)
        main.setSpacing(16)
        title = QLabel('◆  CipherVault')
        title.setObjectName('title')
        main.addWidget(title)
        subtitle = QLabel('PRIVATE BY DESIGN  •  AES-256-GCM  •  COMPLETELY OFFLINE')
        subtitle.setObjectName('muted')
        main.addWidget(subtitle)
        main.addSpacing(12)
        main.addWidget(QLabel('FILES & FOLDERS'))
        self.list = DropList(self.add_paths)
        self.list.setToolTip('Drag files or folders here')
        main.addWidget(self.list, 1)
        self.hint = QLabel('Drag files or folders here, or use the buttons below')
        self.hint.setObjectName('muted')
        main.addWidget(self.hint)
        bar = QHBoxLayout()
        for label, action in [('＋ Add files', self.choose_files), ('＋ Add folder', self.choose_folder), ('− Remove selected', self.remove_selected), ('Clear', self.clear)]:
            btn = QPushButton(label)
            btn.clicked.connect(action)
            bar.addWidget(btn)
        main.addLayout(bar)
        main.addWidget(QLabel('PASSWORD'))
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText('Enter a strong password (never stored)')
        main.addWidget(self.password)
        show = QCheckBox('Show password')
        show.toggled.connect(lambda checked: self.password.setEchoMode(QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password))
        main.addWidget(show)
        actions = QHBoxLayout()
        self.encrypt = QPushButton('🔒 Encrypt selected')
        self.decrypt = QPushButton('🔓 Decrypt selected')
        self.encrypt.setObjectName('primary')
        self.decrypt.setObjectName('primary')
        self.encrypt.clicked.connect(lambda: self.start('encrypt'))
        self.decrypt.clicked.connect(lambda: self.start('decrypt'))
        actions.addWidget(self.encrypt)
        actions.addWidget(self.decrypt)
        main.addLayout(actions)
        self.progress = QProgressBar()
        self.progress.setValue(0)
        main.addWidget(self.progress)
        self.status = QLabel('Ready. Originals are never deleted; outputs are never overwritten.')
        self.status.setObjectName('muted')
        main.addWidget(self.status)
        self.setStyleSheet('''
            QWidget { background:#0b1220; color:#e8edf7; font:14px "Segoe UI"; }
            QLabel#title {font-size:34px; font-weight:800; color:#b5a4ff;}
            QLabel#muted {color:#94a3b8; font-size:12px;}
            QListWidget, QLineEdit {background:#151f32; border:1px solid #34415b; border-radius:10px; padding:12px;}
            QListWidget::item {padding:7px;}
            QListWidget::item:selected {background:#4c3e89;}
            QPushButton {background:#26334c; border:1px solid #3a4966; border-radius:9px; padding:12px; font-weight:600;}
            QPushButton:hover {background:#354666;}
            QPushButton#primary {background:#6d4de0; border:0; font-size:15px; padding:15px;}
            QPushButton#primary:hover {background:#8063f4;}
            QPushButton:disabled {background:#374151; color:#8b94a7;}
            QProgressBar {border:1px solid #34415b; border-radius:7px; background:#151f32; text-align:center; height:19px;}
            QProgressBar::chunk {background:#8b73f2; border-radius:6px;}
        ''')
    def add_paths(self, paths):
        for p in paths:
            if (p.is_file() or p.is_dir()) and p not in self.paths:
                self.paths.append(p)
                self.list.addItem(('📁 ' if p.is_dir() else '📄 ') + str(p))
        self.hint.setText(f'{len(self.paths)} item(s) selected')
    def choose_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, 'Choose files')
        self.add_paths([Path(p) for p in paths])
    def choose_folder(self):
        path = QFileDialog.getExistingDirectory(self, 'Choose folder')
        if path: self.add_paths([Path(path)])
    def remove_selected(self):
        indices = sorted([self.list.row(i) for i in self.list.selectedItems()], reverse=True)
        for i in indices:
            self.list.takeItem(i)
            self.paths.pop(i)
        self.hint.setText(f'{len(self.paths)} item(s) selected')
    def clear(self):
        self.paths.clear()
        self.list.clear()
        self.hint.setText('Drag files or folders here, or use the buttons below')
    def start(self, mode):
        if not self.paths or not self.password.text():
            QMessageBox.warning(self, 'Missing information', 'Add files and enter a password.')
            return
        if mode == 'decrypt' and any(p.is_dir() for p in self.paths):
            QMessageBox.warning(self, 'Select files', 'Decryption requires .cvlt files, not folders.')
            return
        output = QFileDialog.getExistingDirectory(self, 'Select output folder (must be different from input folders)')
        if not output: return
        out = Path(output).resolve()
        if any(p.is_dir() and (out == p.resolve() or out.is_relative_to(p.resolve())) for p in self.paths):
            QMessageBox.warning(self, 'Unsafe destination', 'Choose an output folder outside the folders being encrypted.')
            return
        self.encrypt.setEnabled(False)
        self.decrypt.setEnabled(False)
        self.progress.setValue(0)
        self.worker = Worker(self.paths.copy(), out, self.password.text(), mode)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.status.connect(self.status.setText)
        self.worker.finished_job.connect(self.done)
        self.worker.start()
    def done(self, ok, failed, errors):
        self.encrypt.setEnabled(True)
        self.decrypt.setEnabled(True)
        self.password.clear()
        self.status.setText(f'Finished: {ok} successful, {failed} failed')
        if failed: QMessageBox.warning(self, 'Finished with errors', f'{ok} succeeded, {failed} failed.\n\n{errors[:3500]}')
        else: QMessageBox.information(self, 'Success', f'{ok} item(s) processed successfully.')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = CipherVault()
    window.show()
    sys.exit(app.exec())
