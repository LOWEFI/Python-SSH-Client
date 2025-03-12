import sys
import os
import posixpath
import stat
import base64
import time
import datetime
import concurrent.futures
import threading
import paramiko
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import plotly.graph_objects as go
import shutil
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import db_manager
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QMessageBox, QStackedWidget, QScrollArea, QDialog, QPlainTextEdit, QLineEdit, QListWidget, QListWidgetItem, QMenu, QFrame, QInputDialog, QTextEdit, QAbstractItemView, QSplitter, QFileDialog, QCheckBox, QComboBox, QGroupBox
from PyQt5.QtCore import Qt, QTimer, QUrl, QObject, pyqtSignal, QRunnable, QThreadPool, pyqtProperty, QPropertyAnimation, QRectF, QCoreApplication, QThread, pyqtSlot
from PyQt5.QtGui import QFont, QTextCursor, QPainter, QColor
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEngineSettings
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

if getattr(sys, 'frozen', False):
    BASE_PATH = os.path.dirname(sys.executable)
else:
    BASE_PATH = os.path.abspath(".")
DB_FILE = os.path.join(BASE_PATH, "database.db")
ENC_DB_FILE = DB_FILE + ".enc"

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def load_or_create_salt(path=None):
    if path is None:
        path = os.path.join(BASE_PATH, "salt.bin")
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()
    s = os.urandom(16)
    with open(path, "wb") as f:
        f.write(s)
    return s

def encrypt_file(file_path, key):
    f = Fernet(key)
    with open(file_path, "rb") as i:
        data = i.read()
    enc = f.encrypt(data)
    with open(file_path + ".enc", "wb") as o:
        o.write(enc)

def decrypt_file(enc_path, key, out_path):
    f = Fernet(key)
    with open(enc_path, "rb") as i:
        e = i.read()
    d = f.decrypt(e)
    with open(out_path, "wb") as o:
        o.write(d)

def is_encrypted(file_path):
    try:
        with open(file_path, "rb") as f:
            h = f.read(10)
            return not h.startswith(b"SQLite")
    except:
        return False

class WorkerSignals(QObject):
    finished = pyqtSignal(object)
    chmod_progress = pyqtSignal(str, int, int)
    delete_progress = pyqtSignal(str)

class Worker(QRunnable):
    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()
    def run(self):
        r = self.fn(*self.args, **self.kwargs)
        self.signals.finished.emit(r)

class DownloadDirectoryWorker(QRunnable):
    def __init__(self, file_manager, remote_dir, local_dir):
        super().__init__()
        self.file_manager = file_manager
        self.remote_dir = remote_dir
        self.local_dir = local_dir
        self.signals = WorkerSignals()
    def run(self):
        try:
            self.download_directory_recursive(self.remote_dir, self.local_dir)
            self.signals.finished.emit("Download finished")
        except Exception as e:
            self.signals.finished.emit(str(e))
    def download_directory_recursive(self, r, l):
        try:
            items = self.file_manager.sftp.listdir(r)
        except:
            return
        if self.file_manager.transfer_manager.cancel_event.is_set():
            raise Exception("Download cancelled")
        for i in items:
            if self.file_manager.transfer_manager.cancel_event.is_set():
                raise Exception("Download cancelled")
            rp = posixpath.join(r, i)
            lp = os.path.join(l, i)
            try:
                a = self.file_manager.sftp.stat(rp)
                if stat.S_ISDIR(a.st_mode):
                    os.makedirs(lp, exist_ok=True)
                    self.download_directory_recursive(rp, lp)
                else:
                    s = a.st_size
                    QTimer.singleShot(0, lambda x=rp, y=lp, z=s: self.file_manager.transfer_manager.download_file(x, y, z))
            except:
                pass
            QCoreApplication.processEvents()

class DeleteDirectoryWorker(QRunnable):
    def __init__(self, file_manager, remote_path):
        super().__init__()
        self.file_manager = file_manager
        self.remote_path = remote_path
        self.signals = WorkerSignals()
    def run(self):
        try:
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(**self.file_manager.sftp_details)
            s = c.open_sftp()
        except Exception as e:
            self.signals.delete_progress.emit(f"Error connecting for deletion: {e}")
            self.signals.finished.emit(f"Failed deletion: {self.remote_path}")
            return
        try:
            self.delete_directory_recursive(s, self.remote_path)
            self.signals.finished.emit(f"Deleted: {self.remote_path}")
        except Exception as e:
            self.signals.delete_progress.emit(f"Deletion stopped: {e}")
        finally:
            s.close()
            c.close()
    def delete_directory_recursive(self, sftp, rp):
        if self.file_manager.transfer_manager.cancel_event.is_set():
            raise Exception("Deletion cancelled")
        try:
            for i in sftp.listdir(rp):
                if self.file_manager.transfer_manager.cancel_event.is_set():
                    raise Exception("Deletion cancelled")
                p = posixpath.join(rp, i)
                try:
                    a = sftp.stat(p)
                    if stat.S_ISDIR(a.st_mode):
                        self.delete_directory_recursive(sftp, p)
                    else:
                        sftp.remove(p)
                        self.signals.delete_progress.emit(f"Deleted file: {p}")
                except Exception as e:
                    self.signals.delete_progress.emit(f"Error deleting {p}: {e}")
            sftp.rmdir(rp)
            self.signals.delete_progress.emit(f"Deleted folder: {rp}")
        except Exception as e:
            self.signals.delete_progress.emit(f"Error deleting directory {rp}: {e}")

class ChangePermissionsWorker(QRunnable):
    def __init__(self, file_manager, root_path, mode, target):
        super().__init__()
        self.file_manager = file_manager
        self.root_path = root_path
        self.mode = mode
        self.target = target
        self.signals = WorkerSignals()
        self.paths_to_change = []
    def run(self):
        self.collect_paths(self.root_path)
        t = len(self.paths_to_change)
        c = 0
        for p in self.paths_to_change:
            c += 1
            try:
                self.file_manager.sftp.chmod(p, self.mode)
            except:
                pass
            self.signals.chmod_progress.emit(p, c, t)
        self.signals.finished.emit(f"Permissions changed in {t} item(s) under: {self.root_path}")
    def collect_paths(self, rp):
        try:
            a = self.file_manager.sftp.stat(rp)
            d = stat.S_ISDIR(a.st_mode)
        except:
            return
        if d:
            if self.target != "Files Only":
                self.paths_to_change.append(rp)
            try:
                for i in self.file_manager.sftp.listdir(rp):
                    sp = posixpath.join(rp, i)
                    self.collect_paths(sp)
            except:
                pass
        else:
            if self.target != "Folders Only":
                self.paths_to_change.append(rp)

class TransferManager:
    def __init__(self, sftp_details, progress_callback, file_status_callback):
        self.sftp_details = sftp_details
        self.progress_callback = progress_callback
        self.file_status_callback = file_status_callback
        self.total_bytes = 0
        self.transferred_bytes = {}
        self.file_sizes = {}
        self.in_progress = set()
        self.total_files = 0
        self.completed_files = 0
        self.lock = threading.Lock()
        self.cancel_event = threading.Event()
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)
        self.active_clients = []
    def cancel_all_transfers(self):
        self.cancel_event.set()
        with self.lock:
            for c in self.active_clients:
                try:
                    c.close()
                except:
                    pass
            self.active_clients.clear()
    def upload_file(self, local_file, remote_file):
        with self.lock:
            if local_file in self.in_progress:
                return
            self.in_progress.add(local_file)
            self.total_files += 1
        fs = os.path.getsize(local_file)
        with self.lock:
            self.total_bytes += fs
        self.transferred_bytes[local_file] = 0
        self.file_sizes[local_file] = fs
        def progress_callback_inner(bt, total):
            with self.lock:
                self.transferred_bytes[local_file] = bt
            if self.cancel_event.is_set():
                raise Exception("Upload cancelled")
        def task():
            c = None
            try:
                while not self.cancel_event.is_set():
                    try:
                        c = paramiko.SSHClient()
                        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        with self.lock:
                            self.active_clients.append(c)
                        c.connect(**self.sftp_details)
                        s = c.open_sftp()
                        ch = s.get_channel()
                        ch.settimeout(1)
                        s.put(local_file, remote_file, callback=progress_callback_inner)
                        s.close()
                        c.close()
                        break
                    except:
                        if self.cancel_event.is_set():
                            raise Exception("Upload cancelled")
                        QTimer.singleShot(0, lambda: self.file_status_callback(local_file, "En attente"))
                        time.sleep(5)
                    finally:
                        if c:
                            with self.lock:
                                if c in self.active_clients:
                                    self.active_clients.remove(c)
            except:
                pass
            finally:
                with self.lock:
                    if local_file in self.in_progress:
                        self.in_progress.remove(local_file)
                    self.completed_files += 1
                st = "Annulé" if self.cancel_event.is_set() else "OK"
                QTimer.singleShot(0, lambda: self.file_status_callback(local_file, st))
        try:
            self.executor.submit(task)
        except RuntimeError:
            pass
    def download_file(self, remote_file, local_file, fs):
        with self.lock:
            if remote_file in self.in_progress:
                return
            self.in_progress.add(remote_file)
            self.total_files += 1
        with self.lock:
            self.total_bytes += fs
        self.transferred_bytes[remote_file] = 0
        self.file_sizes[remote_file] = fs
        def progress_callback_inner(bt, total):
            with self.lock:
                self.transferred_bytes[remote_file] = bt
            if self.cancel_event.is_set():
                raise Exception("Download cancelled")
        def task():
            c = None
            try:
                while not self.cancel_event.is_set():
                    try:
                        c = paramiko.SSHClient()
                        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        with self.lock:
                            self.active_clients.append(c)
                        c.connect(**self.sftp_details)
                        s = c.open_sftp()
                        ch = s.get_channel()
                        ch.settimeout(1)
                        s.get(remote_file, local_file, callback=progress_callback_inner)
                        s.close()
                        c.close()
                        break
                    except:
                        if self.cancel_event.is_set():
                            raise Exception("Download cancelled")
                        QTimer.singleShot(0, lambda: self.file_status_callback(remote_file, "En attente"))
                        time.sleep(5)
                    finally:
                        if c:
                            with self.lock:
                                if c in self.active_clients:
                                    self.active_clients.remove(c)
            except:
                pass
            finally:
                with self.lock:
                    if remote_file in self.in_progress:
                        self.in_progress.remove(remote_file)
                    self.completed_files += 1
                st = "Annulé" if self.cancel_event.is_set() else "OK"
                QTimer.singleShot(0, lambda: self.file_status_callback(remote_file, st))
        try:
            self.executor.submit(task)
        except RuntimeError:
            pass
    def get_total_progress(self):
        with self.lock:
            return sum(self.transferred_bytes.values())
    def get_file_progress(self):
        with self.lock:
            return self.completed_files, self.total_files

class DropArea(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setStyleSheet("background-color: #2e2e2e; border: 2px dashed #007acc;")
        self.label = QLabel("Drag and drop files/folders here", self)
        self.label.setStyleSheet("color: white;")
        self.label.setAlignment(Qt.AlignCenter)
    def resizeEvent(self, event):
        self.label.resize(self.size())
        super().resizeEvent(event)
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
    def dropEvent(self, event):
        u = event.mimeData().urls()
        f = [x.toLocalFile() for x in u if x.isLocalFile()]
        if f:
            self.parent().handle_drop(f)
        event.acceptProposedAction()

class CustomLoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Access")
        self.setStyleSheet("background-color: #1e1e1e; color: white;")
        self.setFixedSize(300, 150)
        l = QVBoxLayout(self)
        l.addWidget(QLabel("Enter Password:"))
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.Password)
        self.password_entry.setStyleSheet("background-color: #1e1e1e; color: white; padding: 5px; margin-bottom: 10px; min-height: 30px; border: none;")
        l.addWidget(self.password_entry)
        b = QPushButton("Access")
        b.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white; padding: 8px 16px; border: none; border-radius: 4px; max-width: 120px;} QPushButton:hover { background-color: #007acc; }")
        l.addWidget(b, alignment=Qt.AlignCenter)
        b.clicked.connect(self.accept)

class ToggleSwitch(QWidget):
    toggled = pyqtSignal(bool)
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(60, 28)
        self._checked = False
        self._thumb_pos = 2.0
        self._animation = QPropertyAnimation(self, b"thumb_pos", self)
        self._animation.setDuration(200)
        self.setCursor(Qt.PointingHandCursor)
    def mousePressEvent(self, event):
        self._checked = not self._checked
        self._animation.stop()
        e = self.width() - self.height() + 2 if self._checked else 2
        self._animation.setStartValue(self._thumb_pos)
        self._animation.setEndValue(e)
        self._animation.start()
        self.toggled.emit(self._checked)
        self.update()
    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        bg = QColor("#007acc") if self._checked else QColor("#666666")
        p.setBrush(bg)
        p.setPen(Qt.NoPen)
        p.drawRoundedRect(self.rect(), self.height()/2, self.height()/2)
        tr = QRectF(self._thumb_pos, 2, self.height()-4, self.height()-4)
        p.setBrush(Qt.white)
        p.drawEllipse(tr)
    def get_thumb_pos(self):
        return self._thumb_pos
    def set_thumb_pos(self, pos):
        self._thumb_pos = pos
        self.update()
    thumb_pos = pyqtProperty(float, fget=get_thumb_pos, fset=set_thumb_pos)
    def isChecked(self):
        return self._checked
    def setChecked(self, s):
        self._checked = s
        self._thumb_pos = self.width() - self.height() + 2 if s else 2
        self.update()

class FileManagerEmbedded(QWidget):
    def __init__(self, sftp, remote_path, sftp_details):
        super().__init__()
        self.sftp = sftp
        self.remote_path = remote_path
        self.sftp_details = sftp_details
        self.threadpool = QThreadPool.globalInstance()
        self.transfer_manager = TransferManager(sftp_details, self.update_progress, self.update_transfer_status)
        l = QVBoxLayout(self)
        hl = QHBoxLayout()
        self.back_button = QPushButton("Back")
        self.back_button.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white; padding: 8px 16px; border: none; border-radius: 4px;}")
        self.back_button.setDefault(False)
        self.back_button.setAutoDefault(False)
        self.back_button.clicked.connect(self.go_back)
        hl.addWidget(self.back_button)
        self.dir_entry = QLineEdit(self.remote_path)
        self.dir_entry.setStyleSheet("background-color: #1e1e1e; color: white; padding: 5px; margin: 5px 0; min-height: 20px; border: none;")
        hl.addWidget(self.dir_entry)
        self.go_button = QPushButton("Go")
        self.go_button.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white; padding: 8px 16px; border: none; border-radius: 4px;} QPushButton:hover { background-color: #007acc; }")
        self.go_button.setDefault(False)
        self.go_button.setAutoDefault(False)
        self.go_button.clicked.connect(self.go_to_directory)
        hl.addWidget(self.go_button)
        l.addLayout(hl)
        act = QHBoxLayout()
        upload_btn = QPushButton("Upload File")
        upload_btn.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white; padding: 8px 16px; border: none; border-radius: 4px;} QPushButton:hover { background-color: #007acc; }")
        upload_btn.setDefault(False)
        upload_btn.setAutoDefault(False)
        upload_btn.clicked.connect(self.upload_file)
        act.addWidget(upload_btn)
        upload_folder_btn = QPushButton("Upload Folder")
        upload_folder_btn.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white; padding: 8px 16px; border: none; border-radius: 4px;} QPushButton:hover { background-color: #007acc; }")
        upload_folder_btn.setDefault(False)
        upload_folder_btn.setAutoDefault(False)
        upload_folder_btn.clicked.connect(self.upload_folder)
        act.addWidget(upload_folder_btn)
        self.actions_btn = QPushButton("Actions")
        self.actions_btn.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white; padding: 8px 16px; border: none; border-radius: 4px;} QPushButton:hover { background-color: #007acc; }")
        self.actions_btn.setDefault(False)
        self.actions_btn.setAutoDefault(False)
        self.actions_menu = QMenu(self.actions_btn)
        self.actions_menu.addAction("Download Selected", self.download_selected)
        self.actions_menu.addAction("Delete Selected", self.delete_selected)
        self.actions_menu.addAction("Change Permissions", self.change_permissions_selected)
        self.actions_btn.setMenu(self.actions_menu)
        act.addWidget(self.actions_btn)
        refresh_btn = QPushButton("Refresh")
        refresh_btn.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white; padding: 8px 16px; border: none; border-radius: 4px;} QPushButton:hover { background-color: #007acc; }")
        refresh_btn.setDefault(False)
        refresh_btn.setAutoDefault(False)
        refresh_btn.clicked.connect(self.refresh_file_list)
        act.addWidget(refresh_btn)
        stop_transfers_btn = QPushButton("Stop Transfers")
        stop_transfers_btn.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white; padding: 8px 16px; border: none; border-radius: 4px;} QPushButton:hover { background-color: #007acc; }")
        stop_transfers_btn.setDefault(False)
        stop_transfers_btn.setAutoDefault(False)
        stop_transfers_btn.clicked.connect(self.stop_all_transfers)
        act.addWidget(stop_transfers_btn)
        l.addLayout(act)
        self.drop_area = DropArea(self)
        self.drop_area.setFixedHeight(100)
        l.addWidget(self.drop_area)
        self.list_widget = QListWidget()
        self.list_widget.setSpacing(5)
        self.list_widget.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.list_widget.itemDoubleClicked.connect(self.on_item_double_clicked)
        self.list_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.list_widget.customContextMenuRequested.connect(self.show_context_menu)
        l.addWidget(self.list_widget)
        self.transfers_box = QGroupBox("Transfers Box")
        self.transfers_box.setStyleSheet("color: white;")
        transfers_layout = QVBoxLayout(self.transfers_box)
        self.active_transfers_list = QListWidget()
        self.active_transfers_list.setStyleSheet("background-color: #1e1e1e; color: white;")
        transfers_layout.addWidget(self.active_transfers_list)
        self.log_box = QGroupBox("Log Box")
        self.log_box.setStyleSheet("color: white;")
        log_layout = QVBoxLayout(self.log_box)
        self.log_text_edit = QPlainTextEdit()
        self.log_text_edit.setReadOnly(True)
        self.log_text_edit.setStyleSheet("background-color: #1e1e1e; color: white; padding: 5px;")
        log_layout.addWidget(self.log_text_edit)
        l.addWidget(self.transfers_box)
        l.addWidget(self.log_box)
        self.ui_timer = QTimer()
        self.ui_timer.timeout.connect(self.update_ui_progress)
        self.ui_timer.start(200)
        self.refresh_file_list()
        self.current_transfer_files = []
        self.setLayout(l)
    def reset_transfer_manager(self):
        self.transfer_manager = TransferManager(self.sftp_details, self.update_progress, self.update_transfer_status)
    def update_deletion_status(self, msg):
        self.log_text_edit.appendPlainText(msg)
        self.log_text_edit.ensureCursorVisible()
    def update_progress(self, transferred, total):
        pass
    def update_ui_progress(self):
        self.active_transfers_list.clear()
        with self.transfer_manager.lock:
            for f in self.transfer_manager.in_progress:
                t = self.transfer_manager.transferred_bytes.get(f, 0)
                s = self.transfer_manager.file_sizes.get(f, 0)
                p = (t/s*100) if s>0 else 0
                self.active_transfers_list.addItem(f"{os.path.basename(f)}: {t}/{s} bytes ({p:.1f}%)")
    def update_transfer_status(self, f, status):
        self.log_text_edit.appendPlainText(f"{f} : {status}")
        self.log_text_edit.ensureCursorVisible()
    def confirm_replace_dialog(self, fn, ra):
        if ra:
            return True, True
        m = QMessageBox(self)
        m.setWindowTitle("Confirmation de remplacement")
        m.setText(f"Le fichier/dossier '{fn}' existe déjà.\nVoulez-vous le remplacer ?")
        y = m.addButton("Oui", QMessageBox.YesRole)
        n = m.addButton("Non", QMessageBox.NoRole)
        c = QCheckBox("Toujours remplacer")
        m.setCheckBox(c)
        m.exec_()
        return (m.clickedButton()==y, c.isChecked())
    def delete_directory_recursive_sync(self, rp):
        try:
            for i in self.sftp.listdir(rp):
                p = posixpath.join(rp, i)
                try:
                    a = self.sftp.stat(p)
                    if stat.S_ISDIR(a.st_mode):
                        self.delete_directory_recursive_sync(p)
                    else:
                        self.sftp.remove(p)
                except:
                    pass
            self.sftp.rmdir(rp)
        except:
            pass
    def upload_directory_simple(self, local_dir, remote_dir):
        try:
            self.sftp.mkdir(remote_dir)
        except:
            pass
        for root, dirs, files in os.walk(local_dir):
            rel_path = os.path.relpath(root, local_dir)
            rr = posixpath.join(remote_dir, rel_path)
            try:
                self.sftp.mkdir(rr)
            except:
                pass
            for f in files:
                if f==".DS_Store" or f.startswith("._"):
                    continue
                lf = os.path.join(root, f)
                rf = posixpath.join(rr, f)
                try:
                    self.sftp.stat(rf)
                    self.sftp.remove(rf)
                except:
                    pass
                self.transfer_manager.upload_file(lf, rf)
    def upload_file(self):
        if self.transfer_manager.cancel_event.is_set():
            self.reset_transfer_manager()
        lp = QFileDialog.getOpenFileNames(self, "Sélectionnez les fichiers à téléverser")[0]
        if not lp:
            return
        ra = False
        self.current_transfer_files = []
        for p in lp:
            fn = os.path.basename(p)
            if fn==".DS_Store" or fn.startswith("._"):
                continue
            rf = posixpath.join(self.remote_path, fn)
            try:
                self.sftp.stat(rf)
                ok, ra = self.confirm_replace_dialog(fn, ra)
                if not ok:
                    continue
            except:
                pass
            self.current_transfer_files.append(fn)
            self.transfer_manager.upload_file(p, rf)
        if self.current_transfer_files:
            self.log_text_edit.appendPlainText("Téléversement initié pour : " + ", ".join(self.current_transfer_files))
        QMessageBox.information(self, "Succès", "Téléversement initié.")
        self.refresh_file_list()
    def upload_folder(self):
        if self.transfer_manager.cancel_event.is_set():
            self.reset_transfer_manager()
        ld = QFileDialog.getExistingDirectory(self, "Sélectionnez le dossier à téléverser")
        if not ld:
            return
        rd = posixpath.join(self.remote_path, os.path.basename(ld))
        ex = False
        try:
            self.sftp.stat(rd)
            ex = True
        except:
            pass
        if ex:
            r = QMessageBox.question(self, "Confirmation", f"Le dossier '{rd}' existe déjà.\nVoulez-vous le remplacer ?", QMessageBox.Yes | QMessageBox.No)
            if r == QMessageBox.No:
                return
            else:
                self.delete_directory_recursive_sync(rd)
        def do_upload():
            self.upload_directory_simple(ld, rd)
        w = Worker(do_upload)
        w.signals.finished.connect(lambda: self.refresh_file_list())
        self.threadpool.start(w)
        QMessageBox.information(self, "Succès", "Téléversement du dossier initié.")
    def handle_drop(self, fps):
        if self.transfer_manager.cancel_event.is_set():
            self.reset_transfer_manager()
        tasks = []
        for p in fps:
            b = os.path.basename(p)
            if b==".DS_Store" or b.startswith("._"):
                continue
            if os.path.isdir(p):
                rd = posixpath.join(self.remote_path, b)
                ex = False
                try:
                    self.sftp.stat(rd)
                    ex = True
                except:
                    pass
                if ex:
                    r = QMessageBox.question(self, "Confirmation", f"Le dossier '{rd}' existe déjà.\nVoulez-vous le remplacer ?", QMessageBox.Yes | QMessageBox.No)
                    if r == QMessageBox.No:
                        continue
                    else:
                        self.delete_directory_recursive_sync(rd)
                tasks.append(('dir', p, rd))
            else:
                rf = posixpath.join(self.remote_path, b)
                ex = False
                try:
                    self.sftp.stat(rf)
                    ex = True
                except:
                    pass
                if ex:
                    r = QMessageBox.question(self, "Confirmation", f"Le fichier '{rf}' existe déjà.\nVoulez-vous le remplacer ?", QMessageBox.Yes | QMessageBox.No)
                    if r == QMessageBox.No:
                        continue
                    else:
                        self.sftp.remove(rf)
                tasks.append(('file', p, rf))
        def do_upload():
            for k, lz, rz in tasks:
                if k=='dir':
                    self.upload_directory_simple(lz, rz)
                else:
                    self.transfer_manager.upload_file(lz, rz)
        w = Worker(do_upload)
        w.signals.finished.connect(lambda: self.refresh_file_list())
        self.threadpool.start(w)
        if tasks:
            n = [os.path.basename(t[1]) for t in tasks]
            self.log_text_edit.appendPlainText("Téléversement par glisser-déposer initié pour : " + ", ".join(n))
    def refresh_file_list(self):
        self.list_widget.clear()
        w = Worker(self.load_directory)
        w.signals.finished.connect(self.handle_directory_list)
        self.threadpool.start(w)
    def load_directory(self):
        try:
            return self.sftp.listdir(self.remote_path)
        except Exception as e:
            return e
    def handle_directory_list(self, result):
        if isinstance(result, Exception):
            QMessageBox.critical(self, "Error", f"Failed to list directory: {result}")
            return
        for f in result:
            fp = posixpath.join(self.remote_path, f)
            try:
                a = self.sftp.stat(fp)
                d = stat.S_ISDIR(a.st_mode)
            except:
                d = False
            ic = "📁" if d else "📄"
            it = QListWidgetItem(f"{ic} {f}")
            it.setData(Qt.UserRole, fp)
            it.setData(Qt.UserRole+1, d)
            self.list_widget.addItem(it)
        self.dir_entry.setText(self.remote_path)
    def on_item_double_clicked(self, i):
        fp = i.data(Qt.UserRole)
        if i.data(Qt.UserRole+1):
            self.navigate_to(fp)
    def show_context_menu(self, pos):
        it = self.list_widget.itemAt(pos)
        if not it:
            return
        fp = it.data(Qt.UserRole)
        d = it.data(Qt.UserRole+1)
        m = QMenu()
        m.addAction("Download", lambda: self.download_item(fp, d))
        m.addAction("Change Permissions", lambda: self.change_permissions_item(fp, d))
        m.addAction("Delete", lambda: self.delete_item(fp, d))
        m.exec_(self.list_widget.mapToGlobal(pos))
    def go_to_directory(self):
        nd = self.dir_entry.text().strip()
        if nd:
            self.remote_path = nd
            self.refresh_file_list()
    def navigate_to(self, nd):
        self.remote_path = nd
        self.refresh_file_list()
    def go_back(self):
        p = posixpath.dirname(self.remote_path)
        if p and p!=self.remote_path:
            self.remote_path = p
            self.refresh_file_list()
    def download_selected(self):
        if self.transfer_manager.cancel_event.is_set():
            self.reset_transfer_manager()
        it = self.list_widget.selectedItems()
        if not it:
            QMessageBox.critical(self, "Error", "No files selected.")
            return
        dd = QFileDialog.getExistingDirectory(self, "Select Download Directory")
        if dd:
            self.current_transfer_files = []
            for i in it:
                fp = i.data(Qt.UserRole)
                fn = os.path.basename(fp)
                try:
                    a = self.sftp.stat(fp)
                    if stat.S_ISDIR(a.st_mode):
                        td = os.path.join(dd, fn)
                        os.makedirs(td, exist_ok=True)
                        w = DownloadDirectoryWorker(self, fp, td)
                        self.threadpool.start(w)
                    else:
                        sz = a.st_size
                        self.current_transfer_files.append(fn)
                        self.transfer_manager.download_file(fp, os.path.join(dd, fn), sz)
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to download {fp}: {e}")
            if self.current_transfer_files:
                self.log_text_edit.appendPlainText("Download initiated for: " + ", ".join(self.current_transfer_files))
            QMessageBox.information(self, "Success", f"Download initiated to {dd}")
            self.refresh_file_list()
    def download_item(self, fp, d):
        dd = QFileDialog.getExistingDirectory(self, "Select Download Directory")
        if dd:
            if d:
                td = os.path.join(dd, os.path.basename(fp))
                os.makedirs(td, exist_ok=True)
                w = DownloadDirectoryWorker(self, fp, td)
                self.threadpool.start(w)
            else:
                lp = os.path.join(dd, os.path.basename(fp))
                try:
                    a = self.sftp.stat(fp)
                    sz = a.st_size
                    self.current_transfer_files = [os.path.basename(fp)]
                    self.transfer_manager.download_file(fp, lp, sz)
                    self.log_text_edit.appendPlainText("Download initiated for: " + ", ".join(self.current_transfer_files))
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to download {fp}: {e}")
                    return
            QMessageBox.information(self, "Success", f"Download initiated to {dd}")
    def delete_selected(self):
        if self.transfer_manager.cancel_event.is_set():
            self.reset_transfer_manager()
        it = self.list_widget.selectedItems()
        if not it:
            QMessageBox.critical(self, "Error", "No files selected.")
            return
        r = QMessageBox.question(self, "Confirm", "Delete selected items?")
        if r!=QMessageBox.Yes:
            return
        self.pending_deletions = 0
        for i in it:
            fp = i.data(Qt.UserRole)
            d = i.data(Qt.UserRole+1)
            if d:
                w = DeleteDirectoryWorker(self, fp)
                w.signals.delete_progress.connect(self.update_deletion_status)
                self.pending_deletions += 1
                w.signals.finished.connect(lambda: self.__on_dir_deleted())
                self.threadpool.start(w)
            else:
                try:
                    self.sftp.remove(fp)
                    self.update_deletion_status(f"Deleted file: {fp}")
                except Exception as e:
                    self.update_deletion_status(f"Error deleting file {fp}: {e}")
        if self.pending_deletions==0:
            self.refresh_file_list()
    def __on_dir_deleted(self):
        self.pending_deletions-=1
        if self.pending_deletions<=0:
            self.refresh_file_list()
    def delete_item(self, fp, d):
        if d:
            r = QMessageBox.question(self, "Confirm", f"Delete folder '{fp}' recursively?")
            if r==QMessageBox.Yes:
                if self.transfer_manager.cancel_event.is_set():
                    self.reset_transfer_manager()
                w = DeleteDirectoryWorker(self, fp)
                w.signals.delete_progress.connect(self.update_deletion_status)
                w.signals.finished.connect(lambda: self.refresh_file_list())
                self.threadpool.start(w)
        else:
            r = QMessageBox.question(self, "Confirm", f"Delete file '{fp}'?")
            if r==QMessageBox.Yes:
                try:
                    self.sftp.remove(fp)
                    self.update_deletion_status(f"Deleted file: {fp}")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to delete {fp}: {e}")
                self.refresh_file_list()
    def change_permissions_item(self, fp, d):
        np, ok = QInputDialog.getText(self, "Change Permissions", "Enter new permissions (e.g., 755):")
        if not ok or not np:
            return
        try:
            m = int(np, 8)
        except:
            QMessageBox.critical(self, "Error", "Invalid permission format.")
            return
        tgt, ok = QInputDialog.getItem(self, "Select Target", "Apply to:", ["Both", "Files Only", "Folders Only"], 0, False)
        if not ok:
            return
        w = ChangePermissionsWorker(self, fp, m, tgt)
        w.signals.chmod_progress.connect(self.on_chmod_progress)
        w.signals.finished.connect(lambda msg: self.log_text_edit.appendPlainText("Finished: " + msg))
        w.signals.finished.connect(lambda: self.refresh_file_list())
        self.threadpool.start(w)
        QMessageBox.information(self, "Success", f"Changing permissions in background for {fp}.")
    def change_permissions_selected(self):
        it = self.list_widget.selectedItems()
        if not it:
            QMessageBox.critical(self, "Error", "No files selected.")
            return
        np, ok = QInputDialog.getText(self, "Change Permissions", "Enter new permissions (e.g., 755):")
        if not ok or not np:
            return
        try:
            m = int(np, 8)
        except:
            QMessageBox.critical(self, "Error", "Invalid permission format.")
            return
        tgt, ok = QInputDialog.getItem(self, "Select Target", "Apply to:", ["Both", "Files Only", "Folders Only"], 0, False)
        if not ok:
            return
        for i in it:
            fp = i.data(Qt.UserRole)
            w = ChangePermissionsWorker(self, fp, m, tgt)
            w.signals.chmod_progress.connect(self.on_chmod_progress)
            w.signals.finished.connect(lambda msg: self.log_text_edit.appendPlainText("Finished: " + msg))
            w.signals.finished.connect(lambda: self.refresh_file_list())
            self.threadpool.start(w)
        QMessageBox.information(self, "Success", "Permissions changing in background.")
    def stop_all_transfers(self):
        self.transfer_manager.cancel_all_transfers()
        QMessageBox.information(self, "Stopped", "All file transfers have been stopped.")
    @pyqtSlot(str, int, int)
    def on_chmod_progress(self, path, current, total):
        self.log_text_edit.appendPlainText(f"CHMOD: {os.path.basename(path)} [{current}/{total}]")
        self.log_text_edit.ensureCursorVisible()

class DashboardPage(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        l = QVBoxLayout(self)
        t = QLabel("Dashboard")
        t.setFont(QFont("Arial", 24))
        l.addWidget(t)
        self.map_view = QWebEngineView()
        self.map_view.settings().setAttribute(QWebEngineSettings.LocalContentCanAccessRemoteUrls, True)
        l.addWidget(self.map_view)
        al = QHBoxLayout()
        self.auto_connect_toggle = ToggleSwitch()
        self.auto_connect_toggle.toggled.connect(self.toggle_auto_connect)
        al.addWidget(self.auto_connect_toggle)
        lab = QLabel("Auto-Connect")
        lab.setStyleSheet("color: white; font-size: 14px; margin-left: 5px;")
        al.addWidget(lab)
        l.addLayout(al)
        self.status_list = QListWidget()
        l.addWidget(self.status_list)
        self.server_status_items = {}
        self.load_server_statuses()
        self.update_map()
        self.setLayout(l)
    def showEvent(self, event):
        self.auto_connect_toggle.setChecked(self.main_window.global_auto_connect_enabled)
        self.load_server_statuses()
        super().showEvent(event)
    def load_server_statuses(self):
        self.status_list.clear()
        self.server_status_items.clear()
        for s in db_manager.get_servers():
            sid, name, *_ = s
            it = QListWidgetItem(f"Server {name}: ?")
            self.status_list.addItem(it)
            self.server_status_items[sid] = it
    def update_map(self):
        servers = db_manager.get_servers()
        groups = {}
        for s in servers:
            lat, lon, name = s[6], s[7], s[1]
            k = (round(lat,4), round(lon,4))
            if k not in groups:
                groups[k] = {"lat": lat, "lon": lon, "names": []}
            groups[k]["names"].append(name)
        ml = [v["lat"] for v in groups.values()]
        mo = [v["lon"] for v in groups.values()]
        ht = ["<br>".join(v["names"]) for v in groups.values()]
        if ml:
            clat = sum(ml)/len(ml)
            clon = sum(mo)/len(mo)
        else:
            clat, clon = 0,0
        f = go.Figure(data=go.Scattergeo(lon=mo, lat=ml, mode='markers', marker=dict(size=10,opacity=1), hoverinfo='text', text=ht))
        f.update_layout(autosize=True,geo=dict(projection=dict(type='orthographic'),center=dict(lat=clat,lon=clon),showland=True,landcolor='rgba(20,20,20,0.2)',showocean=True,oceancolor='black',showlakes=True,lakecolor='black',bgcolor='rgba(0,0,0,1)'),paper_bgcolor='rgba(0,0,0,1)',margin=dict(l=0,r=0,t=0,b=0))
        p = os.path.join(BASE_PATH, "plotly_map.html")
        f.write_html(p, div_id="plotly-map")
        with open(p,"r",encoding="utf-8") as f2:
            c = f2.read()
        s = """
<script>
  var visible = true;
  var rotation = 0;
  var autoRotationInterval;
  function startAutoRotation() {
    autoRotationInterval = setInterval(function(){
      rotation = (rotation + 0.5) % 360;
      Plotly.relayout('plotly-map', {'geo.projection.rotation.lon': rotation});
    }, 100);
  }
  function stopAutoRotation() {
    clearInterval(autoRotationInterval);
  }
  setInterval(function(){
    visible = !visible;
    Plotly.restyle('plotly-map', {'marker.opacity': [visible ? 1 : 0]});
  }, 500);
  startAutoRotation();
</script>
</body>
"""
        c = c.replace("</body>", s)
        with open(p,"w",encoding="utf-8") as f3:
            f3.write(c)
        self.map_view.load(QUrl.fromLocalFile(p))
    def toggle_auto_connect(self, c):
        self.main_window.toggle_auto_connect(c)

class ServersPage(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        ml = QVBoxLayout(self)
        t = QLabel("Servers")
        t.setFont(QFont("Arial", 24))
        t.setAlignment(Qt.AlignCenter)
        ml.addWidget(t)
        bl = QHBoxLayout()
        b_add = QPushButton("Ajouter")
        b_add.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white; padding: 8px 16px; border: none; border-radius: 4px;} QPushButton:hover { background-color: #007acc; }")
        b_add.clicked.connect(lambda _,mw=self.main_window: mw.switch_page(AddServerPage(mw)))
        bl.addWidget(b_add)
        bl.addStretch()
        ml.addLayout(bl)
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_content = QWidget()
        self.scroll_content.setStyleSheet("background-color: #1e1e1e;")
        self.scroll_layout = QVBoxLayout(self.scroll_content)
        self.scroll_layout.setAlignment(Qt.AlignTop)
        self.scroll_area.setWidget(self.scroll_content)
        ml.addWidget(self.scroll_area)
        self.load_servers()
        self.setLayout(ml)
    def load_servers(self):
        while self.scroll_layout.count():
            w = self.scroll_layout.takeAt(0).widget()
            if w:
                w.deleteLater()
        s = db_manager.get_servers()
        for i,sv in enumerate(s):
            sid,name,host,port,user,pwd,lat,lon,oi,ac = sv
            rf = QFrame()
            rf.setStyleSheet("background-color: #333; border-radius: 6px;")
            rl = QHBoxLayout(rf)
            rl.setContentsMargins(10,5,10,5)
            b_det = QPushButton(name)
            b_det.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white; padding: 8px 16px; border: none; border-radius: 4px;} QPushButton:hover { background-color: #007acc; }")
            b_det.clicked.connect(lambda _,x=sid: self.main_window.switch_page(ServerDetailPage(self.main_window,x)))
            rl.addWidget(b_det, 2)
            b_edit = QPushButton("Edit")
            b_edit.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white; padding: 8px 16px; border: none; border-radius: 4px;} QPushButton:hover { background-color: #007acc; }")
            b_edit.clicked.connect(lambda _,x=sid: self.edit_server_dialog(x))
            rl.addWidget(b_edit)
            b_del = QPushButton("Delete")
            b_del.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white; padding: 8px 16px; border: none; border-radius: 4px;} QPushButton:hover { background-color: #007acc; }")
            b_del.clicked.connect(lambda _,x=sid: self.delete_server(x))
            rl.addWidget(b_del)
            auto_toggle = ToggleSwitch()
            auto_toggle.setChecked(ac==1)
            auto_toggle.toggled.connect(lambda c,x=sid: db_manager.update_server_auto_connect(x, 1 if c else 0))
            al = QHBoxLayout()
            al.addWidget(auto_toggle)
            lab = QLabel("Auto-Connect")
            lab.setStyleSheet("color: white; font-size: 12px; margin-left: 5px;")
            al.addWidget(lab)
            rl.addLayout(al)
            if i>0:
                b_up = QPushButton("⬆")
                b_up.setFixedWidth(40)
                b_up.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white; padding: 8px; border: none;} QPushButton:hover { background-color: #007acc; }")
                b_up.clicked.connect(lambda _,x=i: self.move_server(x, -1))
                rl.addWidget(b_up)
            if i<len(s)-1:
                b_down = QPushButton("⬇")
                b_down.setFixedWidth(40)
                b_down.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white; padding: 8px; border: none;} QPushButton:hover { background-color: #007acc; }")
                b_down.clicked.connect(lambda _,x=i: self.move_server(x, 1))
                rl.addWidget(b_down)
            self.scroll_layout.addWidget(rf)
    def move_server(self, idx, d):
        s = db_manager.get_servers()
        if (d==-1 and idx>0) or (d==1 and idx<len(s)-1):
            cid = s[idx][0]
            nid = s[idx+d][0]
            db_manager.swap_server_order(cid, nid)
            self.load_servers()
    def delete_server(self, sid):
        r = QMessageBox.question(self, "Confirm", "Are you sure you want to delete this server?")
        if r==QMessageBox.Yes:
            db_manager.delete_server(sid)
            self.load_servers()
    def edit_server_dialog(self, sid):
        s = db_manager.get_server(sid)
        if not s:
            QMessageBox.critical(self, "Error", "Server not found.")
            return
        d = QDialog(self)
        d.setWindowTitle("Edit Server Info")
        d.setStyleSheet("background-color: #1e1e1e; color: white;")
        d.setMinimumWidth(600)
        sc = QScrollArea(d)
        sc.setWidgetResizable(True)
        c = QWidget()
        c.setStyleSheet("background-color: #1e1e1e; color: white;")
        fl = QVBoxLayout(c)
        fl.addWidget(QLabel("Name:"))
        name_entry = QLineEdit(s[1])
        name_entry.setStyleSheet("background-color: #1e1e1e; color: white; padding: 5px; margin-bottom: 10px; min-height: 30px; border: none;")
        fl.addWidget(name_entry)
        fl.addWidget(QLabel("Host:"))
        host_entry = QLineEdit(s[2])
        host_entry.setStyleSheet("background-color: #1e1e1e; color: white; padding: 5px; margin-bottom: 10px; min-height: 30px; border: none;")
        fl.addWidget(host_entry)
        fl.addWidget(QLabel("Port:"))
        port_entry = QLineEdit(str(s[3]))
        port_entry.setStyleSheet("background-color: #1e1e1e; color: white; padding: 5px; margin-bottom: 10px; min-height: 30px; border: none;")
        fl.addWidget(port_entry)
        fl.addWidget(QLabel("Username:"))
        user_entry = QLineEdit(s[4])
        user_entry.setStyleSheet("background-color: #1e1e1e; color: white; padding: 5px; margin-bottom: 10px; min-height: 30px; border: none;")
        fl.addWidget(user_entry)
        fl.addWidget(QLabel("Password:"))
        pass_entry = QLineEdit(s[5])
        pass_entry.setEchoMode(QLineEdit.Password)
        pass_entry.setStyleSheet("background-color: #1e1e1e; color: white; padding: 5px; margin-bottom: 10px; min-height: 30px; border: none;")
        fl.addWidget(pass_entry)
        b_update = QPushButton("Update")
        b_update.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white; padding: 8px 16px; border: none; border-radius: 4px;} QPushButton:hover { background-color: #007acc; }")
        bl = QHBoxLayout()
        bl.addStretch()
        bl.addWidget(b_update)
        bl.addStretch()
        fl.addLayout(bl)
        sc.setWidget(c)
        ml = QVBoxLayout(d)
        ml.addWidget(sc)
        b_update.clicked.connect(lambda: self.submit_update(d, sid, name_entry.text(), host_entry.text(), port_entry.text(), user_entry.text(), pass_entry.text()))
        d.exec_()
    def submit_update(self, dialog, sid, new_name, new_host, new_port, new_user, new_pass):
        try:
            np = int(new_port)
        except:
            QMessageBox.critical(dialog, "Error", "Port must be an integer.")
            return
        db_manager.update_server(sid, new_name, new_host, np, new_user, new_pass)
        QMessageBox.information(dialog, "Success", "Server info updated.")
        dialog.accept()
        self.load_servers()

class AddServerPage(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        ml = QVBoxLayout(self)
        ml.setAlignment(Qt.AlignTop)
        t = QLabel("Ajouter Serveur")
        t.setFont(QFont("Arial",24))
        ml.addWidget(t)
        ff = QFrame()
        ff.setStyleSheet("background-color: #1e1e1e; border-radius: 8px;")
        ff.setMinimumWidth(600)
        fl = QVBoxLayout(ff)
        fl.addWidget(QLabel("Name:"))
        self.name_entry = QLineEdit()
        self.name_entry.setStyleSheet("background-color: #1e1e1e; color: white; padding: 5px; margin-bottom: 10px; min-height: 30px; border: none;")
        fl.addWidget(self.name_entry)
        fl.addWidget(QLabel("Host:"))
        self.host_entry = QLineEdit()
        self.host_entry.setStyleSheet("background-color: #1e1e1e; color: white; padding: 5px; margin-bottom: 10px; min-height: 30px; border: none;")
        fl.addWidget(self.host_entry)
        fl.addWidget(QLabel("Port:"))
        self.port_entry = QLineEdit()
        self.port_entry.setStyleSheet("background-color: #1e1e1e; color: white; padding: 5px; margin-bottom: 10px; min-height: 30px; border: none;")
        fl.addWidget(self.port_entry)
        fl.addWidget(QLabel("Username:"))
        self.user_entry = QLineEdit()
        self.user_entry.setStyleSheet("background-color: #1e1e1e; color: white; padding: 5px; margin-bottom: 10px; min-height: 30px; border: none;")
        fl.addWidget(self.user_entry)
        fl.addWidget(QLabel("Password:"))
        self.pass_entry = QLineEdit()
        self.pass_entry.setEchoMode(QLineEdit.Password)
        self.pass_entry.setStyleSheet("background-color: #1e1e1e; color: white; padding: 5px; margin-bottom: 10px; min-height: 30px; border: none;")
        fl.addWidget(self.pass_entry)
        b_sub = QPushButton("Submit")
        b_sub.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white; padding: 8px 16px; border: none; border-radius: 4px;} QPushButton:hover { background-color: #007acc; }")
        bl = QHBoxLayout()
        bl.addStretch()
        bl.addWidget(b_sub)
        bl.addStretch()
        fl.addLayout(bl)
        b_sub.clicked.connect(self.submit)
        ml.addWidget(ff, alignment=Qt.AlignCenter)
        self.setLayout(ml)
    def submit(self):
        name = self.name_entry.text()
        host = self.host_entry.text()
        port_text = self.port_entry.text()
        user = self.user_entry.text()
        pwd = self.pass_entry.text()
        if not (name and host and port_text and user):
            QMessageBox.critical(self, "Error", "Please fill all required fields.")
            return
        try:
            port = int(port_text)
        except:
            QMessageBox.critical(self, "Error", "Port must be an integer.")
            return
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, port=port, username=user, password=pwd, timeout=10)
            stdin,stdout,stderr = ssh.exec_command("curl -s ipinfo.io/loc")
            loc = stdout.read().decode().strip()
            if ',' in loc:
                la, lo = map(float, loc.split(','))
            else:
                raise Exception("Invalid location format")
            ssh.close()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to fetch location: {e}")
            return
        db_manager.add_server(name, host, port, user, pwd, la, lo)
        self.main_window.switch_page(ServersPage(self.main_window))

class ServerDetailPage(QWidget):
    def __init__(self, main_window, server_id):
        super().__init__()
        self.main_window = main_window
        self.server_id = server_id
        s = db_manager.get_server(server_id)
        if not s:
            QMessageBox.critical(self, "Error", "Server not found.")
            self.main_window.switch_page(ServersPage(self.main_window))
            return
        _,name,host,port,user,pwd,lat,lon,oi,ac = s
        self.sftp_details = {"hostname": host, "port": port, "username": user, "password": pwd}
        l = QVBoxLayout(self)
        t = QLabel(f"Server Detail: {name}")
        t.setFont(QFont("Arial",24))
        l.addWidget(t)
        self.conn_label = QLabel("Connecting via SSH...")
        l.addWidget(self.conn_label)
        self.ssh_client = self.connect_ssh(host, port, user, pwd)
        tb = QHBoxLayout()
        l.addLayout(tb)
        self.btn_add_script = QPushButton("Add script")
        self.btn_add_script.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white; padding: 8px 16px; border: none; border-radius: 4px;} QPushButton:hover { background-color: #007acc; }")
        self.btn_add_script.clicked.connect(self.open_add_script)
        tb.addWidget(self.btn_add_script)
        self.btn_console = QPushButton("Console")
        self.btn_console.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white; padding: 8px 16px; border: none; border-radius: 4px;} QPushButton:hover { background-color: #007acc; }")
        self.btn_console.clicked.connect(self.open_server_console)
        tb.addWidget(self.btn_console)
        sl = QHBoxLayout()
        l.addLayout(sl)
        self.script_combo = QComboBox()
        sl.addWidget(self.script_combo)
        self.run_button = QPushButton("Run")
        self.run_button.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white;}")
        self.run_button.clicked.connect(self.on_run_script)
        sl.addWidget(self.run_button)
        self.edit_button = QPushButton("Edit")
        self.edit_button.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white;}")
        self.edit_button.clicked.connect(self.on_edit_script)
        sl.addWidget(self.edit_button)
        self.delete_button = QPushButton("Delete")
        self.delete_button.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white;}")
        self.delete_button.clicked.connect(self.on_delete_script)
        sl.addWidget(self.delete_button)
        self.refresh_scripts()
        self.fig,self.ax=plt.subplots(figsize=(5,3),dpi=100)
        self.fig.patch.set_facecolor('#323232')
        self.ax.set_facecolor('#323232')
        for sp in self.ax.spines.values():
            sp.set_color('white')
        self.ax.tick_params(axis='both', colors='white')
        self.ax.set_title("Connections Over Time", fontsize=14, fontweight="bold", color="white")
        self.ax.set_xlabel("Time", fontsize=12, color="white")
        self.ax.set_ylabel("Connection Count", fontsize=12, color="white")
        self.ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        self.canvas = FigureCanvas(self.fig)
        l.addWidget(self.canvas)
        if self.main_window.global_auto_connect_enabled:
            self.graph_timer = QTimer(self)
            self.graph_timer.timeout.connect(self.update_graph)
            self.graph_timer.start(5000)
        b_back = QPushButton("Back")
        b_back.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white; padding: 8px 16px; border: none; border-radius: 4px;} QPushButton:hover { background-color: #007acc; }")
        b_back.clicked.connect(lambda: self.main_window.switch_page(ServersPage(self.main_window)))
        l.addWidget(b_back,alignment=Qt.AlignCenter)
        self.setLayout(l)
    def connect_ssh(self, host, port, user, pwd):
        a = self.main_window.auto_connections
        if self.server_id in a and a[self.server_id] is not None:
            c = a[self.server_id]
            if c.get_transport() and c.get_transport().is_active():
                self.conn_label.setText("Using auto-connect SSH")
                return c
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            c.connect(host, port=port, username=user, password=pwd, timeout=10)
            t = c.get_transport()
            if t:
                t.set_keepalive(30)
            self.conn_label.setText("Connected via SSH")
            self.main_window.auto_connections[self.server_id] = c
            return c
        except Exception as e:
            self.conn_label.setText(f"Connection Failed: {e}")
            return None
    def refresh_scripts(self):
        self.script_combo.clear()
        s = db_manager.get_scripts(self.server_id)
        if not s:
            self.script_combo.addItem("No scripts", -1)
            return
        for (i,sr,n,c) in s:
            ix = self.script_combo.count()
            self.script_combo.addItem(n)
            self.script_combo.setItemData(ix, i, Qt.UserRole)
            self.script_combo.setItemData(ix, c, Qt.UserRole+1)
    def on_run_script(self):
        ix = self.script_combo.currentIndex()
        if ix<0:
            return
        sid = self.script_combo.itemData(ix, Qt.UserRole)
        if sid==-1:
            return
        sc = self.script_combo.itemData(ix, Qt.UserRole+1)
        if not self.ssh_client:
            QMessageBox.critical(self, "Error", "SSH connection not available")
            return
        c = ServerConsoleWithFileManager(self.ssh_client, self.sftp_details)
        c.execute_script(sc)
        c.exec_()
    def on_edit_script(self):
        ix = self.script_combo.currentIndex()
        if ix<0:
            return
        sid = self.script_combo.itemData(ix, Qt.UserRole)
        if sid==-1:
            return
        sc = self.script_combo.itemData(ix, Qt.UserRole+1)
        sn = self.script_combo.currentText()
        self.edit_script(sid, sn, sc)
    def on_delete_script(self):
        ix = self.script_combo.currentIndex()
        if ix<0:
            return
        sid = self.script_combo.itemData(ix, Qt.UserRole)
        if sid==-1:
            return
        sn = self.script_combo.currentText()
        r = QMessageBox.question(self, "Confirm", f"Supprimer le script '{sn}' ?", QMessageBox.Yes | QMessageBox.No)
        if r==QMessageBox.Yes:
            db_manager.delete_script(sid)
            self.refresh_scripts()
            QMessageBox.information(self, "Info", "Script supprimé.")
    def edit_script(self, sid, cn, cs):
        d = QDialog(self)
        d.setWindowTitle("Edit Script")
        d.resize(600,400)
        sc = QScrollArea(d)
        sc.setWidgetResizable(True)
        c = QWidget()
        fl = QVBoxLayout(c)
        n = QLineEdit(cn)
        n.setStyleSheet("background-color: #1e1e1e; color: white; padding: 5px; margin-bottom: 10px; min-height: 30px; border: none;")
        fl.addWidget(n)
        st = QPlainTextEdit()
        st.setStyleSheet("background-color: #1e1e1e; color: white; border: none;")
        st.setFont(QFont("Courier New",10))
        st.setLineWrapMode(QPlainTextEdit.NoWrap)
        st.setPlainText(cs)
        fl.addWidget(st)
        b_u = QPushButton("Update")
        b_u.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white; padding: 8px 16px; border: none; border-radius: 4px;} QPushButton:hover { background-color: #007acc; }")
        b_u.clicked.connect(lambda: self.update_script(d, sid, n.text(), st.toPlainText()))
        fl.addWidget(b_u,alignment=Qt.AlignCenter)
        sc.setWidget(c)
        ml = QVBoxLayout(d)
        ml.addWidget(sc)
        d.exec_()
    def update_script(self, dialog, sid, nn, ns):
        if not nn or not ns:
            QMessageBox.critical(dialog, "Error", "Both fields are required.")
            return
        db_manager.update_script(sid, nn, ns)
        dialog.accept()
        self.refresh_scripts()
    def open_add_script(self):
        d = QDialog(self)
        d.setWindowTitle("Ajouter un script")
        d.resize(600,400)
        sc = QScrollArea(d)
        sc.setWidgetResizable(True)
        c = QWidget()
        fl = QVBoxLayout(c)
        n = QLineEdit()
        n.setStyleSheet("background-color: #1e1e1e; color: white; padding: 5px; margin-bottom: 10px; min-height: 30px; border: none;")
        fl.addWidget(n)
        st = QPlainTextEdit()
        st.setStyleSheet("background-color: #1e1e1e; color: white; border: none;")
        st.setFont(QFont("Courier New",10))
        st.setLineWrapMode(QPlainTextEdit.NoWrap)
        fl.addWidget(st)
        b = QPushButton("Submit")
        b.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white; padding: 8px 16px; border: none; border-radius: 4px;} QPushButton:hover { background-color: #007acc; }")
        b.clicked.connect(lambda: self.submit_script(d, n.text(), st.toPlainText()))
        fl.addWidget(b,alignment=Qt.AlignCenter)
        sc.setWidget(c)
        ml = QVBoxLayout(d)
        ml.addWidget(sc)
        d.exec_()
    def submit_script(self, dialog, sn, sc):
        if not sn or not sc:
            QMessageBox.critical(dialog, "Error", "Please provide both a name and script content.")
            return
        db_manager.add_script(self.server_id, sn, sc)
        dialog.accept()
        self.refresh_scripts()
    def open_server_console(self):
        if not (self.ssh_client and self.ssh_client.get_transport() and self.ssh_client.get_transport().is_active()):
            self.ssh_client = self.connect_ssh(self.sftp_details["hostname"], self.sftp_details["port"], self.sftp_details["username"], self.sftp_details["password"])
        if not self.ssh_client:
            QMessageBox.critical(self, "Error", "SSH connection not available")
            return
        c = ServerConsoleWithFileManager(self.ssh_client, self.sftp_details)
        c.exec_()
    def update_graph(self):
        stats = db_manager.get_stats(self.server_id)
        if stats:
            co = datetime.datetime.now() - datetime.timedelta(hours=24)
            ff = [x for x in stats if datetime.datetime.fromtimestamp(x[0])>=co]
            if ff:
                ti = [datetime.datetime.fromtimestamp(x[0]) for x in ff]
                ng = [x[1] for x in ff]
                to = [x[2] for x in ff]
            else:
                ti,ng,to=[],[],[]
            self.ax.clear()
            self.ax.plot(ti,ng,"ro-",label="Nginx")
            self.ax.plot(ti,to,"go-",label="Tor")
            self.ax.set_title("Connections Over Time",color="white")
            self.ax.set_xlabel("Time",color="white")
            self.ax.set_ylabel("Connection Count",color="white")
            self.ax.tick_params(axis='both', colors='white')
            self.ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
            lg = self.ax.legend()
            for text in lg.get_texts():
                text.set_color("white")
            self.fig.autofmt_xdate()
            self.canvas.draw_idle()
        else:
            self.ax.clear()
            self.ax.text(0.5,0.5,"No stats",ha="center",va="center",color="white")
            self.canvas.draw_idle()

class ConsoleWorker(QThread):
    new_data = pyqtSignal(str)
    def __init__(self, shell):
        super().__init__()
        self.shell = shell
        self._running = True
    def run(self):
        while self._running:
            try:
                if self.shell and self.shell.recv_ready():
                    d = self.shell.recv(4096).decode("utf-8",errors="replace")
                    self.new_data.emit(d)
            except:
                pass
            time.sleep(0.1)
    def stop(self):
        self._running = False

class ServerConsoleWithFileManager(QDialog):
    def __init__(self, ssh_client, sftp_details):
        super().__init__()
        self.setWindowTitle("Server Console")
        self.resize(1200,700)
        self.ssh_client = ssh_client
        self.sftp_details = sftp_details
        self.splitter = QSplitter(Qt.Horizontal)
        cw = QWidget()
        cl = QVBoxLayout(cw)
        hh = QLabel("Server Console")
        hh.setStyleSheet("color: #f1f1f1; font-size: 14pt; padding: 5px;")
        hh.setAlignment(Qt.AlignCenter)
        cl.addWidget(hh)
        self.display = QPlainTextEdit()
        self.display.setStyleSheet("background-color: #000000; color: #f1f1f1; font-family: Consolas, monospace; font-size: 10pt; padding: 2px;")
        self.display.setReadOnly(True)
        cl.addWidget(self.display)
        self.input_entry = QLineEdit()
        self.input_entry.setStyleSheet("background-color: #1e1e1e; color: #f1f1f1; padding: 5px;")
        self.input_entry.returnPressed.connect(self.on_enter)
        cl.addWidget(self.input_entry)
        self.splitter.addWidget(cw)
        fmw = QWidget()
        fml = QVBoxLayout(fmw)
        if not self.ssh_client or not (self.ssh_client.get_transport() and self.ssh_client.get_transport().is_active()):
            try:
                c = paramiko.SSHClient()
                c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                c.connect(**self.sftp_details, timeout=10)
                c.get_transport().set_keepalive(30)
                self.ssh_client = c
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to reconnect for SFTP: {e}")
                self.ssh_client = None
        try:
            if self.ssh_client:
                self.sftp = self.ssh_client.open_sftp()
            else:
                self.sftp = None
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open SFTP: {e}")
            self.sftp = None
        self.current_directory = "/root"
        if self.sftp:
            self.file_manager = FileManagerEmbedded(self.sftp, self.current_directory, self.sftp_details)
            fml.addWidget(self.file_manager)
        self.splitter.addWidget(fmw)
        self.splitter.setSizes([900,300])
        ml = QVBoxLayout(self)
        ml.addWidget(self.splitter)
        self.setLayout(ml)
        if not self.ssh_client or not (self.ssh_client.get_transport() and self.ssh_client.get_transport().is_active()):
            self.shell = None
            QMessageBox.critical(self, "Error", "Failed to open shell: SSH client not connected.")
        else:
            try:
                self.shell = self.ssh_client.invoke_shell()
                self.shell.settimeout(0.0)
                self.shell.send("bind 'set enable-bracketed-paste off'\n")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to open shell: {e}")
                self.shell = None
        if self.shell:
            self.console_thread = ConsoleWorker(self.shell)
            self.console_thread.new_data.connect(self.append_shell_data)
            self.console_thread.start()
        else:
            self.console_thread = None
        self.connection_timer = QTimer(self)
        self.connection_timer.timeout.connect(self.check_connection)
        self.connection_timer.start(2000)
    def on_enter(self):
        cmd = self.input_entry.text().strip()
        if cmd and self.shell:
            self.shell.send(cmd+"\n")
            self.input_entry.clear()
    @pyqtSlot(str)
    def append_shell_data(self, data):
        self.display.moveCursor(QTextCursor.End)
        self.display.insertPlainText(data)
    def execute_script(self, script):
        self.display.clear()
        self.splitter.widget(1).hide()
        if self.shell:
            self.shell.send(script+"\n")
    def check_connection(self):
        try:
            if not self.ssh_client or not self.ssh_client.get_transport() or not self.ssh_client.get_transport().is_active():
                self.display.appendPlainText("Connection lost. Reconnecting...\n")
                c = paramiko.SSHClient()
                c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                c.connect(**self.sftp_details, timeout=10)
                c.get_transport().set_keepalive(30)
                self.ssh_client = c
                self.shell = self.ssh_client.invoke_shell()
                self.shell.send("bind 'set enable-bracketed-paste off'\n")
                try:
                    self.sftp = self.ssh_client.open_sftp()
                    if hasattr(self, 'file_manager'):
                        self.file_manager.sftp = self.sftp
                except Exception as e:
                    self.display.appendPlainText(f"Failed to reopen SFTP: {e}\n")
                self.display.appendPlainText("Reconnected.\n")
        except Exception as e:
            self.display.appendPlainText(f"Error during reconnection check: {e}\n")
    def closeEvent(self, event):
        if hasattr(self, "file_manager") and self.file_manager and self.file_manager.transfer_manager.in_progress:
            r = QMessageBox.question(self,"Confirmation","Do you really want to close this page? There are ongoing file transfers.",QMessageBox.Yes|QMessageBox.No)
            if r==QMessageBox.No:
                event.ignore()
                return
            else:
                self.stop_transfers()
        if hasattr(self, "console_thread") and self.console_thread:
            self.console_thread.stop()
            self.console_thread.wait()
        try:
            self.ssh_client.close()
        except:
            pass
        event.accept()
    def stop_transfers(self):
        tm = self.file_manager.transfer_manager
        tm.cancel_all_transfers()
        QMessageBox.information(self, "Stopped", "All file transfers have been stopped.")

class ParametersPage(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.encryption_key = self.main_window.encryption_key
        l = QVBoxLayout(self)
        l.setAlignment(Qt.AlignTop)
        t = QLabel("Parameters")
        t.setFont(QFont("Arial",24))
        l.addWidget(t)
        password_frame = QFrame()
        password_frame.setStyleSheet("background-color: #1e1e1e; border-radius: 8px;")
        password_frame.setMinimumWidth(500)
        password_layout = QVBoxLayout(password_frame)
        lbl_password_title = QLabel("Change Dashboard Password")
        lbl_password_title.setFont(QFont("Arial",16))
        lbl_password_title.setStyleSheet("color: white; margin-bottom: 8px;")
        password_layout.addWidget(lbl_password_title)
        password_layout.addWidget(QLabel("New Password:"))
        self.new_pass_entry = QLineEdit()
        self.new_pass_entry.setEchoMode(QLineEdit.Password)
        self.new_pass_entry.setStyleSheet("background-color: #1e1e1e; color: white; padding: 5px; margin-bottom: 10px; min-height: 30px; border: none;")
        password_layout.addWidget(self.new_pass_entry)
        password_layout.addWidget(QLabel("Confirm Password:"))
        self.confirm_pass_entry = QLineEdit()
        self.confirm_pass_entry.setEchoMode(QLineEdit.Password)
        self.confirm_pass_entry.setStyleSheet("background-color: #1e1e1e; color: white; padding: 5px; margin-bottom: 10px; min-height: 30px; border: none;")
        password_layout.addWidget(self.confirm_pass_entry)
        btn_change = QPushButton("Change Password")
        btn_change.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white; padding: 8px 16px; border: none; border-radius: 4px;} QPushButton:hover { background-color: #007acc; }")
        bl = QHBoxLayout()
        bl.addStretch()
        bl.addWidget(btn_change)
        bl.addStretch()
        password_layout.addLayout(bl)
        btn_change.clicked.connect(self.change_password)
        l.addWidget(password_frame, alignment=Qt.AlignCenter)
        db_frame = QFrame()
        db_frame.setStyleSheet("background-color: #1e1e1e; border-radius: 8px;")
        db_frame.setMinimumWidth(500)
        db_layout = QVBoxLayout(db_frame)
        lbl_db_title = QLabel("Export / Import Dashboard Database")
        lbl_db_title.setFont(QFont("Arial",16))
        lbl_db_title.setStyleSheet("color: white; margin-bottom: 8px;")
        db_layout.addWidget(lbl_db_title)
        self.db_label = QLabel(f"{DB_FILE}")
        self.db_label.setStyleSheet("color: white; margin-bottom: 8px;")
        db_layout.addWidget(self.db_label)
        export_btn = QPushButton("Export")
        export_btn.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white; padding: 8px 16px; border: none; border-radius: 4px;} QPushButton:hover { background-color: #007acc; }")
        export_btn.clicked.connect(self.export_db)
        db_layout.addWidget(export_btn)
        import_btn = QPushButton("Import")
        import_btn.setStyleSheet("QPushButton {background-color: #1e1e1e; color: white; padding: 8px 16px; border: none; border-radius: 4px;} QPushButton:hover { background-color: #007acc; }")
        import_btn.clicked.connect(self.import_db)
        db_layout.addWidget(import_btn)
        l.addWidget(db_frame, alignment=Qt.AlignCenter)
        self.setLayout(l)
    def change_password(self):
        new_pass = self.new_pass_entry.text()
        confirm_pass = self.confirm_pass_entry.text()
        if not new_pass or not confirm_pass:
            QMessageBox.critical(self, "Error", "Please fill both fields.")
            return
        if new_pass!=confirm_pass:
            QMessageBox.critical(self, "Error", "Passwords do not match.")
            return
        QMessageBox.information(self, "Success", "Encryption password changed successfully.")
        self.new_pass_entry.clear()
        self.confirm_pass_entry.clear()
    def export_db(self):
        out_path,_ = QFileDialog.getSaveFileName(self, "Exporter la base de données", os.path.expanduser("~"), "All Files (*)")
        if out_path:
            if not os.path.exists(DB_FILE):
                QMessageBox.critical(self, "Error", "No local database file found to export!")
                return
            try:
                shutil.copy2(DB_FILE, out_path)
                QMessageBox.information(self, "Info", "Database export successful.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Export failed: {e}")
    def import_db(self):
        in_path,_ = QFileDialog.getOpenFileName(self, "Importer la base de données", os.path.expanduser("~"), "All Files (*)")
        if in_path:
            if is_encrypted(in_path):
                try:
                    decrypt_file(in_path, self.encryption_key, DB_FILE)
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Decryption failed: {e}")
                    return
            else:
                try:
                    shutil.copy2(in_path, DB_FILE)
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Import failed: {e}")
                    return
            db_manager.init_db()
            QMessageBox.information(self, "Info", "Database import successful. The new DB is now active.")

class MainWindow(QMainWindow):
    def __init__(self, encryption_key):
        super().__init__()
        self.encryption_key = encryption_key
        self.auto_connections = {}
        self.global_auto_connect_enabled = (db_manager.get_global_auto_connect() == 1)
        self.setWindowTitle("G_O_D")
        self.resize(900,600)
        cw = QWidget()
        self.setCentralWidget(cw)
        ml = QHBoxLayout(cw)
        sb = QVBoxLayout()
        bd = QPushButton("Dashboard")
        bd.setStyleSheet("max-width: 120px;")
        bd.clicked.connect(lambda: self.switch_page(self.dashboard_page))
        sb.addWidget(bd)
        bse = QPushButton("Servers")
        bse.setStyleSheet("max-width: 120px;")
        bse.clicked.connect(lambda: self.switch_page(ServersPage(self)))
        sb.addWidget(bse)
        bp = QPushButton("Parameters")
        bp.setStyleSheet("max-width: 120px;")
        bp.clicked.connect(lambda: self.switch_page(ParametersPage(self)))
        sb.addWidget(bp)
        sb.addStretch()
        ml.addLayout(sb)
        self.pages = QStackedWidget()
        self.dashboard_page = DashboardPage(self)
        self.pages.addWidget(self.dashboard_page)
        self.pages.addWidget(ServersPage(self))
        self.pages.addWidget(ParametersPage(self))
        ml.addWidget(self.pages)
        self.auto_connect_timer = QTimer(self)
        self.auto_connect_timer.timeout.connect(self.auto_connect_loop)
        self.update_auto_connect_indicator()
        if self.global_auto_connect_enabled:
            self.auto_connect_timer.start(2000)
    def switch_page(self, w):
        if self.pages.indexOf(w)==-1:
            self.pages.addWidget(w)
        self.pages.setCurrentWidget(w)
    def toggle_auto_connect(self, e):
        db_manager.update_global_auto_connect(1 if e else 0)
        self.global_auto_connect_enabled = e
        if e:
            self.auto_connect_timer.start(2000)
        else:
            self.auto_connect_timer.stop()
        self.update_auto_connect_indicator()
    def update_auto_connect_indicator(self):
        self.statusBar().setStyleSheet("color: white; background-color: #1e1e1e;")
        self.statusBar().showMessage(f"Auto-Connect: {'ON' if self.global_auto_connect_enabled else 'OFF'}")
    def auto_connect_loop(self):
        servers = db_manager.get_servers()
        ct = int(time.time())
        def connect_and_scan(s):
            (sid,name,host,port,user,pwd,lat,lon,oi,ac)=s
            if not self.global_auto_connect_enabled or ac!=1:
                return None
            c = self.auto_connections.get(sid)
            if c is None or not (c.get_transport() and c.get_transport().is_active()):
                try:
                    c2 = paramiko.SSHClient()
                    c2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    c2.connect(host, port=port, username=user, password=pwd, timeout=5)
                    self.auto_connections[sid] = c2
                except:
                    self.auto_connections[sid] = None
                    return (False,0,0)
            try:
                c3 = self.auto_connections[sid]
                stdin,stdout,stderr = c3.exec_command("ss -p | grep nginx | grep -i estab | wc -l")
                ng = int(stdout.read().decode().strip() or 0)
                stdin,stdout,stderr = c3.exec_command("ss -p | grep tor | grep -i estab | wc -l")
                to = int(stdout.read().decode().strip() or 0)
                return (True,ng,to)
            except:
                return (False,0,0)
        for s in servers:
            if not self.global_auto_connect_enabled or s[9]!=1:
                if self.dashboard_page.server_status_items.get(s[0]):
                    QTimer.singleShot(0, lambda sid=s[0],n=s[1]: self.dashboard_page.server_status_items[sid].setText(f"Server {n}: Disabled"))
        with concurrent.futures.ThreadPoolExecutor() as ex:
            fut = {ex.submit(connect_and_scan, s2): s2 for s2 in servers if s2[9]==1 and self.global_auto_connect_enabled}
            for fu in concurrent.futures.as_completed(fut):
                sv = fut[fu]
                sid = sv[0]
                r = fu.result()
                if r is None:
                    continue
                st,ng2,to2 = r
                if self.dashboard_page.server_status_items.get(sid):
                    txt = f"Server {sv[1]}: " + ("🟢" if st else "🔴") + f" (Nginx: {ng2}, Tor: {to2})"
                    QTimer.singleShot(0, lambda i=self.dashboard_page.server_status_items[sid],t=txt: i.setText(t))
                db_manager.add_stat(sid, ct, ng2, to2)
    def closeEvent(self, event):
        at = False
        cw = self.pages.currentWidget()
        if hasattr(cw, "transfer_manager") and cw.transfer_manager.in_progress:
            at = True
        elif hasattr(cw, "file_manager") and cw.file_manager.transfer_manager.in_progress:
            at = True
        if at:
            r = QMessageBox.question(self,"Confirmation","There are active transfers. Do you really want to exit?",QMessageBox.Yes|QMessageBox.No)
            if r==QMessageBox.No:
                event.ignore()
                return
        if os.path.exists(DB_FILE):
            try:
                encrypt_file(DB_FILE, self.encryption_key)
                os.remove(DB_FILE)
            except Exception as e:
                QMessageBox.critical(None, "Error", f"Encryption failed: {e}")
        event.accept()

if __name__=="__main__":
    s = load_or_create_salt()
    a = QApplication([])
    d = CustomLoginDialog()
    if d.exec_()==QDialog.Accepted:
        p = d.password_entry.text()
    else:
        QMessageBox.critical(None, "Error", "Password is required!")
        sys.exit(1)
    k = derive_key(p, s)
    if os.path.exists(ENC_DB_FILE):
        try:
            decrypt_file(ENC_DB_FILE, k, DB_FILE)
        except Exception as e:
            QMessageBox.critical(None, "Error", f"Decryption failed: {e}")
            sys.exit(1)
    db_manager.init_db()
    w = MainWindow(k)
    w.show()
    a.exec_()