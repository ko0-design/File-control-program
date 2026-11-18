#!/usr/bin/env python3
"""
guard.py - Kiểm soát chương trình khi chạy (1 file duy nhất, có giao diện + dòng lệnh)

Xem chương trình đó đọc/ghi file nào, kết nối mạng đi đâu, tạo tiến trình con nào,
và CẮT QUYỀN: chặn mạng / ghi file / tiến trình con, giới hạn thời gian và RAM, kill hoặc đóng băng.

CÁCH DÙNG
  python guard.py                    mở cửa sổ có menu (khuyên dùng)
  python guard.py C:\\app.exe         mở cửa sổ, điền sẵn chương trình
  python guard.py run [tuỳ chọn] -- chuong_trinh [tham_so...]      chạy bằng dòng lệnh

Khuyến nghị:  pip install psutil
  (cần để xem file/kết nối của .exe, Tạm dừng / Tiếp tục, Dừng an toàn)
Chặn mạng cho .exe bằng Windows Firewall cần mở bằng quyền Administrator.

TUỲ CHỌN DÒNG LỆNH (sau "run")
  --no-net            cấm kết nối mạng
  --no-write          cấm ghi/xoá file (trừ thư mục cho phép bằng --allow-write)
  --allow-write DIR   thư mục được phép ghi (dùng nhiều lần)
  --no-child          cấm tạo tiến trình con
  --kill              vi phạm là kill luôn (mặc định chỉ chặn + ghi log)
  --timeout GIÂY      tự kill sau N giây
  --mem MB            giới hạn RAM (Windows, Job Object)
  --log FILE          file log JSON-lines (mặc định guard.log.jsonl)
  --quiet             không in log ra màn hình (giao diện dùng cờ này)

Ví dụ:
  python guard.py run --no-net --no-child -- python script.py
  python guard.py run --no-net --kill -- C:\\Downloads\\app.exe
  python guard.py run --no-write --allow-write C:\\temp -- python tool.py

Lưu ý: --no-write / --allow-write chỉ có tác dụng với file .py.
       Với .exe/.jar, Windows không cho chặn ghi file theo từng chương trình ở mức này.
"""

import argparse
import json
import os
import queue
import runpy
import shlex
import shutil
import subprocess
import sys
import threading
import time

IS_WIN = os.name == "nt"
try:
    import psutil  # tuỳ chọn: giám sát sâu exe/java
except ImportError:
    psutil = None

try:  # chỉ cần cho giao diện; chế độ dòng lệnh vẫn chạy khi thiếu tkinter
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except ImportError:
    tk = None

# ------------------------------------------------------------------ log
_lock = threading.Lock()
_logf = None
_quiet = False  # --quiet: không in ra stderr (dùng cho giao diện, chỉ ghi file log)


def log(kind, **data):
    rec = {"t": time.strftime("%H:%M:%S"), "event": kind, **data}
    line = json.dumps(rec, ensure_ascii=False, default=str)
    with _lock:
        if _logf:
            _logf.write(line + "\n")
            _logf.flush()
    if _quiet:
        return
    tag = "BLOCK" if data.get("blocked") else "     "
    print(f"[guard]{tag} {kind}: " + ", ".join(f"{k}={v}" for k, v in data.items() if k != "blocked"),
          file=sys.stderr)


# ------------------------------------------------------------------ chế độ Python (audit hook, chặn thật sự)
def _under(p, roots):
    """p nằm trong một trong các thư mục roots? (so khớp theo ranh giới thư mục, không theo tiền tố chuỗi)"""
    return any(p == r or p.startswith(r.rstrip("\\/") + os.sep) for r in roots)


def python_mode(policy, script, args):
    """Chạy script .py trong chính tiến trình này với audit hook: thấy và CHẶN được ngay trước khi xảy ra."""
    global _logf, _quiet
    _quiet = bool(policy.get("quiet"))
    _logf = open(policy["log"], "a", encoding="utf-8")
    guard_log = os.path.abspath(policy["log"])
    skip_roots = tuple(os.path.normcase(os.path.abspath(p)) for p in {sys.prefix, sys.base_prefix})
    allow = tuple(os.path.normcase(os.path.abspath(p)) for p in policy["allow_write"])
    busy = threading.local()
    seen_reads = set()

    def deny(kind, **d):
        log(kind, blocked=True, **d)
        if policy["kill"]:
            os._exit(99)
        raise PermissionError(f"guard: {kind} bị chặn")

    def hook(event, a):
        if getattr(busy, "on", False):
            return
        busy.on = True
        try:
            if event == "open":
                path, mode, flags = a
                if not isinstance(path, (str, bytes, os.PathLike)):
                    return
                p = os.path.normcase(os.path.abspath(os.fsdecode(path)))
                if p == os.path.normcase(guard_log) or _under(p, skip_roots):
                    return
                m = mode or ""
                is_w = any(c in m for c in "wax+") or bool((flags or 0) & (os.O_WRONLY | os.O_RDWR | os.O_CREAT))
                if is_w:
                    if policy["no_write"] and not _under(p, allow):
                        deny("file.write", path=p)
                    log("file.write", path=p)
                elif p not in seen_reads:
                    seen_reads.add(p)
                    log("file.read", path=p)
            elif event in ("os.remove", "os.rmdir", "os.rename", "shutil.rmtree", "shutil.move"):
                p = os.path.normcase(os.path.abspath(os.fsdecode(a[0])))
                if policy["no_write"] and not _under(p, allow):
                    deny("file.delete_or_move", path=p, op=event)
                log("file.delete_or_move", path=p, op=event)
            elif event in ("socket.connect", "socket.bind", "socket.getaddrinfo", "socket.sendto"):
                target = f"{a[0]}:{a[1]}" if event == "socket.getaddrinfo" else (a[1] if len(a) > 1 else a)
                if policy["no_net"]:
                    deny("net", op=event, target=target)
                log("net", op=event, target=target)
            elif event in ("subprocess.Popen", "os.system", "os.exec", "os.spawn", "os.posix_spawn"):
                if policy["no_child"]:
                    deny("process.spawn", op=event, args=a)
                log("process.spawn", op=event, args=a)
            elif event.startswith("winreg.") or event in ("ctypes.dlopen", "ctypes.cdata"):
                log("system", op=event, args=a[:2] if isinstance(a, tuple) else a)
        finally:
            busy.on = False

    sys.addaudithook(hook)
    sys.argv = [script] + args
    log("start", target=script, mode="python-audit")
    runpy.run_path(script, run_name="__main__")


# ------------------------------------------------------------------ Windows Job Object (giới hạn cứng từ hệ điều hành)
def make_job(no_child, mem_mb):
    if not IS_WIN:
        return None
    import ctypes
    from ctypes import wintypes as w

    class IO(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in
                    ("ro", "wo", "oo", "rt", "wt", "ot")]

    class BASIC(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                    ("LimitFlags", w.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", w.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", w.DWORD), ("SchedulingClass", w.DWORD)]

    class EXT(ctypes.Structure):
        _fields_ = [("Basic", BASIC), ("Io", IO), ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]

    k = ctypes.windll.kernel32
    k.CreateJobObjectW.restype = w.HANDLE
    job = k.CreateJobObjectW(None, None)
    info = EXT()
    flags = 0x2000  # KILL_ON_JOB_CLOSE: guard thoát thì mọi tiến trình con chết theo
    if no_child:
        flags |= 0x8  # ACTIVE_PROCESS
        info.Basic.ActiveProcessLimit = 1
    if mem_mb:
        flags |= 0x100  # PROCESS_MEMORY
        info.ProcessMemoryLimit = mem_mb * 1024 * 1024
    info.Basic.LimitFlags = flags
    k.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info))
    return job


def assign_job(job, proc):
    if job:
        import ctypes
        ctypes.windll.kernel32.AssignProcessToJobObject(job, int(proc._handle))


# ------------------------------------------------------------------ chặn mạng theo file bằng Windows Firewall
def fw_block(exe, name):
    if not IS_WIN:
        return False
    r = subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=out",
                        "action=block", f"program={exe}", "enable=yes"], capture_output=True, text=True)
    r2 = subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=in",
                         "action=block", f"program={exe}", "enable=yes"], capture_output=True, text=True)
    ok = r.returncode == 0 and r2.returncode == 0
    if not ok:
        log("warn", msg="Không tạo được rule Firewall (cần chạy bằng quyền Administrator).")
    return ok


def fw_unblock(name):
    if IS_WIN:
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
                       capture_output=True)


# ------------------------------------------------------------------ chế độ giám sát tiến trình ngoài (exe/java/...)
def monitor(proc, policy, stop):
    if not psutil:
        log("warn", msg="Chưa cài psutil nên không xem được file/kết nối của exe. Cài: pip install psutil")
        return
    seen = set()
    try:
        root = psutil.Process(proc.pid)
    except psutil.Error:
        return
    while not stop.is_set():
        try:
            procs = [root] + root.children(recursive=True)
        except psutil.Error:
            break
        for p in procs:
            try:
                key = ("proc", p.pid)
                if key not in seen and p.pid != root.pid:
                    seen.add(key)
                    bad = policy["no_child"]
                    log("process.spawn", pid=p.pid, name=p.name(), cmd=" ".join(p.cmdline())[:200], blocked=bad)
                    if bad:
                        p.kill()
                for f in p.open_files():
                    k = ("file", f.path)
                    if k not in seen:
                        seen.add(k)
                        log("file.open", pid=p.pid, path=f.path)
                for c in p.net_connections(kind="inet"):
                    if c.raddr:
                        k = ("net", c.raddr.ip, c.raddr.port)
                        if k not in seen:
                            seen.add(k)
                            bad = policy["no_net"]
                            log("net.connect", pid=p.pid, to=f"{c.raddr.ip}:{c.raddr.port}", status=c.status, blocked=bad)
                            if bad:
                                if policy["kill"]:
                                    for q in procs:
                                        q.kill()
                                else:
                                    p.suspend()  # đóng băng, không cho gửi thêm dữ liệu
                                    log("suspended", pid=p.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        time.sleep(0.3)


def build_cmd(target, args):
    ext = os.path.splitext(target)[1].lower()
    if ext == ".jar":
        return ["java", "-jar", target] + args
    return [target] + args


def cli_main():
    global _logf, _quiet
    ap = argparse.ArgumentParser(add_help=True)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--no-net", action="store_true")
    r.add_argument("--no-write", action="store_true")
    r.add_argument("--allow-write", action="append", default=[])
    r.add_argument("--no-child", action="store_true")
    r.add_argument("--kill", action="store_true")
    r.add_argument("--timeout", type=int, default=0)
    r.add_argument("--mem", type=int, default=0)
    r.add_argument("--log", default="guard.log.jsonl")
    r.add_argument("--quiet", action="store_true", help="không in log ra màn hình (chỉ ghi file)")
    r.add_argument("cmd_line", nargs=argparse.REMAINDER)
    ns = ap.parse_args()

    cl = [x for x in ns.cmd_line if x != "--"] if ns.cmd_line and ns.cmd_line[0] == "--" else ns.cmd_line
    if not cl:
        ap.error("thiếu chương trình cần chạy sau dấu --")
    _quiet = ns.quiet
    policy = dict(no_net=ns.no_net, no_write=ns.no_write, allow_write=ns.allow_write,
                  no_child=ns.no_child, kill=ns.kill, log=ns.log, quiet=ns.quiet)
    target, args = cl[0], cl[1:]

    # .py (hoặc "python x.py"): dùng audit hook trong chính tiến trình con -> chặn thật sự
    if os.path.basename(target).lower().startswith("python") and args and args[0].lower().endswith(".py"):
        target, args = args[0], args[1:]
    if target.lower().endswith(".py"):
        if os.environ.get("GUARD_INNER") != "1":
            env = dict(os.environ, GUARD_INNER="1", GUARD_POLICY=json.dumps(policy))
            code = subprocess.call([sys.executable, os.path.abspath(__file__), "_py", target] + args, env=env)
            sys.exit(code)
    # --- chế độ ngoài
    _logf = open(ns.log, "a", encoding="utf-8")
    cmd = build_cmd(target, args)
    log("start", target=" ".join(cmd), mode="process-monitor", psutil=bool(psutil))
    fw_name = f"guard-{os.getpid()}"
    fw_on = False
    if ns.no_net:
        exe = os.path.abspath(cmd[0]) if os.path.exists(cmd[0]) else __import__("shutil").which(cmd[0])
        if exe:
            fw_on = fw_block(exe, fw_name)
            log("firewall", program=exe, blocked=fw_on)
    job = make_job(ns.no_child, ns.mem)
    proc = subprocess.Popen(cmd)
    assign_job(job, proc)
    stop = threading.Event()
    threading.Thread(target=monitor, args=(proc, policy, stop), daemon=True).start()
    try:
        proc.wait(timeout=ns.timeout or None)
    except subprocess.TimeoutExpired:
        log("timeout", seconds=ns.timeout, blocked=True)
        proc.kill()
    except KeyboardInterrupt:
        proc.kill()
    finally:
        stop.set()
        if fw_on:
            fw_unblock(fw_name)
        log("exit", code=proc.returncode)


# ======================================================================
#  Giao diện: hằng số và cấu hình
# ======================================================================
GUARD = os.path.abspath(__file__)  # giao diện tự gọi lại chính file này ở chế độ dòng lệnh
HOME = os.path.expanduser("~")
CONF = os.path.join(HOME, ".guard_gui.json")
LOGDIR = os.path.join(HOME, "guard_logs")
NO_WINDOW = 0x08000000  # CREATE_NO_WINDOW (Windows)

PRESETS = {
    "Chỉ giám sát (không chặn gì)": dict(no_net=False, no_write=False, no_child=False, kill=False),
    "Chặn mạng": dict(no_net=True, no_write=False, no_child=False, kill=False),
    "Cô lập (mạng + ghi file + tiến trình con)": dict(no_net=True, no_write=True, no_child=True, kill=False),
    "Cô lập và kill khi vi phạm": dict(no_net=True, no_write=True, no_child=True, kill=True),
}

CAT_VN = {"file": "File", "net": "Mạng", "proc": "Tiến trình", "other": "Hệ thống"}
FILTERS = ["Tất cả", "Chỉ bị chặn", "File", "Mạng", "Tiến trình", "Hệ thống"]

HELP_TEXT = """CÁCH DÙNG
1. Chọn chương trình (.exe / .py / .jar ...) ở ô trên cùng, thêm tham số nếu cần.
2. Tick những quyền muốn CẤM, rồi bấm Chạy (F5).
3. Bảng "Nhật ký giám sát" hiện trực tiếp chương trình đọc/ghi file nào, kết nối tới đâu,
   tạo tiến trình con nào. Dòng đỏ = đã bị chặn.
4. Menu Chạy: Tạm dừng (đóng băng), Tiếp tục, Dừng (kill).
5. Menu Hồ sơ: chọn nhanh bộ quyền hoặc lưu / nạp bộ quyền của riêng bạn.

CÁI GÌ CHẶN ĐƯỢC THẬT
- File .py: chặn ngay trước khi hành động xảy ra (mạng, ghi/xoá file, tiến trình con).
- .exe / .jar:
    + Cấm mạng  -> tạo rule Windows Firewall riêng cho file đó (cần mở bằng quyền Administrator).
                   Không có quyền Admin thì chỉ phát hiện rồi đóng băng/kill, có thể lọt vài gói đầu.
    + Cấm tiến trình con -> bị kill ngay khi xuất hiện.
    + Cấm ghi file KHÔNG áp dụng cho .exe/.jar (chỉ xem được danh sách file đang mở).
- Giám sát .exe kiểm tra 0,3 giây một lần nên có thể bỏ sót thao tác cực ngắn.

LƯU Ý
- Chương trình chạy không có bàn phím (không nhập được dữ liệu từ cửa sổ này).
- Mã độc cố tình né (ctypes, code native...) vẫn có thể vượt qua chế độ .py.
  File nghi ngờ nặng: chạy trong Windows Sandbox hoặc máy ảo.
- Nhật ký lưu tại: """ + LOGDIR


# ======================================================================
#  Phần lõi (không phụ thuộc tkinter)
# ======================================================================
def py_exe():
    exe = sys.executable
    if IS_WIN and exe.lower().endswith("pythonw.exe"):
        cand = exe[:-len("pythonw.exe")] + "python.exe"
        if os.path.exists(cand):
            return cand
    return exe


def split_args(text):
    if not text.strip():
        return []
    out = []
    for t in shlex.split(text, posix=not IS_WIN):
        if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'":
            t = t[1:-1]
        out.append(t)
    return out


def is_py_target(prog, args):
    """Giống cách guard.py quyết định dùng chế độ .py (chặn thật sự)."""
    b = os.path.basename(prog.strip().strip('"')).lower()
    if b.endswith(".py"):
        return True
    if b.startswith("python"):
        return bool(args) and args[0].lower().endswith(".py")
    return False


def build_command(prog, args, o, logpath):
    cmd = [py_exe(), GUARD, "run", "--quiet", "--log", logpath]
    if o.get("no_net"):
        cmd.append("--no-net")
    if o.get("no_child"):
        cmd.append("--no-child")
    if o.get("kill"):
        cmd.append("--kill")
    if o.get("no_write") and is_py_target(prog, args):
        cmd.append("--no-write")
        for d in o.get("allow_write", []):
            cmd += ["--allow-write", d]
    if int(o.get("timeout") or 0) > 0:
        cmd += ["--timeout", str(int(o["timeout"]))]
    if int(o.get("mem") or 0) > 0:
        cmd += ["--mem", str(int(o["mem"]))]
    return cmd + ["--", prog] + list(args)


def event_to_row(ev):
    name = str(ev.get("event", ""))
    if name.startswith("file"):
        cat = "file"
    elif name.startswith("net"):
        cat = "net"
    elif name.startswith("process"):
        cat = "proc"
    else:
        cat = "other"
    blocked = bool(ev.get("blocked"))
    skip = {"t", "event", "blocked"}
    detail = "  ".join(f"{k}={v}" for k, v in ev.items() if k not in skip)
    if blocked:
        res, tag = "BỊ CHẶN", "blocked"
    elif name in ("warn", "suspended", "timeout"):
        res, tag = {"warn": "Cảnh báo", "suspended": "Đã đóng băng", "timeout": "Hết giờ"}[name], "warn"
    else:
        res, tag = "", ""
    return dict(t=ev.get("t", ""), cat=cat, cat_vn=CAT_VN[cat], event=name, detail=detail,
                res=res, tag=tag, blocked=blocked)


class Runner:
    """Chạy guard.py như tiến trình con; sự kiện / đầu ra được đẩy vào self.q."""

    def __init__(self):
        self.q = queue.Queue()      # ("ev", dict) | ("out", str) | ("done", int)
        self.proc = None
        self.logpath = None
        self.paused = False
        self.user_stopped = False

    @property
    def running(self):
        return self.proc is not None

    def start(self, prog, args_text, opts):
        if self.proc:
            raise RuntimeError("Đang có chương trình chạy.")
        prog = prog.strip().strip('"')
        if not prog:
            raise ValueError("Chưa chọn chương trình.")
        if os.path.exists(prog):
            prog = os.path.abspath(prog)
        elif not shutil.which(prog):
            raise ValueError(f"Không tìm thấy: {prog}")
        try:
            args = split_args(args_text)
        except ValueError as e:
            raise ValueError(f"Tham số sai cú pháp: {e}")

        os.makedirs(LOGDIR, exist_ok=True)
        ms = int(time.time() * 1000) % 1000
        self.logpath = os.path.join(LOGDIR, time.strftime("guard-%Y%m%d-%H%M%S") + f"-{ms:03d}.jsonl")
        cmd = build_command(prog, args, opts, self.logpath)

        kw = {}
        if IS_WIN:
            kw["creationflags"] = NO_WINDOW
        else:
            kw["start_new_session"] = True
        env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")
        self.user_stopped = False
        self.paused = False
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, env=env, **kw)
        self.proc = proc
        stop_tail = threading.Event()
        reader = threading.Thread(target=self._read_out, args=(proc,), daemon=True)
        tailer = threading.Thread(target=self._tail, args=(self.logpath, stop_tail), daemon=True)
        waiter = threading.Thread(target=self._wait, args=(proc, reader, tailer, stop_tail), daemon=True)
        reader.start()
        tailer.start()
        waiter.start()
        return cmd

    # ---- luồng nền
    def _read_out(self, proc):
        for raw in iter(proc.stdout.readline, b""):
            self.q.put(("out", raw.decode("utf-8", "replace")))

    def _tail(self, path, stop):
        while not os.path.exists(path):
            if stop.is_set():
                return
            time.sleep(0.05)
        buf = ""
        with open(path, encoding="utf-8", errors="replace") as f:
            while True:
                chunk = f.read()
                if chunk:
                    buf += chunk
                    *lines, buf = buf.split("\n")
                    for ln in lines:
                        if ln.strip():
                            try:
                                self.q.put(("ev", json.loads(ln)))
                            except ValueError:
                                pass
                elif stop.is_set():
                    break
                else:
                    time.sleep(0.1)

    def _wait(self, proc, reader, tailer, stop_tail):
        code = proc.wait()
        reader.join(1.5)
        time.sleep(0.3)
        stop_tail.set()
        tailer.join(2)
        self.proc = None
        self.paused = False
        self.q.put(("done", code))

    # ---- điều khiển
    def descendants(self):
        p = self.proc
        if not (psutil and p):
            return []
        try:
            return psutil.Process(p.pid).children(recursive=True)
        except psutil.Error:
            return []

    def pause(self):
        if not psutil:
            return False
        n = 0
        for c in self.descendants():
            try:
                c.suspend()
                n += 1
            except psutil.Error:
                pass
        self.paused = n > 0
        return self.paused

    def resume(self):
        if not psutil:
            return False
        for c in self.descendants():
            try:
                c.resume()
            except psutil.Error:
                pass
        self.paused = False
        return True

    def stop(self):
        """Có psutil: kill chương trình đích và để guard tự thoát (nó sẽ dọn rule Firewall).
        Sau 4 giây guard còn sống thì kill luôn. Không có psutil: kill cả cây."""
        p = self.proc
        if not p:
            return
        self.user_stopped = True
        if psutil:
            for c in self.descendants():
                try:
                    c.kill()
                except psutil.Error:
                    pass
            t = threading.Timer(4.0, self._force, args=(p,))
            t.daemon = True
            t.start()
        else:
            self._hard_kill(p)

    def _force(self, p):
        if p.poll() is None:
            self._hard_kill(p)

    @staticmethod
    def _hard_kill(p):
        try:
            if IS_WIN:
                subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"],
                               capture_output=True, creationflags=NO_WINDOW)
            else:
                import signal
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass


def load_conf():
    try:
        with open(CONF, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_conf(d):
    try:
        with open(CONF, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=1)
    except OSError:
        pass


# ======================================================================
#  Giao diện
# ======================================================================
if tk is not None:

    class App(tk.Tk):
        # chỉ số các mục trong menu "Chạy"
        M_RUN, M_PAUSE, M_RESUME, M_STOP = 0, 1, 2, 3

        def __init__(self, first_path=None):
            super().__init__()
            self.title("Guard - Kiểm soát chương trình")
            self.geometry("1000x720")
            self.minsize(840, 580)
            self.runner = Runner()
            self.conf = load_conf()
            self.rows = []
            self.counts = dict(file=0, net=0, proc=0, blocked=0)
            self.status = tk.StringVar(value="Sẵn sàng.")
            self.stats = tk.StringVar()
            self._closing_tries = 0

            self.prog = tk.StringVar()
            self.args = tk.StringVar()
            self.no_net = tk.BooleanVar(value=False)
            self.no_write = tk.BooleanVar(value=False)
            self.no_child = tk.BooleanVar(value=False)
            self.kill = tk.BooleanVar(value=False)
            self.timeout = tk.IntVar(value=0)
            self.mem = tk.IntVar(value=0)
            self.filter = tk.StringVar(value=FILTERS[0])

            self._build_menu()
            self._build_ui()
            self._load_conf()
            if first_path:
                self.prog.set(first_path)
            self.prog.trace_add("write", lambda *a: self._refresh_state())
            self.args.trace_add("write", lambda *a: self._refresh_state())
            self.filter.trace_add("write", lambda *a: self._refill())
            self._update_stats()
            self._refresh_state()
            self.protocol("WM_DELETE_WINDOW", self.on_close)
            self.bind_all("<F5>", lambda e: self.run())
            self.bind_all("<Control-o>", lambda e: self.choose_prog())
            self.after(100, self._poll)
            if not psutil:
                self.status.set("Chưa cài psutil: không xem được file/kết nối của .exe, "
                                "không Tạm dừng được. Cài bằng:  pip install psutil")

        # ------------------------------------------------------------ menu
        def _build_menu(self):
            bar = tk.Menu(self)
            self.config(menu=bar)

            m = tk.Menu(bar, tearoff=0)
            bar.add_cascade(label="Tệp", menu=m)
            m.add_command(label="Chọn chương trình…", accelerator="Ctrl+O", command=self.choose_prog)
            m.add_command(label="Xuất nhật ký…", command=self.export_log)
            m.add_command(label="Mở thư mục nhật ký", command=self.open_logdir)
            m.add_separator()
            m.add_command(label="Thoát", command=self.on_close)

            self.m_run = tk.Menu(bar, tearoff=0)
            bar.add_cascade(label="Chạy", menu=self.m_run)
            self.m_run.add_command(label="Chạy", accelerator="F5", command=self.run)
            self.m_run.add_command(label="Tạm dừng (đóng băng)", command=self.pause)
            self.m_run.add_command(label="Tiếp tục", command=self.resume)
            self.m_run.add_command(label="Dừng (kill)", command=self.stop)
            self.m_run.add_separator()
            self.m_run.add_command(label="Xoá nhật ký trên màn hình", command=self.clear_log)

            m = tk.Menu(bar, tearoff=0)
            bar.add_cascade(label="Hồ sơ quyền", menu=m)
            for name in PRESETS:
                m.add_command(label=name, command=lambda n=name: self.apply_preset(n))
            m.add_separator()
            m.add_command(label="Lưu hồ sơ hiện tại…", command=self.save_profile)
            m.add_command(label="Nạp hồ sơ…", command=self.load_profile)

            m = tk.Menu(bar, tearoff=0)
            bar.add_cascade(label="Công cụ", menu=m)
            m.add_command(label="Dọn rule Firewall còn sót (Windows)", command=self.cleanup_firewall)

            m = tk.Menu(bar, tearoff=0)
            bar.add_cascade(label="Trợ giúp", menu=m)
            m.add_command(label="Hướng dẫn và giới hạn", command=self.show_help)

        # ------------------------------------------------------------ bố cục
        def _build_ui(self):
            top = ttk.LabelFrame(self, text="Chương trình cần kiểm soát", padding=8)
            top.pack(fill="x", padx=10, pady=(10, 4))
            top.columnconfigure(1, weight=1)
            ttk.Label(top, text="Chương trình:").grid(row=0, column=0, sticky="w")
            self.cb_prog = ttk.Combobox(top, textvariable=self.prog)
            self.cb_prog.grid(row=0, column=1, sticky="ew", padx=6)
            ttk.Button(top, text="Chọn…", command=self.choose_prog).grid(row=0, column=2)
            ttk.Label(top, text="Tham số:").grid(row=1, column=0, sticky="w", pady=(6, 0))
            ttk.Entry(top, textvariable=self.args).grid(row=1, column=1, columnspan=2,
                                                        sticky="ew", padx=6, pady=(6, 0))

            perm = ttk.LabelFrame(self, text="Quyền  (tick = CẤM)", padding=8)
            perm.pack(fill="x", padx=10, pady=4)
            perm.columnconfigure(1, weight=1)
            left = ttk.Frame(perm)
            left.grid(row=0, column=0, sticky="nw")
            ttk.Checkbutton(left, text="Cấm kết nối mạng", variable=self.no_net).pack(anchor="w")
            ttk.Checkbutton(left, text="Cấm tạo tiến trình con", variable=self.no_child).pack(anchor="w")
            self.chk_write = ttk.Checkbutton(left, text="Cấm ghi / xoá file  (chỉ áp dụng cho .py)",
                                             variable=self.no_write)
            self.chk_write.pack(anchor="w")
            ttk.Checkbutton(left, text="Vi phạm là kill ngay (không tick: chỉ chặn / đóng băng)",
                            variable=self.kill).pack(anchor="w")

            right = ttk.Frame(perm)
            right.grid(row=0, column=1, sticky="nsew", padx=(24, 0))
            right.columnconfigure(0, weight=1)
            ttk.Label(right, text="Thư mục ĐƯỢC PHÉP ghi (khi cấm ghi file, chỉ .py):").grid(
                row=0, column=0, columnspan=2, sticky="w")
            self.lst = tk.Listbox(right, height=3, exportselection=False)
            self.lst.grid(row=1, column=0, rowspan=2, sticky="ew")
            self.btn_add = ttk.Button(right, text="Thêm…", command=self.add_dir)
            self.btn_add.grid(row=1, column=1, padx=(6, 0), sticky="ew")
            self.btn_del = ttk.Button(right, text="Bỏ", command=self.del_dir)
            self.btn_del.grid(row=2, column=1, padx=(6, 0), sticky="ew")

            lim = ttk.Frame(perm)
            lim.grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))
            ttk.Label(lim, text="Tự kill sau (giây, 0 = không):").pack(side="left")
            ttk.Spinbox(lim, from_=0, to=86400, width=7, textvariable=self.timeout).pack(side="left", padx=(4, 18))
            ttk.Label(lim, text="RAM tối đa (MB, 0 = không, chỉ Windows):").pack(side="left")
            ttk.Spinbox(lim, from_=0, to=262144, width=7, textvariable=self.mem).pack(side="left", padx=4)

            btns = ttk.Frame(self)
            btns.pack(fill="x", padx=10, pady=6)
            self.btn_run = ttk.Button(btns, text="▶  Chạy (F5)", command=self.run)
            self.btn_run.pack(side="left")
            self.btn_pause = ttk.Button(btns, text="Tạm dừng", command=self.pause)
            self.btn_pause.pack(side="left", padx=6)
            self.btn_resume = ttk.Button(btns, text="Tiếp tục", command=self.resume)
            self.btn_resume.pack(side="left")
            self.btn_stop = ttk.Button(btns, text="■  Dừng", command=self.stop)
            self.btn_stop.pack(side="left", padx=6)
            ttk.Label(btns, textvariable=self.stats).pack(side="right")

            ttk.Label(self, textvariable=self.status, relief="sunken", anchor="w",
                      padding=(6, 2)).pack(fill="x", side="bottom")

            nb = ttk.Notebook(self)
            nb.pack(fill="both", expand=True, padx=10, pady=(0, 4))

            tab1 = ttk.Frame(nb)
            nb.add(tab1, text="Nhật ký giám sát")
            fbar = ttk.Frame(tab1)
            fbar.pack(fill="x", pady=(4, 2))
            ttk.Label(fbar, text="Lọc:").pack(side="left", padx=(4, 4))
            ttk.Combobox(fbar, textvariable=self.filter, values=FILTERS, state="readonly",
                         width=14).pack(side="left")
            cols = ("t", "cat", "event", "detail", "res")
            self.tree = ttk.Treeview(tab1, columns=cols, show="headings", selectmode="browse")
            for c, text, w in (("t", "Giờ", 70), ("cat", "Loại", 90), ("event", "Sự kiện", 130),
                               ("detail", "Chi tiết", 560), ("res", "Kết quả", 100)):
                self.tree.heading(c, text=text)
                self.tree.column(c, width=w, anchor="w", stretch=(c == "detail"))
            self.tree.tag_configure("blocked", background="#ffd6d6")
            self.tree.tag_configure("warn", background="#fff0c2")
            sb = ttk.Scrollbar(tab1, orient="vertical", command=self.tree.yview)
            self.tree.configure(yscrollcommand=sb.set)
            sb.pack(side="right", fill="y")
            self.tree.pack(fill="both", expand=True)
            self.tree.bind("<Control-c>", self._copy_row)
            self.tree.bind("<Double-1>", self._copy_row)

            tab2 = ttk.Frame(nb)
            nb.add(tab2, text="Đầu ra của chương trình")
            self.out = tk.Text(tab2, wrap="word", state="disabled", height=10)
            sb2 = ttk.Scrollbar(tab2, orient="vertical", command=self.out.yview)
            self.out.configure(yscrollcommand=sb2.set)
            sb2.pack(side="right", fill="y")
            self.out.pack(fill="both", expand=True)


        # ------------------------------------------------------------ tuỳ chọn
        @staticmethod
        def _int(var):
            try:
                return max(0, int(var.get()))
            except (tk.TclError, ValueError):
                return 0

        def get_opts(self):
            return dict(no_net=self.no_net.get(), no_write=self.no_write.get(),
                        no_child=self.no_child.get(), kill=self.kill.get(),
                        timeout=self._int(self.timeout), mem=self._int(self.mem),
                        allow_write=list(self.lst.get(0, "end")))

        def set_opts(self, o):
            self.no_net.set(bool(o.get("no_net")))
            self.no_write.set(bool(o.get("no_write")))
            self.no_child.set(bool(o.get("no_child")))
            self.kill.set(bool(o.get("kill")))
            if "timeout" in o:
                self.timeout.set(int(o.get("timeout") or 0))
            if "mem" in o:
                self.mem.set(int(o.get("mem") or 0))
            if "allow_write" in o:
                self.lst.delete(0, "end")
                for d in o["allow_write"]:
                    self.lst.insert("end", d)

        def apply_preset(self, name):
            self.set_opts(PRESETS[name])
            self.status.set(f"Đã áp dụng hồ sơ: {name}")

        def save_profile(self):
            path = filedialog.asksaveasfilename(defaultextension=".json",
                                                filetypes=[("Hồ sơ Guard", "*.json")])
            if path:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(self.get_opts(), f, ensure_ascii=False, indent=1)
                self.status.set(f"Đã lưu hồ sơ: {path}")

        def load_profile(self):
            path = filedialog.askopenfilename(filetypes=[("Hồ sơ Guard", "*.json"), ("Tất cả", "*.*")])
            if not path:
                return
            try:
                with open(path, encoding="utf-8") as f:
                    self.set_opts(json.load(f))
                self.status.set(f"Đã nạp hồ sơ: {path}")
            except (OSError, ValueError) as e:
                messagebox.showerror("Không nạp được hồ sơ", str(e))

        def _load_conf(self):
            rec = self.conf.get("recent", [])
            self.cb_prog.configure(values=rec)
            if self.conf.get("opts"):
                self.set_opts(self.conf["opts"])

        def _save_conf(self):
            self.conf["opts"] = self.get_opts()
            save_conf(self.conf)

        def _remember(self, prog):
            rec = [p for p in self.conf.get("recent", []) if p != prog]
            self.conf["recent"] = ([prog] + rec)[:10]
            self.cb_prog.configure(values=self.conf["recent"])

        # ------------------------------------------------------------ chọn file
        def choose_prog(self):
            path = filedialog.askopenfilename(
                title="Chọn chương trình cần kiểm soát",
                filetypes=[("Chương trình", "*.exe *.py *.jar *.bat *.cmd"), ("Tất cả", "*.*")])
            if path:
                self.prog.set(path)

        def add_dir(self):
            d = filedialog.askdirectory(title="Thư mục được phép ghi")
            if d:
                self.lst.insert("end", d)

        def del_dir(self):
            for i in reversed(self.lst.curselection()):
                self.lst.delete(i)

        # ------------------------------------------------------------ chạy / điều khiển
        def run(self):
            if self.runner.running:
                return
            self.clear_log()
            try:
                args = split_args(self.args.get())
            except ValueError:
                args = []
            if self.no_write.get() and not is_py_target(self.prog.get(), args):
                self.status.set("Lưu ý: 'Cấm ghi file' bị bỏ qua vì đây không phải file .py.")
            try:
                self.runner.start(self.prog.get(), self.args.get(), self.get_opts())
            except (ValueError, RuntimeError, OSError) as e:
                messagebox.showerror("Không chạy được", str(e))
                return
            self._remember(self.prog.get().strip().strip('"'))
            self._save_conf()
            self.status.set("Đang chạy…")
            self._refresh_state()

        def pause(self):
            if not psutil:
                messagebox.showinfo("Cần psutil", "Cài bằng lệnh:  pip install psutil")
                return
            if self.runner.pause():
                self.status.set("Đã đóng băng chương trình. Chọn Chạy > Tiếp tục để chạy tiếp.")
            self._refresh_state()

        def resume(self):
            if self.runner.resume():
                self.status.set("Đang chạy…")
            self._refresh_state()

        def stop(self):
            if self.runner.running:
                self.status.set("Đang dừng…")
                self.runner.stop()

        def clear_log(self):
            self.rows = []
            self.counts = dict(file=0, net=0, proc=0, blocked=0)
            self.tree.delete(*self.tree.get_children())
            self.out.configure(state="normal")
            self.out.delete("1.0", "end")
            self.out.configure(state="disabled")
            self._update_stats()

        # ------------------------------------------------------------ nhận sự kiện
        def _poll(self):
            try:
                for _ in range(500):
                    kind, val = self.runner.q.get_nowait()
                    if kind == "ev":
                        self._on_event(val)
                    elif kind == "out":
                        self._on_out(val)
                    elif kind == "done":
                        self._on_done(val)
            except queue.Empty:
                pass
            finally:
                self.after(100, self._poll)

        def _passes(self, row):
            f = self.filter.get()
            if f == "Tất cả":
                return True
            if f == "Chỉ bị chặn":
                return row["blocked"]
            return row["cat_vn"] == f

        def _insert(self, row):
            self.tree.insert("", "end", tags=(row["tag"],) if row["tag"] else (),
                             values=(row["t"], row["cat_vn"], row["event"], row["detail"], row["res"]))

        def _on_event(self, ev):
            row = event_to_row(ev)
            self.rows.append(row)
            if row["cat"] in self.counts:
                self.counts[row["cat"]] += 1
            if row["blocked"]:
                self.counts["blocked"] += 1
            if self._passes(row):
                self._insert(row)
                kids = self.tree.get_children()
                if kids:
                    self.tree.see(kids[-1])
            self._update_stats()

        def _refill(self):
            self.tree.delete(*self.tree.get_children())
            for r in self.rows:
                if self._passes(r):
                    self._insert(r)

        def _on_out(self, line):
            self.out.configure(state="normal")
            self.out.insert("end", line)
            self.out.see("end")
            self.out.configure(state="disabled")

        def _on_done(self, code):
            if self.runner.user_stopped:
                msg = "Đã dừng theo yêu cầu."
            elif code == 99:
                msg = "Bị kill vì vi phạm chính sách (mã 99)."
            else:
                msg = f"Chương trình đã kết thúc (mã thoát {code})."
            self.status.set(msg)
            self.btn_run.focus_set()
            self._refresh_state()

        def _update_stats(self):
            c = self.counts
            self.stats.set(f"File: {c['file']}   Mạng: {c['net']}   Tiến trình: {c['proc']}   "
                           f"Bị chặn: {c['blocked']}")

        def _copy_row(self, _e=None):
            sel = self.tree.selection()
            if sel:
                v = self.tree.item(sel[0], "values")
                self.clipboard_clear()
                self.clipboard_append("\t".join(str(x) for x in v))
                self.status.set("Đã sao chép dòng vào clipboard.")

        # ------------------------------------------------------------ trạng thái nút / menu
        def _refresh_state(self):
            running = self.runner.running
            paused = self.runner.paused

            def st(ok):
                return "normal" if ok else "disabled"

            self.btn_run.configure(state=st(not running))
            self.btn_pause.configure(state=st(running and not paused))
            self.btn_resume.configure(state=st(running and paused))
            self.btn_stop.configure(state=st(running))
            self.m_run.entryconfigure(self.M_RUN, state=st(not running))
            self.m_run.entryconfigure(self.M_PAUSE, state=st(running and not paused))
            self.m_run.entryconfigure(self.M_RESUME, state=st(running and paused))
            self.m_run.entryconfigure(self.M_STOP, state=st(running))
            try:
                args = split_args(self.args.get())
            except ValueError:
                args = []
            py = is_py_target(self.prog.get(), args)
            self.chk_write.configure(state=st(py))
            self.btn_add.configure(state=st(py))
            self.btn_del.configure(state=st(py))

        # ------------------------------------------------------------ công cụ khác
        def export_log(self):
            if not self.rows:
                messagebox.showinfo("Trống", "Chưa có nhật ký để xuất.")
                return
            path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                filetypes=[("CSV", "*.csv"), ("JSON Lines", "*.jsonl")])
            if not path:
                return
            try:
                if path.lower().endswith(".jsonl"):
                    with open(path, "w", encoding="utf-8") as f:
                        for r in self.rows:
                            f.write(json.dumps(r, ensure_ascii=False) + "\n")
                else:
                    import csv
                    with open(path, "w", encoding="utf-8-sig", newline="") as f:
                        w = csv.writer(f)
                        w.writerow(["Giờ", "Loại", "Sự kiện", "Chi tiết", "Kết quả"])
                        for r in self.rows:
                            w.writerow([r["t"], r["cat_vn"], r["event"], r["detail"], r["res"]])
                self.status.set(f"Đã xuất nhật ký: {path}")
            except OSError as e:
                messagebox.showerror("Không xuất được", str(e))

        def open_logdir(self):
            os.makedirs(LOGDIR, exist_ok=True)
            try:
                if IS_WIN:
                    os.startfile(LOGDIR)
                elif sys.platform == "darwin":
                    subprocess.Popen(["open", LOGDIR])
                else:
                    subprocess.Popen(["xdg-open", LOGDIR])
            except OSError as e:
                messagebox.showerror("Không mở được", str(e))

        def cleanup_firewall(self):
            if not IS_WIN:
                messagebox.showinfo("Chỉ dành cho Windows", "Rule Firewall của Guard chỉ có trên Windows.")
                return
            if not messagebox.askyesno(
                    "Dọn rule Firewall",
                    "Xoá mọi rule Windows Firewall có tên bắt đầu bằng 'guard-' (do Guard tạo)?\n"
                    "Cần mở công cụ này bằng quyền Administrator."):
                return
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-NetFirewallRule -DisplayName 'guard-*' -ErrorAction SilentlyContinue | "
                 "Remove-NetFirewallRule"],
                capture_output=True, text=True, creationflags=NO_WINDOW)
            if r.returncode == 0:
                messagebox.showinfo("Xong", "Đã dọn các rule 'guard-*' (nếu có).")
            else:
                messagebox.showerror("Không dọn được", (r.stderr or "Cần quyền Administrator.")[:500])

        def show_help(self):
            w = tk.Toplevel(self)
            w.title("Hướng dẫn và giới hạn")
            w.geometry("720x560")
            t = tk.Text(w, wrap="word", padx=10, pady=10)
            t.insert("1.0", HELP_TEXT)
            t.configure(state="disabled")
            t.pack(fill="both", expand=True)

        def on_close(self):
            if self.runner.running:
                if not messagebox.askyesno("Đang chạy", "Chương trình đang chạy. Dừng nó và thoát?"):
                    return
                self.runner.stop()
                self._closing_tries = 0
                self._wait_close()
            else:
                self._save_conf()
                self.destroy()

        def _wait_close(self):
            self._closing_tries += 1
            if self.runner.running and self._closing_tries < 30:
                self.after(200, self._wait_close)
            else:
                self._save_conf()
                self.destroy()


def gui_main():
    if tk is None:
        print("Python của bạn thiếu tkinter nên không mở được cửa sổ.\n"
              "Windows: cài lại Python từ python.org (tick 'tcl/tk and IDLE').\n"
              "Vẫn có thể dùng bản dòng lệnh:  python guard.py run --help")
        sys.exit(1)
    if IS_WIN:
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)  # chữ nét hơn trên màn hình độ phân giải cao
        except Exception:
            pass
    first = sys.argv[1] if len(sys.argv) > 1 else None
    App(first).mainloop()


# ======================================================================
#  Điểm vào
# ======================================================================
def main():
    argv = sys.argv[1:]
    if len(argv) >= 2 and argv[0] == "_py":          # nội bộ: chạy script .py dưới audit hook
        python_mode(json.loads(os.environ["GUARD_POLICY"]), argv[1], argv[2:])
    elif argv and argv[0] in ("run", "-h", "--help"):  # dòng lệnh
        cli_main()
    else:                                              # không đối số (hoặc 1 đường dẫn) -> cửa sổ
        gui_main()


if __name__ == "__main__":
    main()
