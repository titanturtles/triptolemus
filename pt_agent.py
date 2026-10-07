#!/usr/bin/env python3
"""TitanTurtles Packet Tracer competition agent (progressive levels + GUI).

A student runs this, enters their Team ID, and clicks Start. The agent:
  - connects to the running Packet Tracer over its IPC (PTMP),
  - asks the levels service which levels are unlocked for the team,
  - downloads the current level's .pka to a managed temp folder and opens it in PT,
  - reports live completion % to the sarpedon scoreboard,
  - auto-advances to the next level once the current one is cleared (server-gated),
  - on "Finish Competition": saves the work, uploads it for review, closes PT, and
    wipes the local .pka copies.

Config (JSON; default ./pt_agent.conf.json, also looked for next to the exe):
{
  "remote":    "https://scoreboard.titanturtles.xyz",         // sarpedon (score posting)
  "levelsvc":  "https://scoreboard.titanturtles.xyz/levels",  // gating + upload service
  "interval":  10,
  "pt_app_id": "xyz.titanturtles.ptagent",
  "pt_secret": "<ExApp shared secret>",
  "levels": [
    { "level": 1, "image": "PT-...-L1", "password": "<sarpedon per-image key>",
      "pt_password": "<activity hash, or omit if the activity is unlocked>",
      "threshold": 100 }
  ]
}
Students only ever enter their Team ID; everything else lives in this config.

Packet Tracer setup (once per machine): Extensions > IPC > Configure Apps > Add
the ptagent.pta file, then quit PT normally so it saves. Launch PT before Start.
"""
import argparse, hashlib, json, os, platform, shutil, socket, subprocess, sys, tempfile, threading, time, uuid
import urllib.parse, urllib.request, urllib.error

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    sys.exit("Missing dependency 'cryptography' (pip install cryptography).")

# sarpedon's delimiter is Go string(byte(255))+string(byte(222)) = UTF-8 of those
# code points (0xC3BF 0xC39E), NOT raw 0xFF 0xDE.
DELIM = (chr(255) + chr(222)).encode("utf-8")
CONF_DEFAULT = "pt_agent.conf.json"
STATE_FILE = "pt_agent.state.json"
AGENT_VERSION = "1.1.2"  # bump on every published build; the server advertises the latest


# ---------------- sarpedon /update protocol (matches aeacus; tested) ----------------
def _encrypt(password: str, plaintext: bytes) -> str:
    key = hashlib.sha256(password.encode("utf-8")).digest()
    pad = 16 - (len(plaintext) % 16)
    plaintext = plaintext + (b" " * pad)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return (nonce + ct).hex()


def build_update(password, team, image, percent, items_done, items_total, items=None) -> str:
    # sarpedon requires each vuln to be "<text> - <N> pts" and the vuln points to SUM to the
    # score. With the per-item tree we report the aeacus-style points model: score = earned
    # points, one vuln per earned item. Without the tree we fall back to completion %.
    entries = []
    if items:
        earned = [it for it in items if it.get("earned")]
        for it in earned[:200]:
            name = str(it.get("name", "item")).replace("-", "/")  # '-' is sarpedon's field separator
            entries.append((name, int(it.get("points", 0))))
        score = sum(pts for _, pts in entries)
        scored_count, total_count = int(items_done), int(items_total)
        if not entries:   # nothing scored yet; one zero-point placeholder (sum 0 == score 0)
            entries = [("No items scored yet", 0)]
    else:
        score = int(percent)  # truncate like PT's on-screen %
        scored_count, total_count = int(items_done), int(items_total)
        entries = [("Completion", score)]
    blob = str(scored_count).encode() + DELIM + str(total_count).encode() + DELIM
    for name, pts in entries:
        blob += f"{name} - {pts} pts".encode("utf-8", "replace") + DELIM
    vhex = _encrypt(password, blob).encode("ascii")
    upd = (b"team" + DELIM + team.encode() + DELIM + b"image" + DELIM + image.encode() + DELIM +
           b"score" + DELIM + str(score).encode() + DELIM + b"vulns" + DELIM + vhex + DELIM +
           b"time" + DELIM + str(int(time.time())).encode() + DELIM)
    return _encrypt(password, upd)


def post_update(remote: str, update: str, timeout=10) -> int:
    data = urllib.parse.urlencode({"update": update}).encode()
    req = urllib.request.Request(remote.rstrip("/") + "/update", data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode()
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


# ---------------- Packet Tracer IPC (PTMP) ----------------
class PTMPError(Exception):
    pass


class PTMPClient:
    """Minimal Packet Tracer PTMP client: text encoding, MD5 challenge auth, chained
    IPC calls. Verified against Packet Tracer 9.0.0. Frames are
    `<ascii-body-len>\\0<body>`; body = NUL-terminated fields, field[0] = type int."""
    VOID, BYTE, BOOL, SHORT, INT, LONG, FLOAT, DOUBLE, STRING, QSTRING = range(10)

    def __init__(self, app_id, secret, host="127.0.0.1", ports=range(39000, 39010), timeout=6.0):
        self.app_id, self.secret = app_id, secret
        self.host, self.ports, self.timeout = host, list(ports), timeout
        self.sock, self.port, self._id = None, None, 0

    def _send(self, mtype, fields):
        body = b"".join(p.encode("utf-8") + b"\x00" for p in [str(mtype)] + list(fields))
        self.sock.sendall(str(len(body)).encode("ascii") + b"\x00" + body)

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            c = self.sock.recv(n - len(buf))
            if not c:
                raise PTMPError("connection closed mid-frame")
            buf += c
        return buf

    def _recv_frame(self):
        lenbuf = b""
        while True:
            c = self.sock.recv(1)
            if not c:
                raise PTMPError("connection closed")
            if c == b"\x00":
                break
            lenbuf += c
        fields = self._recv_exact(int(lenbuf.decode("ascii"))).split(b"\x00")
        if fields and fields[-1] == b"":
            fields = fields[:-1]
        return [f.decode("utf-8", "replace") for f in fields]

    def connect(self):
        last = None
        for port in self.ports:
            try:
                self.sock = socket.create_connection((self.host, port), timeout=self.timeout)
            except OSError as e:
                last = e
                continue
            self.sock.settimeout(self.timeout)
            self.port, self._reached = port, False
            try:
                self._handshake()
                return self
            except PTMPError as e:
                self.sock.close()
                self.sock = None
                if self._reached:
                    raise
                last = e
            except OSError:
                # TCP connected but the handshake was interrupted — timed out, or PT aborted/
                # reset it (WinError 10053/10054). Usually PT is still loading, or a dialog or a
                # firewall/antivirus is interfering. Don't scan other ports — report clearly.
                try:
                    self.sock.close()
                except Exception:
                    pass
                self.sock = None
                raise PTMPError("Packet Tracer's connection was interrupted before the agent could "
                                "finish connecting (it may still be loading, or a dialog or "
                                "firewall/antivirus is interrupting it). Wait until Packet Tracer is "
                                "fully open, then click Start again.")
        raise PTMPError(f"Packet Tracer not reachable on {self.host}:{self.ports[0]}-{self.ports[-1]} ({last})")

    def _handshake(self):
        u = "{" + str(uuid.uuid4()) + "}"
        ts = time.strftime("%Y%m%d%H%M%S")
        self._send(0, ["PTMP", "1", u, "1", "1", "1", "4", ts, "0", ""])
        r = self._recv_frame()
        if not r or r[0] != "1":
            raise PTMPError(f"negotiation failed: {r}")
        self._reached = True
        self._send(2, [self.app_id])
        r = self._recv_frame()
        if not r or r[0] != "3":
            raise PTMPError(f"no auth challenge: {r}")
        digest = hashlib.md5((r[1] + self.secret).encode("utf-8")).hexdigest().upper()
        self._send(4, [self.app_id, digest, ""])
        r = self._recv_frame()
        if not (r and r[0] == "5" and r[1].lower() == "true"):
            raise PTMPError("Packet Tracer rejected the agent: register it as an ExApp "
                            "(Extensions > IPC > Configure Apps > Add the .pta, then quit PT normally), "
                            "or the secret does not match the registered KEY")

    def _encode_arg(self, v):
        if isinstance(v, bool):
            return [str(self.BOOL), "true" if v else "false"]
        if isinstance(v, int):
            return [str(self.INT), str(v)]
        if isinstance(v, str):
            return [str(self.QSTRING), v]
        raise PTMPError(f"unsupported argument {v!r}")

    def call(self, *steps):
        self._id += 1
        cid = self._id
        fields = [str(cid)]
        for step in steps:
            fields.append(step[0])
            for a in step[1:]:
                fields += self._encode_arg(a)
            fields.append("0")
        self._send(100, fields)
        while True:
            r = self._recv_frame()
            if not r:
                continue
            t = r[0]
            if t in ("6", "103"):
                continue
            if t == "7":
                raise PTMPError("Packet Tracer disconnected")
            if t == "101" and len(r) > 1 and r[1] == str(cid):
                raise PTMPError((r[2] if len(r) > 2 else "") + ": " + (r[3] if len(r) > 3 else ""))
            if t == "102" and len(r) > 1 and r[1] == str(cid):
                return self._parse(r[2:])

    def _parse(self, toks):
        if not toks:
            return None
        code, v = toks[0], (toks[1] if len(toks) > 1 else "")
        if code == str(self.BOOL):
            return v.lower() == "true"
        if code in (str(self.BYTE), str(self.SHORT), str(self.INT), str(self.LONG)):
            return int(v)
        if code in (str(self.FLOAT), str(self.DOUBLE)):
            return float(v)
        if code in (str(self.STRING), str(self.QSTRING)):
            return v
        if code == str(self.VOID):
            return None
        return toks[1:]

    def active(self, method, *args):
        """appWindow().getActiveFile().<method>(args...)"""
        return self.call(("appWindow",), ("getActiveFile",), (method,) + args)

    def _slow_call(self, secs, *steps):
        """Run a call that PT answers slowly (opening/saving a .pka can take far longer than
        the default 6s socket timeout on a loaded VM). Widens the socket timeout just for it."""
        old = self.sock.gettimeout() if self.sock else None
        try:
            if self.sock:
                self.sock.settimeout(secs)
            return self.call(*steps)
        finally:
            if self.sock and old is not None:
                try:
                    self.sock.settimeout(old)
                except Exception:
                    pass

    # --- file control (appWindow level; PT can take a while, so use a long timeout) ---
    def file_open(self, path):
        r = self._slow_call(180, ("appWindow",), ("fileOpen", path))
        return int(r) if r is not None else -1

    def file_save_as(self, path):
        return self._slow_call(300, ("appWindow",), ("fileSaveAsNoPrompt", path, False))

    def file_new(self):
        return self._slow_call(60, ("appWindow",), ("fileNew", False))

    def read_activity(self, pt_password=None):
        """Returns (title, percent, items_done, items_total) for the open activity."""
        if not self.active("isActivityFile"):
            raise PTMPError("no activity (.pka) is open in Packet Tracer")
        if not self.active("isPasswordConfirmed"):
            if not pt_password:
                raise PTMPError("this level's activity is locked but no pt_password is configured")
            if not self.active("confirmPassword", pt_password):
                raise PTMPError("this level's pt_password was rejected by Packet Tracer")
        title = self.active("getSavedFilename")
        pct = float(self.active("getPercentageComplete"))
        total = int(self.active("getAssessmentItemsCount"))
        done = int(self.active("getCorrectAssessmentItemsCount"))
        return title, pct, done, total

    def read_items(self, cap=250):
        """Walk getAssessedComparatorTree() and return the scored leaf items:
        [{name, points, earned}]. Best-effort: returns [] if the tree API is absent.
        Each leaf's getCheckType() is 2 (correct) / 1 (partial) / 0 (incorrect)."""
        base = [("appWindow",), ("getActiveFile",), ("getAssessedComparatorTree",)]

        def prop(path, name, *a):
            return self.call(*(base + [("getChildNodeAt", i) for i in path] + [(name,) + a]))

        out = []

        def walk(path, names):
            if len(out) >= cap:
                return
            try:
                n = prop(path, "getChildCount")
                nm = str(prop(path, "getNodeName"))
            except PTMPError:
                return
            names2 = names + [nm] if nm else names
            if not isinstance(n, (int, float)) or int(n) <= 0:   # leaf
                try:
                    ct = prop(path, "getCheckType")
                    pts = prop(path, "getTotalLeafPoints")
                except PTMPError:
                    return
                out.append({"name": " / ".join(names2[1:]) or nm,   # drop the "Network" root
                            "points": int(pts) if isinstance(pts, (int, float)) else 0,
                            "earned": (ct == 2)})
                return
            for i in range(int(n)):
                walk(path + [i], names2)

        try:
            walk([], [])
        except Exception:
            pass
        return out

    def close(self):
        if self.sock:
            try:
                self._send(7, ["bye"])
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None


# ---------------- levels service client ----------------
class LevelsClient:
    def __init__(self, base, timeout=15):
        self.base = base.rstrip("/")
        self.timeout = timeout

    def status(self, team, comp=""):
        q = {"team": team}
        if comp:
            q["comp"] = comp
        with urllib.request.urlopen(self.base + "/status?" + urllib.parse.urlencode(q), timeout=self.timeout) as r:
            return json.loads(r.read().decode())

    def download(self, team, comp, n, dest):
        q = {"team": team, "n": n}
        if comp:
            q["comp"] = comp
        with urllib.request.urlopen(self.base + "/level?" + urllib.parse.urlencode(q), timeout=self.timeout) as r:
            data = r.read()
        with open(dest, "wb") as f:
            f.write(data)
        return len(data)

    def upload(self, team, comp, n, data):
        q = {"team": team, "n": n}
        if comp:
            q["comp"] = comp
        req = urllib.request.Request(self.base + "/upload?" + urllib.parse.urlencode(q), data=data, method="POST",
                                     headers={"Content-Type": "application/octet-stream"})
        with urllib.request.urlopen(req, timeout=max(self.timeout, 60)) as r:
            return r.getcode()

    def upload_progress(self, team, comp, n, data):
        q = {"team": team, "n": n}
        if comp:
            q["comp"] = comp
        req = urllib.request.Request(self.base + "/progress?" + urllib.parse.urlencode(q), data=data, method="POST",
                                     headers={"Content-Type": "application/octet-stream"})
        with urllib.request.urlopen(req, timeout=max(self.timeout, 60)) as r:
            return r.getcode()

    def download_progress(self, team, comp, n, dest):
        """Download the team's saved progress for a level; returns bytes, or 0 if none."""
        q = {"team": team, "n": n}
        if comp:
            q["comp"] = comp
        try:
            with urllib.request.urlopen(self.base + "/progress?" + urllib.parse.urlencode(q), timeout=self.timeout) as r:
                data = r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return 0
            raise
        with open(dest, "wb") as f:
            f.write(data)
        return len(data)

    def reset(self, team, comp, token):
        """Erase this team's scores + progress for the competition (class-token gated)."""
        q = {"team": team}
        if comp:
            q["comp"] = comp
        req = urllib.request.Request(self.base + "/reset?" + urllib.parse.urlencode(q), data=b"", method="POST",
                                     headers={"X-Class-Token": token or ""})
        with urllib.request.urlopen(req, timeout=max(self.timeout, 30)) as r:
            return r.getcode()


# ---------------- OS helpers ----------------
def close_pt():
    """Terminate the Packet Tracer process (best-effort, cross-platform)."""
    try:
        if platform.system() == "Windows":
            subprocess.run(["taskkill", "/F", "/IM", "PacketTracer.exe"],
                           capture_output=True, timeout=15)
        else:
            for pat in ("PacketTracer", "packettracer"):
                subprocess.run(["pkill", "-f", pat], capture_output=True, timeout=15)
    except Exception:
        pass


def wipe(path):
    shutil.rmtree(path, ignore_errors=True)


def pt_port_open(host="127.0.0.1", ports=range(39000, 39010), timeout=1.0):
    for p in ports:
        try:
            socket.create_connection((host, p), timeout=timeout).close()
            return True
        except OSError:
            pass
    return False


def find_pt_command(cfg):
    """Return an argv list to launch Packet Tracer, or None if not found.
    `pt_path` in the config overrides auto-detection."""
    import glob
    p = cfg.get("pt_path")
    if p and os.path.exists(p):
        return [p]
    sysname = platform.system()
    if sysname == "Windows":
        for pf in (os.environ.get("ProgramW6432", ""), os.environ.get("ProgramFiles", ""),
                   os.environ.get("ProgramFiles(x86)", "")):
            if not pf:
                continue
            for pat in ("Cisco Packet Tracer*/bin/PacketTracer.exe",
                        "Cisco Packet Tracer*/bin/PacketTracer*.exe",
                        "Cisco Packet Tracer*/PacketTracer*.exe"):
                hits = sorted(glob.glob(os.path.join(pf, pat)))
                if hits:
                    return [hits[-1]]  # newest-sorted install
    elif sysname == "Darwin":
        if os.path.exists("/Applications/Cisco Packet Tracer.app"):
            return ["open", "-a", "Cisco Packet Tracer"]
    else:  # Linux
        for c in ("/opt/pt/packettracer", "/opt/pt/bin/PacketTracer", "/opt/pt/packettracer.AppImage"):
            if os.path.exists(c):
                return [c]
        w = shutil.which("packettracer")
        if w:
            return [w]
    return None


def launch_pt(cmd):
    kwargs = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if platform.system() == "Windows":
        kwargs["creationflags"] = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen(cmd, **kwargs)


def reveal(path):
    """Open a file manager showing (and selecting) the given file."""
    path = os.path.abspath(path)
    folder = os.path.dirname(path)
    try:
        if platform.system() == "Windows":
            subprocess.Popen(["explorer", "/select,", path])
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", "-R", path])
        else:
            subprocess.Popen(["xdg-open", folder])
    except Exception:
        pass


def pta_path(conf_dir):
    """Find ptagent.pta next to the config / executable."""
    bases = [conf_dir]
    if getattr(sys, "frozen", False):
        bases.append(os.path.dirname(sys.executable))
    else:
        bases.append(os.path.dirname(os.path.abspath(__file__)))
    for b in bases:
        c = os.path.join(b, "ptagent.pta")
        if os.path.exists(c):
            return c
    return os.path.join(conf_dir, "ptagent.pta")


# ---------------- config / state ----------------
def resolve_config(path):
    if os.path.exists(path):
        return path
    base = (os.path.dirname(sys.executable) if getattr(sys, "frozen", False)
            else os.path.dirname(os.path.abspath(__file__)))
    cand = os.path.join(base, os.path.basename(path))
    return cand if os.path.exists(cand) else path


def load_cfg(path):
    with open(path) as f:
        return json.load(f)


def load_state(base_dir):
    try:
        with open(os.path.join(base_dir, STATE_FILE)) as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(base_dir, state):
    try:
        with open(os.path.join(base_dir, STATE_FILE), "w") as f:
            json.dump(state, f)
    except Exception:
        pass


def reset_local(base_dir):
    """New-student reset: forget the saved Team ID and delete leftover local activity
    files. Leaves the config, ptagent.pta, and Packet Tracer's agent registration
    untouched — so first-time setup never has to be repeated."""
    try:
        os.remove(os.path.join(base_dir, STATE_FILE))
    except FileNotFoundError:
        pass
    except Exception:
        pass
    try:
        import glob
        for d in glob.glob(os.path.join(tempfile.gettempdir(), "ptagent_*")):
            wipe(d)
    except Exception:
        pass


# ---------------- competition orchestrator ----------------
class Competition:
    """Drives one competition. The GUI calls start()/stop()/finish(); a scoring-loop
    thread posts live scores and auto-advances levels. report(kind, payload) kinds:
    'log','status','cards','error','state'. state payloads: 'idle','running','paused','done'."""
    def __init__(self, cfg, team_id, report, cancel):
        self.cfg = cfg
        self.team = team_id
        self.report = report
        self.cancel = cancel          # global: set when the window closes, to abort waits
        self.client = None
        self.comp = cfg.get("comp", "")
        self.practice = bool(cfg.get("practice", False))
        self.free_switch = False      # practice "unlock all": disables auto-advance, allows jumps
        self.levels = LevelsClient(cfg["levelsvc"])
        self.tmp = None
        self.current = None           # level number currently open in PT
        self.current_path = None      # local .pka path of the current level
        self.loop_stop = None         # per-run event that stops the scoring loop
        self.loop_thread = None
        self.io_lock = threading.Lock()  # serialize PT socket use (loop read vs. save)

    def level_cfg(self, n):
        for l in self.cfg["levels"]:
            if int(l["level"]) == int(n):
                return l
        return None

    def _connect(self):
        """Connect to Packet Tracer; if it isn't running, launch it and wait. PT often accepts
        the IPC port a moment before it can answer PTMP, so the handshake is retried briefly."""
        def try_connect():
            return PTMPClient(self.cfg["pt_app_id"], self.cfg["pt_secret"]).connect()

        # "was interrupted" = PT is up but the handshake didn't finish — timeout/abort/reset
        # (worth retrying); "not reachable" = no IPC port open yet (launch PT if allowed).
        not_ready = lambda m: ("was interrupted" in m) or ("not reachable" in m)

        try:
            return try_connect()
        except PTMPError as e:
            if not not_ready(str(e)):
                raise  # auth rejected etc. — a retry won't help
            if "not reachable" in str(e) and self.cfg.get("auto_launch", True):
                cmd = find_pt_command(self.cfg)
                if not cmd:
                    raise  # can't find Packet Tracer -> upstream shows install message
                self.report("log", "Packet Tracer isn't running — launching it…")
                self.report("status", "Launching Packet Tracer…")
                try:
                    launch_pt(cmd)
                except Exception as le:
                    self.report("log", "Could not launch Packet Tracer: " + str(le))
                    raise e
                for i in range(90):  # wait up to ~3 min (PT startup + any NetAcad login)
                    if self.cancel.is_set():
                        raise PTMPError("cancelled")
                    if pt_port_open():
                        break
                    self.report("status", f"Waiting for Packet Tracer to start… (log in if prompted) — {i * 2}s")
                    self.cancel.wait(2)
            elif "not reachable" in str(e):
                raise  # auto-launch disabled and PT isn't up
            # Port is (now) open; PT may still need a few seconds to answer PTMP — retry.
            last = e
            for _ in range(8):  # ~24s of grace after the port opens
                if self.cancel.is_set():
                    raise PTMPError("cancelled")
                self.cancel.wait(3)
                try:
                    return try_connect()
                except PTMPError as e2:
                    last = e2
                    if not_ready(str(e2)):
                        self.report("status", "Packet Tracer is finishing startup — connecting…")
                        continue
                    raise  # a definite error (e.g. auth rejected)
            raise last

    def _active_level(self):
        """Return (level_number, levels) for the level the student should be on now."""
        st = self.levels.status(self.team, self.comp)
        levels = st.get("levels", [])
        active = next((l for l in levels if l.get("unlocked") and not l.get("cleared")), None)
        if active:
            return active["level"], levels
        unlocked = [l for l in levels if l.get("unlocked")]
        if unlocked:
            return unlocked[-1]["level"], levels   # everything cleared: stay on the last one
        return (levels[0]["level"] if levels else None), levels

    def _load_level(self, lvl, fresh):
        """Open a level in PT. fresh=False tries the student's saved progress first."""
        lc = self.level_cfg(lvl)
        if not lc:
            raise PTMPError(f"level {lvl} is missing from the agent config")
        path = os.path.join(self.tmp, f"level{lvl}.pka")
        got = 0
        if not fresh:
            try:
                got = self.levels.download_progress(self.team, self.comp, lvl, path)
            except Exception as e:
                self.report("log", f"Could not fetch saved progress: {e}")
        if not got:
            self.levels.download(self.team, self.comp, lvl, path)
        with self.io_lock:
            code = self.client.file_open(path)
        if code != 0:
            raise PTMPError(f"Packet Tracer could not open level {lvl} (code {code})")
        self.current, self.current_path = lvl, path
        src = "your saved progress" if got else "a fresh copy"
        self.report("log", f"Level {lvl} loaded in Packet Tracer ({src}). Go!")

    def _loop(self):
        interval = int(self.cfg.get("interval", 10))
        while not self.loop_stop.is_set() and not self.cancel.is_set():
            try:
                st = self.levels.status(self.team, self.comp)
            except Exception as e:
                self.report("log", f"levels service unreachable: {e}")
                self.loop_stop.wait(interval)
                continue
            levels = st.get("levels", [])
            active = next((l for l in levels if l.get("unlocked") and not l.get("cleared")), None)

            # a level just cleared -> advance to the newly-unlocked one (fresh copy).
            # In practice "unlock all" mode the student picks levels manually, so don't auto-advance.
            if active and active["level"] != self.current and not self.free_switch:
                # save + upload the level that just cleared so every level is reviewable,
                # not just the last one the student finishes on
                self._save(progress=True, final=True)
                try:
                    with self.io_lock:
                        self.client.file_new()
                except Exception:
                    pass
                try:
                    self._load_level(active["level"], fresh=True)
                except Exception as e:
                    self.report("log", f"Could not load level {active['level']}: {e}")

            # read + post the current level's live score
            live_pct = None
            if self.current:
                lc = self.level_cfg(self.current)
                try:
                    with self.io_lock:
                        _title, pct, done, total = self.client.read_activity(lc.get("pt_password"))
                        items = self.client.read_items()
                    live_pct = pct
                    upd = build_update(lc["password"], self.team, lc["image"], pct, done, total, items)
                    code = post_update(self.cfg["remote"], upd)
                    tag = "OK" if code == 200 else f"rejected({code})"
                    epts = sum(i["points"] for i in items if i.get("earned"))
                    tpts = sum(i["points"] for i in items)
                    extra = f", {epts}/{tpts} pts" if items else ""
                    self.report("log", f"Level {self.current}: {int(pct)}% ({done}/{total} items{extra}) -> {tag}")
                except PTMPError as e:
                    self.report("log", f"Read error: {e}")

            self.report("cards", {"levels": levels, "active": (self.current or 0), "pct": live_pct})
            if levels and all(l.get("cleared") for l in levels):
                self.report("status", "All levels cleared! Click Finish Competition to submit.")
            elif self.current:
                self.report("status", f"Working on level {self.current}"
                                      + (f" — {int(live_pct)}%" if live_pct is not None else ""))
            self.loop_stop.wait(interval)

    # ---------- control actions (each invoked in its own thread by the GUI) ----------
    def start(self, fresh=False):
        """Start or resume. fresh=True ignores saved progress and loads a clean copy."""
        try:
            if not self.client:
                self.report("status", "Connecting to Packet Tracer…")
                self.client = self._connect()
                self.report("log", f"Connected to Packet Tracer on port {self.client.port}.")
            if not self.tmp:
                self.tmp = tempfile.mkdtemp(prefix="ptagent_")
            lvl, _levels = self._active_level()
            if lvl is None:
                self.report("error", "This competition has no levels configured.")
                self.report("state", "idle")
                return
            self._load_level(lvl, fresh=fresh)
        except PTMPError as e:
            self._report_connect_error(e)
            self.report("state", "idle")
            return
        except Exception as e:
            self.report("log", "Could not start: " + str(e))
            self.report("error", "Could not start:\n\n" + str(e))
            self.report("state", "idle")
            return
        self.loop_stop = threading.Event()
        self.loop_thread = threading.Thread(target=self._loop, daemon=True)
        self.loop_thread.start()
        self.report("state", "running")

    def _stop_loop(self):
        if self.loop_stop:
            self.loop_stop.set()
        if self.loop_thread:
            self.loop_thread.join(timeout=20)
        self.loop_thread = None

    def start_over(self):
        """Discard the current level's progress and reload a clean copy, then run."""
        self._stop_loop()
        self.start(fresh=True)

    def switch_level(self, n):
        """Practice only: jump to a chosen level. Saves + uploads the level being left (so
        every level is reviewable), then opens the chosen one, keeping the scoring loop running."""
        if not self.client:
            self.report("error", "Click Start first, then you can jump between levels.")
            return
        if n == self.current:
            self.report("status", f"Already on level {n}.")
            return
        try:
            self._save(progress=True, final=True)   # preserve the level you're leaving
            try:
                with self.io_lock:
                    self.client.file_new()
            except Exception:
                pass
            self._load_level(n, fresh=False)
            self.report("status", f"Switched to level {n}.")
        except Exception as e:
            self.report("log", f"Could not switch to level {n}: {e}")
            self.report("error", f"Could not switch to level {n}:\n\n{e}")

    def restart_all(self):
        """Erase this team's scores + progress for the whole competition on the server, then
        load Level 1 (gating resets because the recorded scores are gone)."""
        self._stop_loop()
        try:
            self.levels.reset(self.team, self.comp, self.cfg.get("class_token"))
            self.report("log", "Progress erased on the server. Restarting at Level 1.")
        except Exception as e:
            self.report("log", f"Could not reset progress: {e}")
            self.report("error", "Could not reset your progress on the server:\n\n" + str(e))
            self.report("state", "idle")
            return
        self.start(fresh=True)

    def checkpoint(self):
        """Save + upload the current work, but keep Packet Tracer open and keep scoring."""
        if not (self.client and self.current and self.current_path):
            self.report("state", "running")
            return
        self._save(progress=True)
        self.report("status", f"Saved. Still working on level {self.current} — keep going.")
        self.report("state", "running")

    def stop(self):
        """Pause: save the current work to the server, then close Packet Tracer."""
        self.report("status", "Saving your work and closing Packet Tracer…")
        self._stop_loop()
        self._save(progress=True)
        self._close_pt()
        self.report("log", "Paused — your work is saved on the server. Click Resume to continue.")
        self.report("status", "Paused and saved. Resume, start over, or finish.")
        self.report("state", "paused")

    def finish(self):
        """Final: save + upload for review, close Packet Tracer, wipe local copies."""
        self.report("status", "Finishing — saving and uploading your work…")
        self._stop_loop()
        self._save(progress=True, final=True)
        self._close_pt()
        if self.tmp:
            wipe(self.tmp)
            self.tmp = None
        self.current = self.current_path = None
        self.report("log", "Submitted. Packet Tracer closed and local activity files removed.")
        self.report("status", "Finished — you may close this window.")
        self.report("state", "done")

    def _save(self, progress=False, final=False):
        """Save the current PT file and push it to the server (progress and/or review)."""
        if not (self.client and self.current and self.current_path):
            return
        try:
            with self.io_lock:
                self.client.file_save_as(self.current_path)
            with open(self.current_path, "rb") as f:
                data = f.read()
        except Exception as e:
            self.report("log", f"Could not save level {self.current} in Packet Tracer: {e}")
            return
        if progress:
            try:
                self.levels.upload_progress(self.team, self.comp, self.current, data)
                self.report("log", f"Saved level {self.current} progress to the server ({len(data)} bytes).")
            except Exception as e:
                self.report("log", f"Saving progress failed: {e}")
        if final:
            try:
                code = self.levels.upload(self.team, self.comp, self.current, data)
                self.report("log", f"Uploaded level {self.current} for review ({len(data)} bytes, HTTP {code}).")
            except Exception as e:
                self.report("log", f"Upload for review failed: {e}")

    def _close_pt(self):
        with self.io_lock:
            try:
                if self.client:
                    self.client.file_new()
            except Exception:
                pass
            try:
                if self.client:
                    self.client.close()
            except Exception:
                pass
            self.client = None
        close_pt()

    def _report_connect_error(self, e):
        msg = str(e)
        if "not reachable" in msg:
            msg = ("Packet Tracer isn't running on this computer.\n\n"
                   "Please make sure Cisco Packet Tracer is installed and open, "
                   "then click Start again.")
        elif "register" in msg.lower():
            msg = (msg + "\n\nFirst time on this computer? Click "
                   "\"First-time setup (register the agent)…\" for step-by-step help.")
        self.report("status", "Not connected — Packet Tracer not found.")
        self.report("log", "Could not connect to Packet Tracer: " + str(e))
        self.report("error", msg)


# ---------------- enrollment (competition set from the server) ----------------
def fetch_enroll(levelsvc_base, token, timeout=20):
    """GET /enroll with the shared class token -> the full competition set + default."""
    base = levelsvc_base.rstrip("/")
    req = urllib.request.Request(base + "/enroll", headers={"X-Class-Token": token})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def resolve_enrollment(cfg):
    """Return (shared, competitions, default_comp_id).
    With a 'class_token' bootstrap config, fetch everything from the server; otherwise
    fall back to a single inline competition (legacy pt_agent.conf.json with levels)."""
    shared = {
        "remote": cfg.get("remote", ""), "levelsvc": cfg.get("levelsvc", ""),
        "pt_app_id": cfg.get("pt_app_id", ""), "pt_secret": cfg.get("pt_secret", ""),
        "interval": cfg.get("interval", 10), "auto_launch": cfg.get("auto_launch", True),
        "class_token": cfg.get("class_token", ""),
    }
    if cfg.get("pt_command"):
        shared["pt_command"] = cfg["pt_command"]
    token = cfg.get("class_token")
    if token:
        data = fetch_enroll(cfg["levelsvc"], token)
        for k in ("remote", "pt_app_id", "pt_secret"):
            if data.get(k):
                shared[k] = data[k]
        return shared, data.get("competitions", []), data.get("default", "")
    comps = [{"comp": cfg.get("comp", ""), "name": cfg.get("comp") or "Competition",
              "levels": cfg.get("levels", [])}]
    return shared, comps, cfg.get("comp", "")


def comp_cfg(shared, competition):
    """Build a single-competition cfg (the shape the Competition class expects)."""
    c = dict(shared)
    c["comp"] = competition.get("comp", "")
    c["practice"] = bool(competition.get("practice", False))
    c["levels"] = competition.get("levels", [])
    return c


# ---------------- GUI ----------------
def run_gui(cfg, conf_dir):
    import threading, queue
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox

    state = load_state(conf_dir)
    msgq = queue.Queue()
    server_served = bool(cfg.get("class_token"))  # bootstrap config pulls competitions from the server

    root = tk.Tk()
    root.title(f"TitanTurtles — Packet Tracer Competition (v{AGENT_VERSION})")
    root.geometry("680x600")

    # Open at a normal size even if the window manager tries to maximize a new window on
    # autostart. The window stays resizable; we just clear any maximized state right after
    # it maps (a few times, to beat the WM's maximize-on-map).
    def _nomaximize():
        try:
            root.attributes("-zoomed", False)  # Linux WM maximized flag
        except Exception:
            pass
        try:
            root.state("normal")
        except Exception:
            pass
        root.geometry("680x600")
    for _d in (80, 400, 1000):
        root.after(_d, _nomaximize)
    intro = ttk.Label(
        root, wraplength=580, justify="left", foreground="#2f5e97", padding=(10, 8, 10, 0),
        text="How to use:   1) Open Packet Tracer (register the agent once: Extensions → IPC → "
             "Configure Apps → Add).   2) Enter your Team ID and click Start — your level opens "
             "automatically.   3) Work in Packet Tracer; clearing a level unlocks the next.   "
             "Need a break? Click Stop to save & close, then Resume later to pick up where you left "
             "off. Start from beginning reloads a clean copy.   4) Click Finish Competition when "
             "you're done — it saves and submits your work.")
    intro.pack(anchor="w", fill="x")

    def show_setup_help():
        p = pta_path(conf_dir)
        win = tk.Toplevel(root)
        win.title("First-time setup")
        win.geometry("620x430")
        win.transient(root)
        steps = (
            "Do this ONCE on this computer so Packet Tracer accepts the scoring agent:\n\n"
            "1. Open Packet Tracer (click Start here and the agent opens it for you).\n\n"
            "2. In Packet Tracer:   Extensions  →  IPC  →  Configure Apps\n\n"
            "3. Click \"Add\", then choose this file:\n"
            f"       {p}\n"
            "   (use the button below to open its folder)\n\n"
            "4. Click \"Ok\" — \"TitanTurtles PT Agent\" appears in the list.\n\n"
            "5. Quit Packet Tracer normally (File → Exit) so it saves the registration.\n\n"
            "6. Reopen Packet Tracer, then click Start here."
        )
        ttk.Label(win, text=steps, justify="left", wraplength=580, padding=12).pack(anchor="w", fill="both", expand=True)
        bb = ttk.Frame(win, padding=8)
        bb.pack(fill="x")
        ttk.Button(bb, text="Open folder with ptagent.pta", command=lambda: reveal(p)).pack(side="left")
        ttk.Button(bb, text="Close", command=win.destroy).pack(side="right")
        win.lift()
        win.focus_force()

    helpbar = ttk.Frame(root, padding=(10, 0, 10, 2))
    helpbar.pack(anchor="w", fill="x")
    ttk.Button(helpbar, text="First-time setup (register the agent)…", command=show_setup_help).pack(side="left")

    # competition selector — populated from the server on open (Reload re-fetches)
    ENR = {"shared": dict(cfg), "comps": [], "by_name": {}}
    sel_var = tk.StringVar()
    compbar = ttk.Frame(root, padding=(10, 0, 10, 2))
    compbar.pack(anchor="w", fill="x")
    ttk.Label(compbar, text="Competition:").pack(side="left")
    combo = ttk.Combobox(compbar, textvariable=sel_var, state="readonly", width=28)
    combo.pack(side="left", padx=6)
    # anchor Reset + Reload on the right so they're always visible
    reset_btn = ttk.Button(compbar, text="Reset (new student)")  # command wired below
    reset_btn.pack(side="right", padx=(6, 0))
    reload_btn = ttk.Button(compbar, text="Reload")  # command wired below
    reload_btn.pack(side="right")

    # practice-only controls (shown by select_comp when the chosen competition is practice):
    # an "Unlock all levels" toggle + a level picker so the student can jump around freely.
    practicebar = ttk.Frame(root, padding=(10, 0, 10, 2))
    free_switch_var = tk.BooleanVar(value=False)
    LEVELPICK = {}  # label -> level number
    practice_chk = ttk.Checkbutton(practicebar, text="Unlock all levels (practice)",
                                   variable=free_switch_var)  # command wired below
    practice_chk.pack(side="left")
    ttk.Label(practicebar, text="   Jump to level:").pack(side="left")
    level_pick_var = tk.StringVar()
    level_combo = ttk.Combobox(practicebar, textvariable=level_pick_var, state="disabled", width=22)
    level_combo.pack(side="left", padx=6)
    goto_btn = ttk.Button(practicebar, text="Go", state="disabled")  # command wired below
    goto_btn.pack(side="left")

    frm = ttk.Frame(root, padding=10)
    frm.pack(fill="both", expand=True)

    ttk.Label(frm, text="Team ID:").grid(row=0, column=0, sticky="w", pady=4)
    team_var = tk.StringVar(value=state.get("team_id", cfg.get("team_id", "")))
    ttk.Entry(frm, textvariable=team_var, width=36).grid(row=0, column=1, sticky="we", pady=4)

    # level cards (rebuilt whenever the selected competition changes)
    cards_frame = ttk.LabelFrame(frm, text="Levels", padding=8)
    cards_frame.grid(row=1, column=0, columnspan=3, sticky="we", pady=8)
    level_rows = {}

    status_var = tk.StringVar(value="Idle. Open Packet Tracer, then enter your Team ID and Start.")
    ttk.Label(frm, textvariable=status_var, foreground="#2f5e97").grid(row=3, column=0, columnspan=3, sticky="w", pady=4)

    log = scrolledtext.ScrolledText(frm, height=12, width=72, state="disabled", font=("TkFixedFont", 9))
    log.grid(row=4, column=0, columnspan=3, sticky="nsew", pady=6)
    frm.rowconfigure(4, weight=1)
    frm.columnconfigure(1, weight=1)

    # always-visible version footer (the log scrolls; a maximized window can hide the title)
    ttk.Label(frm, text=f"version {AGENT_VERSION}", foreground="#888").grid(
        row=5, column=0, columnspan=3, sticky="e")

    def logln(s):
        log.configure(state="normal")
        log.insert("end", time.strftime("%H:%M:%S ") + s + "\n")
        log.see("end")
        log.configure(state="disabled")

    def set_card(n, text, color):
        if n in level_rows:
            sv, lbl = level_rows[n]
            sv.set(text)
            lbl.configure(foreground=color)

    def render_cards(payload):
        active = payload.get("active", 0)
        pct = payload.get("pct")
        for ls in payload.get("levels", []):
            n = ls["level"]
            if ls.get("cleared"):
                set_card(n, "✓ done", "#1b7f3b")
            elif n == active:
                txt = "▶ active" + (f" — {int(pct)}%" if pct is not None else "")
                set_card(n, txt, "#b06a00")
            elif ls.get("unlocked"):
                set_card(n, "… unlocked", "#555")
            else:
                set_card(n, "🔒 locked", "#999")

    def rebuild_cards(levels):
        for w in cards_frame.winfo_children():
            w.destroy()
        level_rows.clear()
        for lc in levels:
            n = int(lc["level"])
            label = lc.get("name") or f"Level {n}"
            row = ttk.Frame(cards_frame)
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=label, width=26, font=("TkDefaultFont", 10, "bold")).pack(side="left")
            sv = tk.StringVar(value="… ready" if n == 1 else "🔒 locked")
            lbl = ttk.Label(row, textvariable=sv, foreground="#888")
            lbl.pack(side="left")
            level_rows[n] = (sv, lbl)
        if not levels:
            ttk.Label(cards_frame, text="(no competition selected)", foreground="#999").pack(anchor="w")

    cancel = threading.Event()
    comp = {"obj": None}
    ui_state = {"v": "idle"}

    def ensure_comp():
        team_id = team_var.get().strip()
        if not team_id:
            status_var.set("Enter your Team ID first.")
            return None
        c = ENR["by_name"].get(sel_var.get())
        if not c:
            status_var.set("Select a competition first (click Reload if the list is empty).")
            return None
        ccfg = comp_cfg(ENR["shared"], c)
        for key in ("remote", "levelsvc", "pt_app_id", "pt_secret"):
            if not ccfg.get(key):
                status_var.set(f"Config missing '{key}'. Contact your instructor.")
                return None
        if not ccfg.get("levels"):
            status_var.set("This competition has no levels yet. Pick another or click Reload.")
            return None
        cur = comp["obj"]
        if cur is None or cur.team != team_id or cur.comp != ccfg.get("comp", ""):
            save_state(conf_dir, {"team_id": team_id})
            comp["obj"] = Competition(ccfg, team_id, lambda k, p: msgq.put((k, p)), cancel)
        comp["obj"].free_switch = bool(ccfg.get("practice")) and free_switch_var.get()
        return comp["obj"]

    # enabled buttons per state: (start, resume, stop, checkpoint, start-over, finish)
    # (start, resume, stop, checkpoint, restart-level, start-over-L1, finish)
    BTN_STATES = {"idle":    (1, 0, 0, 0, 0, 1, 0),
                  "running": (0, 0, 1, 1, 1, 1, 1),
                  "paused":  (0, 1, 0, 0, 1, 1, 1),
                  "done":    (0, 0, 0, 0, 0, 0, 0),
                  "busy":    (0, 0, 0, 0, 0, 0, 0)}

    def set_buttons(st):
        for b, on in zip((btn_start, btn_resume, btn_stop, btn_checkpoint, btn_over, btn_startover, btn_finish),
                         BTN_STATES.get(st, BTN_STATES["idle"])):
            b.configure(state=("normal" if on else "disabled"))
        # lock the competition picker / reset once a competition is under way
        try:
            combo.configure(state=("readonly" if st in ("idle", "done") else "disabled"))
            reload_btn.configure(state=("normal" if (server_served and st in ("idle", "done")) else "disabled"))
            reset_btn.configure(state=("normal" if st in ("idle", "paused", "done") else "disabled"))
        except Exception:
            pass

    def run_action(fn, label):
        status_var.set(label)
        set_buttons("busy")
        threading.Thread(target=fn, daemon=True).start()

    def do_start():
        c = ensure_comp()
        if not c:
            return
        logln(f"Starting as team {c.team}…")
        run_action(lambda: c.start(fresh=False), "Connecting to Packet Tracer…")

    def do_resume():
        c = ensure_comp()
        if not c:
            return
        logln("Resuming — fetching your saved work…")
        run_action(lambda: c.start(fresh=False), "Resuming…")

    def do_stop():
        c = comp["obj"]
        if not c:
            return
        run_action(c.stop, "Saving your work and closing Packet Tracer…")

    def do_checkpoint():
        c = comp["obj"]
        if not c:
            return
        logln("Saving a checkpoint — Packet Tracer stays open…")
        run_action(c.checkpoint, "Saving and uploading — keep working…")

    def do_over():
        c = ensure_comp()
        if not c:
            return
        if not messagebox.askyesno("Restart this level",
                "Reload a clean copy of the CURRENT level (discards unsaved work on this level "
                "only). This does NOT go back to Level 1. Continue?"):
            return
        logln("Restarting the current level with a clean copy…")
        run_action(c.start_over, "Loading a clean copy…")

    def do_restart_all():
        c = ensure_comp()
        if not c:
            return
        if not messagebox.askyesno("Start over (Level 1)",
                "ERASE all your progress in this competition and go back to Level 1?\n\n"
                "This deletes your recorded scores and saved work for this competition on the "
                "server and cannot be undone. Continue?"):
            return
        logln("Erasing progress and restarting from Level 1…")
        run_action(c.restart_all, "Resetting to Level 1…")

    def do_finish():
        c = comp["obj"]
        if not c:
            return
        if not messagebox.askyesno("Finish Competition",
                "This saves and uploads your work for review, closes Packet Tracer, and removes "
                "the local activity files. You can't resume after finishing. Continue?"):
            return
        run_action(c.finish, "Finishing — saving and uploading…")

    def do_reset():
        if ui_state["v"] in ("running", "busy"):
            return
        if not messagebox.askyesno("Reset for a new student",
                "Set this computer up for a new student?\n\n"
                "• Clears the saved Team ID and deletes leftover local activity files.\n"
                "• Does NOT touch Packet Tracer's agent registration — you will NOT need to "
                "redo first-time setup.\n\nContinue?"):
            return
        c = comp["obj"]
        try:
            if c and getattr(c, "tmp", None):
                wipe(c.tmp)
        except Exception:
            pass
        reset_local(conf_dir)
        comp["obj"] = None
        team_var.set("")
        selc = ENR["by_name"].get(sel_var.get())
        rebuild_cards(selc.get("levels", []) if selc else [])  # clear the previous student's progress
        set_buttons("idle")
        ui_state["v"] = "idle"
        logln("Reset for a new student (Packet Tracer registration kept — no first-time setup needed).")
        status_var.set("Ready for a new student: enter Team ID, pick your competition, and Start.")

    def on_free_toggle():
        on = free_switch_var.get()
        try:
            level_combo.configure(state=("readonly" if on else "disabled"))
            goto_btn.configure(state=("normal" if on else "disabled"))
        except Exception:
            pass
        if comp["obj"]:
            comp["obj"].free_switch = on
        if on:
            status_var.set("Practice: levels unlocked — pick a level and click Go to jump.")

    def do_goto_level():
        c = comp["obj"]
        if not c or ui_state["v"] != "running":
            status_var.set("Click Start first, then you can jump between levels.")
            return
        n = LEVELPICK.get(level_pick_var.get())
        if not n:
            return
        logln(f"Jumping to level {n} (practice)…")
        run_action(lambda: c.switch_level(n), f"Switching to level {n}…")

    practice_chk.configure(command=on_free_toggle)
    goto_btn.configure(command=do_goto_level)

    # control buttons laid out in a 3-column grid so none get clipped on a small window
    btnbar = ttk.Frame(frm)
    btnbar.grid(row=2, column=0, columnspan=3, sticky="we", pady=6)
    for col in range(3):
        btnbar.columnconfigure(col, weight=1)
    btn_start      = ttk.Button(btnbar, text="Start",                command=do_start)
    btn_resume     = ttk.Button(btnbar, text="Resume",               command=do_resume)
    btn_stop       = ttk.Button(btnbar, text="Stop (save & close)",  command=do_stop)
    btn_checkpoint = ttk.Button(btnbar, text="Save & keep working",  command=do_checkpoint)
    btn_over       = ttk.Button(btnbar, text="Restart this level",   command=do_over)
    btn_startover  = ttk.Button(btnbar, text="Start over (Level 1)", command=do_restart_all)
    btn_finish     = ttk.Button(btnbar, text="Finish Competition",   command=do_finish)
    btn_start.grid(row=0, column=0, sticky="we", padx=3, pady=2)
    btn_resume.grid(row=0, column=1, sticky="we", padx=3, pady=2)
    btn_stop.grid(row=0, column=2, sticky="we", padx=3, pady=2)
    btn_checkpoint.grid(row=1, column=0, sticky="we", padx=3, pady=2)
    btn_over.grid(row=1, column=1, sticky="we", padx=3, pady=2)
    btn_startover.grid(row=1, column=2, sticky="we", padx=3, pady=2)
    btn_finish.grid(row=2, column=0, sticky="we", padx=3, pady=2)
    set_buttons("idle")

    def select_comp(*_):
        comp["obj"] = None   # a different competition needs a fresh Competition object
        c = ENR["by_name"].get(sel_var.get())
        if not c:
            rebuild_cards([])
            practicebar.pack_forget()
            return
        rebuild_cards(c.get("levels", []))
        if c.get("practice"):
            LEVELPICK.clear()
            labels = []
            for lc in c.get("levels", []):
                n = int(lc["level"])
                lab = lc.get("name") or f"Level {n}"
                LEVELPICK[lab] = n
                labels.append(lab)
            level_combo.configure(values=labels)
            if labels:
                level_pick_var.set(labels[0])
            free_switch_var.set(True)   # practice defaults to unlocked / free switching
            practicebar.pack(fill="x", after=compbar)
            on_free_toggle()
        else:
            free_switch_var.set(False)
            practicebar.pack_forget()
        nm = c.get("name") or c.get("comp")
        status_var.set(f"Selected “{nm}”. Enter your Team ID and click Start.")

    def apply_enrollment(shared, comps, default_comp):
        ENR["shared"], ENR["comps"], ENR["by_name"] = shared, comps, {}
        names = []
        for c in comps:
            nm = c.get("name") or c.get("comp") or "(unnamed)"
            base, i = nm, 2
            while nm in ENR["by_name"]:
                nm = f"{base} ({i})"
                i += 1
            ENR["by_name"][nm] = c
            names.append(nm)
        combo.configure(values=names)
        pick = next((nm for nm, c in ENR["by_name"].items() if c.get("comp") == default_comp), None)
        if not pick and names:
            pick = names[0]
        if pick:
            sel_var.set(pick)
            select_comp()
        else:
            rebuild_cards([])
            status_var.set("No competitions available yet. Ask your instructor, then click Reload.")
        logln(f"Loaded {len(comps)} competition(s)." + (f"  Default: {default_comp}." if default_comp else ""))

    def load_enrollment():
        if not server_served:
            logln("This config has a fixed competition list (no class_token), so it can't fetch "
                  "new competitions. Ask your instructor for the 'Student bootstrap' config to get "
                  "competitions from the server automatically.")
        status_var.set("Loading competitions from the server…")
        logln("Fetching the competition list from the server…")

        def work():
            try:
                res = resolve_enrollment(cfg)
            except Exception as e:
                msgq.put(("enroll_error", str(e)))
                return
            msgq.put(("enroll_ok", res))
        threading.Thread(target=work, daemon=True).start()

    combo.bind("<<ComboboxSelected>>", select_comp)
    reload_btn.configure(command=load_enrollment)
    reset_btn.configure(command=do_reset)

    def poll():
        try:
            while True:
                kind, payload = msgq.get_nowait()
                if kind == "log":
                    logln(payload)
                elif kind == "status":
                    status_var.set(payload)
                elif kind == "cards":
                    render_cards(payload)
                elif kind == "error":
                    try:
                        messagebox.showerror("Packet Tracer", payload)
                    except Exception:
                        pass
                elif kind == "state":
                    ui_state["v"] = payload
                    set_buttons(payload)
                elif kind == "enroll_ok":
                    apply_enrollment(*payload)
                elif kind == "enroll_error":
                    logln("Could not load competitions: " + payload)
                    status_var.set("Could not load competitions. Check your connection and click Reload.")
                    try:
                        messagebox.showerror("Competitions",
                                             "Could not load competitions from the server:\n\n" + payload)
                    except Exception:
                        pass
        except queue.Empty:
            pass
        root.after(250, poll)

    logln(f"Ready. Agent v{AGENT_VERSION}. Server: {cfg.get('levelsvc', '?')}")
    root.after(250, poll)
    if not os.environ.get("PT_AGENT_SELFTEST"):
        load_enrollment()

    def on_close():
        cancel.set()
        c = comp["obj"]
        if c and c.loop_stop:
            c.loop_stop.set()
        root.destroy()
    root.protocol("WM_DELETE_WINDOW", on_close)

    # Headless self-test (dev): build the GUI, fake an enrollment, render cards, close.
    if os.environ.get("PT_AGENT_SELFTEST"):
        demo = [{"level": 1, "image": "x", "threshold": 100}, {"level": 2, "image": "y", "threshold": 100}]
        apply_enrollment(dict(cfg), [{"comp": "demo", "name": "Demo competition", "levels": demo},
                                     {"comp": "demo2", "name": "Practice competition", "practice": True, "levels": demo}], "demo")
        if os.environ.get("PT_AGENT_SELFTEST_PRACTICE"):
            sel_var.set("Practice competition")   # exercise the practice controls path
            select_comp()
            print("[practice] practicebar mapped:", bool(practicebar.winfo_manager()),
                  "level choices:", list(LEVELPICK.keys()), "free_switch:", free_switch_var.get())
        render_cards({"levels": [{"level": 1, "unlocked": True, "cleared": True},
                                 {"level": 2, "unlocked": True, "cleared": False}], "active": 2, "pct": 42})
        if os.environ.get("PT_AGENT_GEOCHECK"):
            root.update_idletasks()
            root.update()
            ww = root.winfo_width()
            print(f"[geo] window width={ww}")
            for nm, b in [("start", btn_start), ("resume", btn_resume), ("checkpoint", btn_checkpoint),
                          ("stop", btn_stop), ("restartlevel", btn_over), ("startoverL1", btn_startover),
                          ("finish", btn_finish), ("reset", reset_btn), ("reload", reload_btn)]:
                x, w = b.winfo_rootx() - root.winfo_rootx(), b.winfo_width()
                vis = "OK" if (x >= 0 and x + w <= ww and w > 1) else "CLIPPED"
                print(f"[geo] {nm:10s} x={x:4d} w={w:4d} text='{b.cget('text')}' -> {vis}")
        root.after(1500, on_close)

    root.mainloop()


# ---------------- CLI (headless; for testing) ----------------
def run_cli(cfg, conf_dir, team_id, once, comp_id=None):
    team_id = team_id or cfg.get("team_id") or load_state(conf_dir).get("team_id")
    if not team_id:
        sys.exit("No team_id (use --team or set it in config/state).")
    shared, comps, default_comp = resolve_enrollment(cfg)
    if not comps:
        sys.exit("no competitions available from the server")
    want = comp_id or default_comp
    chosen = next((c for c in comps if c.get("comp") == want), comps[0])
    print(f"[comp] {chosen.get('name') or chosen.get('comp')}  ({len(chosen.get('levels', []))} level(s))")
    ccfg = comp_cfg(shared, chosen)
    cancel = threading.Event()
    comp = Competition(ccfg, team_id, lambda k, p: print(f"[{k}] {p}"), cancel)
    comp.start(fresh=False)
    if once:
        # one status+read cycle, then stop the loop and close PT without submitting
        time.sleep(int(cfg.get("interval", 10)) + 5)
        comp._stop_loop()
        comp._close_pt()
        return
    try:
        while comp.loop_thread and comp.loop_thread.is_alive():
            comp.loop_thread.join(0.5)
    except KeyboardInterrupt:
        print("\nstopping — saving your work…")
        comp.stop()


# ---------------- auto-update (frozen builds only) ----------------
def _ver_tuple(v):
    out = []
    for part in str(v).split("."):
        num = "".join(ch for ch in part if ch.isdigit())
        out.append(int(num) if num else 0)
    return tuple(out)


def _platform_key():
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def _relaunch_env():
    """Environment for starting a fresh copy of ourselves. A PyInstaller one-file build passes
    _PYI_* variables to its children; a relaunched copy that inherits them thinks it's a child,
    looks for the old (already deleted) unpack folder, and dies. Strip them and ask the
    bootloader to start clean."""
    env = {k: v for k, v in os.environ.items()
           if not (k.startswith("_PYI") or k.startswith("_MEIPASS"))}
    env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    return env


def _spawn_updater(new_path, target_path):
    """Replace target_path with new_path once this process exits, then relaunch it.
    Progress goes to pt_agent.update.log next to the app."""
    pid = os.getpid()
    log = os.path.join(os.path.dirname(target_path), "pt_agent.update.log")
    if sys.platform.startswith("win"):
        bat = new_path + ".update.bat"
        # wait for this PID, then swap (retrying ~60s while the exe is still locked) and relaunch;
        # if the swap never succeeds, drop the download and relaunch the old version
        script = (
            "@echo off\r\n"
            f'echo waiting for {pid} > "{log}"\r\n'
            ":wait\r\n"
            f'tasklist /FI "PID eq {pid}" | find "{pid}" >nul 2>&1 && (ping -n 2 127.0.0.1 >nul & goto wait)\r\n'
            "set /a tries=0\r\n"
            ":swap\r\n"
            f'move /Y "{new_path}" "{target_path}" >nul 2>&1 && goto moved\r\n'
            "set /a tries+=1\r\n"
            "if %tries% GEQ 60 goto giveup\r\n"
            "ping -n 2 127.0.0.1 >nul\r\n"
            "goto swap\r\n"
            ":giveup\r\n"
            f'echo swap failed, keeping the old version >> "{log}"\r\n'
            f'del "{new_path}" >nul 2>&1\r\n'
            "goto launch\r\n"
            ":moved\r\n"
            f'echo swapped >> "{log}"\r\n'
            ":launch\r\n"
            f'start "" "{target_path}"\r\n'
            f'echo relaunched >> "{log}"\r\n'
            'del "%~f0"\r\n'
        )
        with open(bat, "w") as f:
            f.write(script)
        subprocess.Popen(["cmd", "/c", bat], creationflags=0x00000008,  # DETACHED_PROCESS
                         env=_relaunch_env())
    else:
        sh = new_path + ".update.sh"
        script = (
            "#!/bin/sh\n"
            f'echo "$(date) waiting for {pid}" > "{log}"\n'
            f"while kill -0 {pid} 2>/dev/null; do sleep 0.5; done\n"
            f'if mv -f "{new_path}" "{target_path}" >>"{log}" 2>&1; then\n'
            f'  chmod +x "{target_path}"; echo "$(date) swapped" >>"{log}"\n'
            "else\n"
            f'  echo "$(date) swap failed, keeping the old version" >>"{log}"; rm -f "{new_path}"\n'
            "fi\n"
            f'"{target_path}" >>"{log}" 2>&1 &\n'
            f'echo "$(date) relaunched" >>"{log}"\n'
            'rm -- "$0"\n'
        )
        with open(sh, "w") as f:
            f.write(script)
        os.chmod(sh, 0o755)
        subprocess.Popen(["sh", sh], start_new_session=True, env=_relaunch_env())


def _update_available(cfg):
    """Quick, silent check: return the platform to update to if the server has a newer build
    for this (frozen) agent, else None. No download, no UI."""
    if not getattr(sys, "frozen", False) or not cfg.get("auto_update", True):
        return None
    base = (cfg.get("levelsvc") or "").rstrip("/")
    token = cfg.get("class_token")
    if not base or not token:
        return None
    try:
        req = urllib.request.Request(base + "/agent/latest", headers={"X-Class-Token": token})
        with urllib.request.urlopen(req, timeout=6) as r:
            info = json.loads(r.read().decode())
    except Exception:
        return None
    srv_ver = info.get("version") or ""
    plat = _platform_key()
    if not srv_ver or plat not in (info.get("platforms") or []):
        return None
    if _ver_tuple(srv_ver) <= _ver_tuple(AGENT_VERSION):
        return None
    return plat


def _download_and_stage(cfg, plat):
    """Download the new build, stage it, and spawn the updater. Returns True on success."""
    base = (cfg.get("levelsvc") or "").rstrip("/")
    token = cfg.get("class_token")
    target = os.path.abspath(sys.executable)
    new_path = target + ".new"
    try:
        url = base + "/agent/file?platform=" + urllib.parse.quote(plat)
        req = urllib.request.Request(url, headers={"X-Class-Token": token})
        with urllib.request.urlopen(req, timeout=180) as r:
            data = r.read()
        if len(data) < 100 * 1024:  # sanity: a real build is never this small
            return False
        with open(new_path, "wb") as f:
            f.write(data)
        _spawn_updater(new_path, target)
        return True
    except Exception:
        try:
            if os.path.exists(new_path):
                os.remove(new_path)
        except Exception:
            pass
        return False


def _update_with_splash(cfg):
    """If an update is available, show a tiny 'Updating…' window while downloading, then
    hand off to the updater. Returns True if an update was applied (caller should exit)."""
    plat = _update_available(cfg)
    if not plat:
        return False
    try:
        import tkinter as tk
    except Exception:
        return _download_and_stage(cfg, plat)
    root = tk.Tk()
    root.title("Updating")
    root.geometry("340x100")
    try:
        root.resizable(False, False)
    except Exception:
        pass
    tk.Label(root, text="Updating the Packet Tracer agent…\nIt will restart automatically.",
             padx=20, pady=24, justify="center").pack(expand=True)
    result = {"ok": False}

    def work():
        result["ok"] = _download_and_stage(cfg, plat)
        try:
            root.after(0, root.destroy)
        except Exception:
            pass
    threading.Thread(target=work, daemon=True).start()
    try:
        root.mainloop()
    except Exception:
        pass
    return result["ok"]


def _attach_parent_console():
    """Windowed (GUI) Windows exes have no console, so stdout from --version/--help/--cli
    goes nowhere. Attach to the launching console so those flags print as expected."""
    if not sys.platform.startswith("win"):
        return
    try:
        import ctypes
        if ctypes.windll.kernel32.AttachConsole(-1):  # ATTACH_PARENT_PROCESS
            sys.stdout = open("CONOUT$", "w")
            sys.stderr = open("CONOUT$", "w")
    except Exception:
        pass


def main():
    # make console output (version/help/cli) visible when launched from a terminal on Windows
    if any(a in ("--version", "-h", "--help", "--cli", "--once") for a in sys.argv[1:]):
        _attach_parent_console()
    ap = argparse.ArgumentParser(description="Packet Tracer competition agent (levels)")
    ap.add_argument("--version", action="version", version=f"pt_agent {AGENT_VERSION}")
    ap.add_argument("-c", "--config", default=CONF_DEFAULT)
    ap.add_argument("--gui", action="store_true", help="force the GUI")
    ap.add_argument("--cli", action="store_true", help="headless loop")
    ap.add_argument("--once", action="store_true", help="one cycle then exit (implies --cli)")
    ap.add_argument("--team", help="team id (CLI)")
    ap.add_argument("--comp", help="competition id to run (CLI; defaults to the server default)")
    args = ap.parse_args()
    cfg_path = resolve_config(args.config)
    cfg = load_cfg(cfg_path)
    conf_dir = os.path.dirname(os.path.abspath(cfg_path))
    if not cfg.get("levelsvc"):
        sys.exit("config missing 'levelsvc'")
    if not cfg.get("class_token") and not cfg.get("levels"):
        sys.exit("config missing 'levels' (or 'class_token' to fetch competitions from the server)")
    if args.cli or args.once:
        run_cli(cfg, conf_dir, args.team, args.once, args.comp)
    else:
        # self-update before the main window opens; if it updates, exit so the updater can swap us
        if _update_with_splash(cfg):
            return
        run_gui(cfg, conf_dir)


if __name__ == "__main__":
    main()
