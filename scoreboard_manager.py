#!/usr/bin/env python3
"""Cisco Scoreboard Manager (for the test creator).

Manage multiple Packet Tracer competitions on the TitanTurtles scoreboard, all
over HTTPS (no SSH):
  - See every competition on the server (levels, hidden state, # submissions).
  - New / Edit a competition with a wizard or a single page.
  - Deploy it live; the full config is saved locally so you can reload & edit it.
  - Hide / Show / Remove a competition on the server.
  - Review and download students' finished .pka submissions.

Run: python3 scoreboard_manager.py
"""
import io, json, os, platform, re, secrets, shutil, subprocess, sys, threading, zipfile
import urllib.request, urllib.error, urllib.parse

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox

# When frozen (PyInstaller --onefile), look beside the executable, not the temp
# extraction dir — so pka_tool/, manager_data/ and settings live next to the app.
if getattr(sys, "frozen", False):
    HERE = os.path.dirname(sys.executable)
else:
    HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "manager_data")       # local manifests + settings
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")


# ---------------- helpers ----------------
def find_pka_tool():
    d = os.path.join(HERE, "pka_tool")
    sysname, mach = platform.system(), platform.machine().lower()
    if sysname == "Windows":
        name = "pka_tool_windows_amd64.exe"
    elif sysname == "Darwin":
        name = "pka_tool_macos_arm64" if ("arm" in mach or "aarch" in mach) else "pka_tool_macos_amd64"
    else:
        name = "pka_tool_linux_amd64"
    for cand in (os.path.join(d, name), os.path.join(HERE, name)):
        if os.path.exists(cand):
            return cand
    return None


def extract_hash(pka_tool, pka_path):
    out = subprocess.run([pka_tool, "-pass", pka_path], capture_output=True, text=True, timeout=120)
    lines = out.stdout.strip().splitlines()
    return lines[0].strip() if lines else ""


def gen_key():
    return "ptk_" + secrets.token_hex(16)


def slug(s):
    s = re.sub(r"[^a-zA-Z0-9]+", "-", s.strip().lower()).strip("-")
    return s or "comp"


def slug_image(pka_path, comp_id, level):
    base = os.path.splitext(os.path.basename(pka_path))[0]
    keep = "".join(c if (c.isalnum() or c in "-_") else ("-" if c == " " else "") for c in base)
    return f"{comp_id}-L{level}-{keep}"[:60]


APP_SETTINGS = [
    ("remote", "Scoreboard URL", "https://scoreboard.titanturtles.xyz"),
    ("levelsvc", "Levels service URL", "https://scoreboard.titanturtles.xyz/levels"),
    ("pt_app_id", "ExApp id (from ptagent.pta)", "xyz.titanturtles.ptagent"),
    ("pt_secret", "ExApp secret (KEY)", ""),
    ("admin_token", "Admin token", ""),
]


# ---------------- server admin client ----------------
def parse_sub_name(name):
    """Final submission names are '<team>_L<n>_<timestamp>.pka' -> (team, n)."""
    base = name[:-4] if name.lower().endswith(".pka") else name
    parts = base.rsplit("_", 2)
    if len(parts) == 3 and parts[1].startswith("L"):
        return parts[0], parts[1][1:]
    return "", ""


class Admin:
    def __init__(self, base, token):
        self.base = base.rstrip("/")
        self.token = token

    def _req(self, path, data=None, method="GET"):
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"X-Admin-Token": self.token})
        if data is not None:
            req.add_header("Content-Type", "application/zip")
        with urllib.request.urlopen(req, timeout=600 if data else 30) as r:
            return r.read()

    def competitions(self):
        return json.loads(self._req("/admin/competitions").decode()).get("competitions", [])

    def deploy(self, comp, name, zip_bytes):
        q = urllib.parse.urlencode({"comp": comp, "name": name})
        return json.loads(self._req("/admin/deploy?" + q, data=zip_bytes, method="POST").decode())

    def competition(self, comp, action):
        q = urllib.parse.urlencode({"comp": comp, "action": action})
        return json.loads(self._req("/admin/competition?" + q, method="POST").decode())

    def submissions(self, comp):
        return json.loads(self._req("/admin/submissions?" + urllib.parse.urlencode({"comp": comp})).decode()).get("submissions", [])

    def submission(self, comp, name):
        return self._req("/admin/submission?" + urllib.parse.urlencode({"comp": comp, "name": name}))

    def agentconfig(self, comp):
        return json.loads(self._req("/admin/agentconfig?" + urllib.parse.urlencode({"comp": comp})).decode())

    def classtoken(self):
        return json.loads(self._req("/admin/classtoken").decode()).get("classToken", "")

    def progress(self, comp):
        return json.loads(self._req("/admin/progress?" + urllib.parse.urlencode({"comp": comp})).decode()).get("progress", [])

    def progressfile(self, comp, name):
        return self._req("/admin/progressfile?" + urllib.parse.urlencode({"comp": comp, "name": name}))

    def restore(self, comp, kind, name, team, n):
        q = urllib.parse.urlencode({"comp": comp, "kind": kind, "name": name, "team": team, "n": n})
        return json.loads(self._req("/admin/restore?" + q, data=b"", method="POST").decode())


# ---------------- competition editor ----------------
class Editor(tk.Toplevel):
    STEPS = ["Name", "Levels", "Build & Deploy"]
    HELP = [
        "Give the competition a name. Its id (used on the server) is derived from the name.",
        "Add one level per Packet Tracer activity (start with 1). Browse the .pka and set "
        "the % needed to clear it. '+ Add level' for more.",
        "Generate builds the files locally; Deploy sends them to the server and makes it live. "
        "The config is saved locally so you can reload and edit this competition later.",
    ]

    def __init__(self, manager, manifest=None):
        super().__init__(manager.root)
        self.manager = manager
        self.pka_tool = manager.pka_tool
        self.title("Competition editor")
        self.geometry("820x660")
        self.transient(manager.root)   # stay above the manager window
        self.lift()
        self.focus_force()
        self.step = 0
        self.mode = tk.StringVar(value="wizard")
        self.name_var = tk.StringVar()
        self.out_var = tk.StringVar(value=os.path.join(DATA_DIR, "builds"))
        self.rows = []
        self.loaded_id = None
        if manifest:
            self._load(manifest)
        else:
            self._add_level_data()

        top = ttk.Frame(self, padding=(12, 8, 12, 0)); top.pack(fill="x")
        ttk.Label(top, text="Layout:").pack(side="left")
        ttk.Radiobutton(top, text="Wizard", value="wizard", variable=self.mode, command=self.render).pack(side="left")
        ttk.Radiobutton(top, text="One page", value="single", variable=self.mode, command=self.render).pack(side="left")
        self.header = ttk.Label(self, font=("TkDefaultFont", 13, "bold"), padding=(12, 6, 12, 2)); self.header.pack(anchor="w")
        self.instr = ttk.Label(self, wraplength=780, foreground="#2f5e97", padding=(12, 0, 12, 6)); self.instr.pack(anchor="w", fill="x")
        self.body = ttk.Frame(self, padding=(12, 0)); self.body.pack(fill="both", expand=True)
        self.nav = ttk.Frame(self, padding=(12, 4))
        self.back_btn = ttk.Button(self.nav, text="← Back", command=self.back); self.back_btn.pack(side="left")
        self.next_btn = ttk.Button(self.nav, text="Next →", command=self.nxt); self.next_btn.pack(side="right")
        self.log = scrolledtext.ScrolledText(self, height=6, state="disabled", font=("TkFixedFont", 9)); self.log.pack(fill="x", padx=12, pady=(0, 10))
        self.render()

    # data
    def _add_level_data(self, d=None):
        d = d or {}
        self.rows.append({
            "pka": tk.StringVar(value=d.get("pka", "")),
            "image": tk.StringVar(value=d.get("image", "")),
            "thresh": tk.StringVar(value=str(d.get("threshold", 100))),
            "key": d.get("key", ""), "hash": d.get("hash", ""),
        })

    def _load(self, manifest):
        self.name_var.set(manifest.get("name", ""))
        self.loaded_id = manifest.get("comp_id")
        self.out_var.set(manifest.get("out_folder", self.out_var.get()))
        for lv in manifest.get("levels", []):
            self._add_level_data(lv)
        if not self.rows:
            self._add_level_data()

    def logln(self, s):
        self.log.configure(state="normal"); self.log.insert("end", s + "\n"); self.log.see("end")
        self.log.configure(state="disabled"); self.update_idletasks()

    # nav / render
    def render(self):
        for w in self.body.winfo_children():
            w.destroy()
        if self.mode.get() == "wizard":
            if not self.nav.winfo_ismapped():
                self.nav.pack(fill="x", before=self.log)
            self.header.config(text=f"Step {self.step + 1} of 3:  {self.STEPS[self.step]}")
            self.instr.config(text=self.HELP[self.step])
            [self._p_name, self._p_levels, self._p_build][self.step](self.body)
            self.back_btn.config(state="normal" if self.step else "disabled")
            self.next_btn.config(state="normal" if self.step < 2 else "disabled",
                                 text="Next →" if self.step < 2 else "— last —")
        else:
            self.nav.pack_forget()
            self.header.config(text="All steps")
            self.instr.config(text="Fill each section, then Generate and Deploy.")
            inner = self._scroll(self.body)
            for i, t in enumerate(self.STEPS):
                lf = ttk.LabelFrame(inner, text=f"Step {i + 1} — {t}", padding=8); lf.pack(fill="x", pady=6, padx=2)
                ttk.Label(lf, text=self.HELP[i], wraplength=720, foreground="#777").pack(anchor="w", pady=(0, 6))
                [self._p_name, self._p_levels, self._p_build][i](lf)

    def _scroll(self, parent):
        cv = tk.Canvas(parent, highlightthickness=0); sb = ttk.Scrollbar(parent, orient="vertical", command=cv.yview)
        inner = ttk.Frame(cv); win = cv.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.bind("<Configure>", lambda e: cv.itemconfig(win, width=e.width))
        cv.configure(yscrollcommand=sb.set); cv.pack(side="left", fill="both", expand=True); sb.pack(side="right", fill="y")
        return inner

    def nxt(self):
        if self.step < 2:
            self.step += 1; self.render()

    def back(self):
        if self.step:
            self.step -= 1; self.render()

    # pages
    def _p_name(self, parent):
        g = ttk.Frame(parent); g.pack(fill="x")
        ttk.Label(g, text="Competition name:").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(g, textvariable=self.name_var, width=40).grid(row=0, column=1, sticky="we", pady=4)
        g.columnconfigure(1, weight=1)
        if self.loaded_id:
            ttk.Label(g, text=f"(editing existing: id={self.loaded_id})", foreground="#777").grid(row=1, column=1, sticky="w")

    def _p_levels(self, parent):
        for idx, r in enumerate(self.rows, start=1):
            row = ttk.LabelFrame(parent, text=f"Level {idx}", padding=6); row.pack(fill="x", pady=4)
            t = ttk.Frame(row); t.pack(fill="x")
            ttk.Button(t, text="Browse .pka…", command=lambda rr=r, n=idx: self._pick(rr, n)).pack(side="left")
            ttk.Label(t, textvariable=r["pka"], width=44, foreground="#555").pack(side="left", padx=6)
            b = ttk.Frame(row); b.pack(fill="x", pady=(4, 0))
            ttk.Label(b, text="image:").pack(side="left")
            ttk.Entry(b, textvariable=r["image"], width=26).pack(side="left", padx=4)
            ttk.Label(b, text="clear %:").pack(side="left", padx=(10, 0))
            ttk.Entry(b, textvariable=r["thresh"], width=5).pack(side="left", padx=4)
        btns = ttk.Frame(parent); btns.pack(anchor="w", pady=6)
        ttk.Button(btns, text="+ Add level", command=self._add).pack(side="left")
        if len(self.rows) > 1:
            ttk.Button(btns, text="Remove last", command=self._remove_last).pack(side="left", padx=6)

    def _p_build(self, parent):
        o = ttk.Frame(parent); o.pack(fill="x", pady=4)
        ttk.Label(o, text="Output folder:").pack(side="left")
        ttk.Entry(o, textvariable=self.out_var, width=48).pack(side="left", padx=4)
        ttk.Button(o, text="…", width=3, command=lambda: self.out_var.set(filedialog.askdirectory(parent=self) or self.out_var.get())).pack(side="left")
        b = ttk.Frame(parent); b.pack(fill="x", pady=10)
        ttk.Button(b, text="1. Generate", command=self.generate).pack(side="left")
        ttk.Button(b, text="2. Deploy", command=self.deploy).pack(side="left", padx=8)

    def _add(self):
        self._add_level_data(); self.render(); self.lift()

    def _remove_last(self):
        if len(self.rows) > 1:
            self.rows.pop(); self.render(); self.lift()

    def _pick(self, r, n):
        p = filedialog.askopenfilename(parent=self, title=f"Level {n} activity",
                                       filetypes=[("Packet Tracer Activity", "*.pka"), ("All files", "*.*")])
        self.lift(); self.focus_force()
        if p:
            r["pka"].set(p)
            if not r["image"].get():
                r["image"].set(slug_image(p, slug(self.name_var.get() or "comp"), n))

    # build
    def _comp_id(self):
        return self.loaded_id or slug(self.name_var.get())

    def generate(self):
        try:
            self._generate()
        except Exception as e:
            messagebox.showerror("Generate", str(e)); self.logln("ERROR: " + str(e))

    def _generate(self):
        name = self.name_var.get().strip()
        if not name:
            raise RuntimeError("enter a competition name (Step 1)")
        used = [r for r in self.rows if r["pka"].get().strip()]
        if not used:
            raise RuntimeError("add at least one level with a .pka (Step 2)")
        comp_id = self._comp_id()
        out = os.path.join(self.out_var.get().strip(), comp_id)
        os.makedirs(out, exist_ok=True)
        S = self.manager.settings
        levels_json, sarp_blocks, agent_levels, manifest_levels = [], [], [], []
        for idx, r in enumerate(used, start=1):
            pka = r["pka"].get().strip()
            image = r["image"].get().strip() or slug_image(pka, comp_id, idx)
            thresh = int(r["thresh"].get().strip() or "100")
            key = r["key"] or gen_key()      # reuse existing key on edit (sarpedon has it registered)
            r["key"] = key
            self.logln(f"Level {idx}: {os.path.basename(pka)} image={image} clear>={thresh}%")
            h = ""
            if self.pka_tool:
                h = extract_hash(self.pka_tool, pka)
                self.logln("  " + (f"hash={h}" if h else "unlocked (no pt_password)"))
            r["hash"] = h
            shutil.copyfile(pka, os.path.join(out, f"level{idx}.pka"))
            levels_json.append({"level": idx, "image": image, "threshold": thresh, "file": f"level{idx}.pka"})
            sarp_blocks.append(f'[[image]]\nname = "{image}"\ncolor = "#1BA0E2"\npassword = "{key}"')
            al = {"level": idx, "image": image, "password": key, "threshold": thresh}
            if h:
                al["pt_password"] = h
            agent_levels.append(al)
            manifest_levels.append({"level": idx, "pka": pka, "image": image, "threshold": thresh, "key": key, "hash": h})

        json.dump({"db": "mongodb://localhost:27017", "dbName": "sarpedon", "listen": "127.0.0.1:8099",
                   "filesDir": "/opt/levelsvc/levels", "uploadDir": "/opt/levelsvc/submissions",
                   "maxUploadMB": 128, "levels": levels_json},
                  open(os.path.join(out, "levels.json"), "w"), indent=2)
        json.dump({"remote": S.get("remote", ""), "levelsvc": S.get("levelsvc", ""), "comp": comp_id,
                   "interval": 10, "pt_app_id": S.get("pt_app_id", ""), "pt_secret": S.get("pt_secret", ""),
                   "levels": agent_levels},
                  open(os.path.join(out, "pt_agent.conf.json"), "w"), indent=2)
        with open(os.path.join(out, "sarpedon_images.conf"), "w") as f:
            f.write("# image blocks\n\n" + "\n\n".join(sarp_blocks) + "\n")
        # local manifest (reloadable)
        os.makedirs(DATA_DIR, exist_ok=True)
        json.dump({"name": name, "comp_id": comp_id, "out_folder": self.out_var.get().strip(),
                   "levels": manifest_levels},
                  open(os.path.join(DATA_DIR, comp_id + ".json"), "w"), indent=2)
        self.loaded_id = comp_id
        self._out = out
        self.logln(f"Generated '{name}' (id={comp_id}) in {out}. Now Deploy.")
        messagebox.showinfo("Generated", f"Built '{name}'.\nNext: Deploy.")

    def deploy(self):
        comp_id = self._comp_id()
        out = os.path.join(self.out_var.get().strip(), comp_id)
        if not os.path.exists(os.path.join(out, "levels.json")):
            messagebox.showerror("Deploy", "Click Generate first."); return
        try:
            adm = self.manager.admin()
        except Exception as e:
            messagebox.showerror("Deploy", str(e)); return
        if not messagebox.askyesno("Deploy", f"Make '{self.name_var.get()}' live now?"):
            return
        self.logln("Deploying…")
        threading.Thread(target=self._deploy_worker, args=(adm, comp_id, self.name_var.get().strip(), out), daemon=True).start()

    def _deploy_worker(self, adm, comp_id, name, out):
        try:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
                for fn in os.listdir(out):
                    if fn in ("levels.json", "sarpedon_images.conf", "pt_agent.conf.json") or fn.lower().endswith(".pka"):
                        zf.write(os.path.join(out, fn), fn)
            res = adm.deploy(comp_id, name, buf.getvalue())
            self.logln("Deploy OK: " + json.dumps(res))
            messagebox.showinfo("Deploy", "Live.\n\n" + json.dumps(res, indent=2))
            self.manager.refresh()
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            self.logln(f"Deploy failed HTTP {e.code}: {body}")
            messagebox.showerror("Deploy", f"HTTP {e.code}: {body or e.reason}")
        except Exception as e:
            self.logln("Deploy failed: " + str(e)); messagebox.showerror("Deploy", str(e))


# ---------------- manager (home) ----------------
class ManagerApp:
    def __init__(self, root):
        self.root = root
        self.pka_tool = find_pka_tool()
        self.settings = self._load_settings()
        root.title("Cisco Scoreboard Manager")
        root.geometry("860x600")

        s = ttk.LabelFrame(root, text="Server connection", padding=8)
        s.pack(fill="x", padx=10, pady=8)
        self.svars = {}
        for i, (k, label, d) in enumerate(APP_SETTINGS):
            ttk.Label(s, text=label + ":").grid(row=i // 2, column=(i % 2) * 2, sticky="w", pady=2, padx=(0, 4))
            v = tk.StringVar(value=self.settings.get(k, d))
            ttk.Entry(s, textvariable=v, width=42, show=("*" if k in ("pt_secret", "admin_token") else "")).grid(
                row=i // 2, column=(i % 2) * 2 + 1, sticky="we", pady=2)
            self.svars[k] = v
        s.columnconfigure(1, weight=1); s.columnconfigure(3, weight=1)
        ttk.Button(s, text="Save + Refresh", command=self.save_and_refresh).grid(row=3, column=3, sticky="e", pady=4)

        c = ttk.LabelFrame(root, text="Competitions on the server", padding=8)
        c.pack(fill="both", expand=True, padx=10, pady=(0, 8))
        cols = ("name", "id", "levels", "default", "hidden", "subs")
        self.tree = ttk.Treeview(c, columns=cols, show="headings", height=10)
        for col, txt, w in [("name", "Name", 200), ("id", "Id", 170), ("levels", "# of levels", 70),
                            ("default", "Default", 60), ("hidden", "Hidden", 60), ("subs", "Submissions", 90)]:
            self.tree.heading(col, text=txt); self.tree.column(col, width=w)
        self.tree.pack(fill="both", expand=True, side="left")
        sb = ttk.Scrollbar(c, orient="vertical", command=self.tree.yview); sb.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=sb.set)

        btns = ttk.Frame(root, padding=(10, 0, 10, 10)); btns.pack(fill="x")
        ttk.Button(btns, text="New competition", command=self.new).pack(side="left")
        ttk.Button(btns, text="Edit", command=self.edit).pack(side="left", padx=4)
        ttk.Button(btns, text="Set as default", command=self.set_default).pack(side="left", padx=4)
        ttk.Button(btns, text="Hide / Show", command=self.toggle_hidden).pack(side="left", padx=4)
        ttk.Button(btns, text="Remove", command=self.remove).pack(side="left", padx=4)
        ttk.Button(btns, text="Review submissions", command=self.review).pack(side="right")
        ttk.Button(btns, text="Student bootstrap…", command=self.student_bootstrap).pack(side="right", padx=4)
        ttk.Button(btns, text="Export agent config", command=self.export_config).pack(side="right", padx=4)

        self.status = ttk.Label(root, text="", foreground="#2f5e97", padding=(10, 0, 10, 6)); self.status.pack(anchor="w")
        self.refresh()

    # settings
    def _load_settings(self):
        try:
            return json.load(open(SETTINGS_FILE))
        except Exception:
            return {k: d for k, _, d in APP_SETTINGS}

    def _save_settings(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        self.settings = {k: self.svars[k].get().strip() for k in self.svars}
        json.dump(self.settings, open(SETTINGS_FILE, "w"), indent=2)

    def save_and_refresh(self):
        self._save_settings(); self.refresh()

    def admin(self):
        base = self.svars["levelsvc"].get().strip()
        token = self.svars["admin_token"].get().strip()
        if not base or not token:
            raise RuntimeError("fill in Levels service URL and Admin token")
        return Admin(base, token)

    # list
    def refresh(self):
        self._save_settings()
        for i in self.tree.get_children():
            self.tree.delete(i)
        try:
            comps = self.admin().competitions()
        except Exception as e:
            self.status.config(text="Could not reach server: " + str(e)); return
        for cp in comps:
            self.tree.insert("", "end", iid=cp["id"],
                             values=(cp["name"], cp["id"], cp["levels"], "★" if cp.get("default") else "",
                                     "yes" if cp["hidden"] else "", cp["submissions"]))
        self.status.config(text=f"{len(comps)} competition(s). Local configs: {self._manifest_ids()}")

    def _manifest_ids(self):
        try:
            return ", ".join(sorted(f[:-5] for f in os.listdir(DATA_DIR) if f.endswith(".json") and f != "settings.json")) or "(none)"
        except Exception:
            return "(none)"

    def _selected(self):
        sel = self.tree.selection()
        return sel[0] if sel else None

    # actions
    def new(self):
        Editor(self)

    def edit(self):
        cid = self._selected()
        mani_path = os.path.join(DATA_DIR, (cid or "") + ".json")
        if cid and os.path.exists(mani_path):
            Editor(self, manifest=json.load(open(mani_path)))
        elif cid:
            messagebox.showinfo("Edit", f"No local config for '{cid}' on this machine "
                                        "(it was deployed elsewhere). You can still Hide/Show/Remove/Review it, "
                                        "or make a New competition.")
        else:
            messagebox.showinfo("Edit", "Select a competition first (or click New).")

    def toggle_hidden(self):
        cid = self._selected()
        if not cid:
            return
        vals = self.tree.item(cid, "values")
        action = "show" if vals[4] == "yes" else "hide"  # (name,id,levels,default,hidden,subs)
        try:
            self.admin().competition(cid, action); self.refresh()
        except Exception as e:
            messagebox.showerror("Hide/Show", str(e))

    def remove(self):
        cid = self._selected()
        if not cid:
            return
        if not messagebox.askyesno("Remove", f"Remove competition '{cid}' from the server?\n"
                                             "(Level files are deleted; student submissions are kept.)"):
            return
        try:
            self.admin().competition(cid, "remove"); self.refresh()
        except Exception as e:
            messagebox.showerror("Remove", str(e))

    def set_default(self):
        cid = self._selected()
        if not cid:
            messagebox.showinfo("Set as default", "Select a competition first."); return
        try:
            self.admin().competition(cid, "default"); self.refresh()
            self.status.config(text=f"'{cid}' is now the default — students who just click Start get it.")
        except Exception as e:
            messagebox.showerror("Set as default", str(e))

    def student_bootstrap(self):
        """Write the tiny file students get: the server URL + shared class token.
        The agent fetches the full competition list (and keys) from the server on open."""
        self._save_settings()
        base = self.settings.get("levelsvc", "")
        if not base:
            messagebox.showinfo("Student bootstrap", "Set the Levels service URL first."); return
        try:
            token = self.admin().classtoken()
        except Exception as e:
            messagebox.showerror("Student bootstrap", str(e)); return
        if not token:
            messagebox.showerror("Student bootstrap", "Server returned no class token."); return
        boot = {"levelsvc": base, "class_token": token, "interval": 10, "auto_launch": True}
        dest = filedialog.asksaveasfilename(initialfile="pt_agent.conf.json", defaultextension=".json",
                                            title="Save student bootstrap config")
        if not dest:
            return
        json.dump(boot, open(dest, "w"), indent=2)
        messagebox.showinfo("Student bootstrap",
                            f"Wrote {dest}\n\nGive students this file + the agent (pt_agent.exe) + ptagent.pta.\n"
                            "When they open the agent it loads every competition from the server, with your "
                            "default pre-selected. Class token is shared by all students.")

    def export_config(self):
        cid = self._selected()
        if not cid:
            messagebox.showinfo("Export", "Select a competition first."); return
        self._save_settings()
        try:
            data = self.admin().agentconfig(cid)
        except Exception as e:
            messagebox.showerror("Export", str(e)); return
        S = self.settings
        cfg = {"remote": S.get("remote", ""), "levelsvc": S.get("levelsvc", ""), "comp": data["comp"],
               "interval": 10, "auto_launch": True,
               "pt_app_id": S.get("pt_app_id", ""), "pt_secret": S.get("pt_secret", ""), "levels": []}
        for l in data.get("levels", []):
            al = {"level": l["level"], "image": l["image"], "password": l.get("password", ""),
                  "threshold": l.get("threshold", 100)}
            if l.get("ptPassword"):
                al["pt_password"] = l["ptPassword"]
            cfg["levels"].append(al)
        if not cfg["levels"] or not any(l.get("password") for l in cfg["levels"]):
            messagebox.showwarning("Export", "This competition has no stored keys yet.\n\n"
                                    "Re-deploy it once with this manager (Edit → Deploy) to populate them, "
                                    "then export again.")
            return
        dest = filedialog.asksaveasfilename(initialfile="pt_agent.conf.json", defaultextension=".json",
                                            title=f"Save {cid} agent config")
        if dest:
            json.dump(cfg, open(dest, "w"), indent=2)
            messagebox.showinfo("Export", f"Wrote {dest}\n\nShip this with the agent + ptagent.pta to students.")

    def review(self):
        cid = self._selected()
        if not cid:
            messagebox.showinfo("Review", "Select a competition first."); return
        try:
            adm = self.admin()
            prog = adm.progress(cid)
            subs = adm.submissions(cid)
        except Exception as e:
            messagebox.showerror("Review", str(e)); return
        win = tk.Toplevel(self.root); win.title(f"Review — {cid}"); win.geometry("680x460")
        win.transient(self.root)
        ttk.Label(win, wraplength=660, justify="left", foreground="#2f5e97", padding=(8, 6),
                  text="“Paused (live)” is each team's current work — it appears the moment a student clicks "
                       "Stop or Finish, one per team & level, always the latest. “Final” submissions are the "
                       "timestamped copies saved when a student clicks Finish Competition.").pack(anchor="w")
        cols = ("kind", "team", "level", "file", "bytes", "modified")
        tv = ttk.Treeview(win, columns=cols, show="headings", height=14)
        for col, txt, wdt in [("kind", "Kind", 90), ("team", "Team", 130), ("level", "Lvl", 40),
                              ("file", "File", 210), ("bytes", "Bytes", 70), ("modified", "Modified (UTC)", 150)]:
            tv.heading(col, text=txt); tv.column(col, width=wdt)
        tv.pack(fill="both", expand=True, padx=8)
        rows = []  # parallel to tree items
        for p in sorted(prog, key=lambda s: s.get("modified", ""), reverse=True):
            tv.insert("", "end", values=("paused (live)", p.get("team", ""), p.get("level", ""),
                                         p["name"], p["bytes"], p.get("modified", "")))
            rows.append({"kind": "progress", "name": p["name"],
                         "team": str(p.get("team", "")), "level": str(p.get("level", ""))})
        for s in sorted(subs, key=lambda s: s.get("modified", ""), reverse=True):
            team, level = parse_sub_name(s["name"])
            tv.insert("", "end", values=("final", team, level, s["name"], s["bytes"], s.get("modified", "")))
            rows.append({"kind": "submission", "name": s["name"], "team": team, "level": level})

        def _sel():
            sel = tv.selection()
            return rows[tv.index(sel[0])] if sel else None

        def dl():
            row = _sel()
            if not row:
                return
            nm = row["name"]
            dest = filedialog.asksaveasfilename(initialfile=nm, defaultextension=".pka", parent=win)
            if not dest:
                return
            try:
                data = adm.progressfile(cid, nm) if row["kind"] == "progress" else adm.submission(cid, nm)
                open(dest, "wb").write(data)
                messagebox.showinfo("Download", "Saved " + dest, parent=win)
            except Exception as e:
                messagebox.showerror("Download", str(e), parent=win)

        def restore():
            row = _sel()
            if not row:
                return
            if not (row.get("team") and row.get("level")):
                messagebox.showwarning("Restore", "Can't determine the team/level for this file.", parent=win); return
            if not messagebox.askyesno("Restore for resume",
                    f"Make this the resumable copy for team “{row['team']}”, level {row['level']}?\n\n"
                    "The student can then reopen the agent, pick this competition, enter the same Team ID and "
                    "click Start to continue from this exact file — even if they had clicked Finish Competition.",
                    parent=win):
                return
            try:
                adm.restore(cid, row["kind"], row["name"], row["team"], row["level"])
                messagebox.showinfo("Restore",
                    f"Restored. Team “{row['team']}” can reopen the agent and click Start to continue.",
                    parent=win)
                win.destroy(); self.review()
            except Exception as e:
                messagebox.showerror("Restore", str(e), parent=win)

        bb = ttk.Frame(win); bb.pack(fill="x", pady=6)
        ttk.Button(bb, text="Download selected", command=dl).pack(side="left", padx=8)
        ttk.Button(bb, text="Restore (let team resume)", command=restore).pack(side="left", padx=4)
        ttk.Button(bb, text="Refresh", command=lambda: (win.destroy(), self.review())).pack(side="left", padx=4)
        ttk.Button(bb, text="Close", command=win.destroy).pack(side="right", padx=8)
        win.lift()


def main():
    root = tk.Tk()
    ManagerApp(root)
    if os.environ.get("PT_MGR_SELFTEST"):
        root.after(1500, root.destroy)
    root.mainloop()


if __name__ == "__main__":
    main()
