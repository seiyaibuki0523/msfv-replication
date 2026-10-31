#!/usr/bin/env python3
"""AISEC Lab — GUI experiment console (Tkinter window).

Pick a detect model + verify model + ship policy + target (a bundled
benchmark, a local repo path, or a GitHub URL to clone), press Run, and watch
the 4-config ablation live. Wraps run_ablation_fast.py; reuses aisec_lab.py's
status/vLLM helpers.

Launch:
  python3 \
      <MSFV_ROOT>/experiments/aisec_gui.py
"""
from __future__ import annotations

import os
import subprocess
import threading
import time
from pathlib import Path

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

EXP = Path(os.path.join(os.environ.get("MSFV_ROOT", Path(__file__).resolve().parent.parent), "experiments"))
VENV_PY = os.environ.get("MSFV_PYTHON", "python3")
CLONES = Path(os.path.join(os.environ.get("MSFV_SCAN_TARGETS", "/path/to/_scan_targets"), "_gui_clones"))
LOGDIR = Path("/tmp/aisec_gui"); LOGDIR.mkdir(exist_ok=True)

import sys
sys.path.insert(0, str(EXP))
import aisec_lab as LAB  # _vllm_health, _final, _live_state, CONFIGS, BENCHMARKS

# Detect-model → AISEC_FAST_CHAIN (primary + fallback). Verify is separate.
DETECT_CHAINS = {
    "qwen (fast)":        "vllm:qwen3-coder,vllm:nemotron-120b",
    "gemma-31B":          "vllm:gemma-4-31b,vllm:nemotron-120b",
    "nemotron-120B":      "vllm:nemotron-120b",
    "nemotron (cloud)":   "nvidia:nemotron-120b",
}
VERIFY_BACKENDS = {
    "nemotron (self)":  "vllm:nemotron-120b",
    "nemotron (cloud)": "nvidia:nemotron-120b",
    "sonnet":           "sonnet",
}
POLICIES = {"precision (≥medium)": "medium", "recall (≥low)": "low"}
BENCHMARKS = ["dvd", "pygoat", "nodegoat", "smartbugs", "smartbugs_sampled"]
CONFIGS = ["baseline", "full", "nosource", "nopoc"]


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AISEC Lab — Experiment Console")
        self.geometry("980x720")
        self.proc: subprocess.Popen | None = None
        self.logpath: Path | None = None
        self.cur_name = tk.StringVar(value="")
        self._build()
        self._refresh_status()
        self._refresh_health()

    # ---- layout ----------------------------------------------------------
    def _build(self):
        pad = dict(padx=8, pady=4)
        # Header: vLLM health
        top = ttk.Frame(self); top.pack(fill="x", **pad)
        ttk.Label(top, text="AISEC Lab", font=("", 15, "bold")).pack(side="left")
        self.health = ttk.Label(top, text="checking vLLM…", foreground="#888")
        self.health.pack(side="right")

        # Config row
        cfg = ttk.LabelFrame(self, text="Configuration"); cfg.pack(fill="x", **pad)
        self.detect = tk.StringVar(value="qwen (fast)")
        self.verify = tk.StringVar(value="nemotron (self)")
        self.policy = tk.StringVar(value="precision (≥medium)")
        self.conc = tk.StringVar(value="8")
        for i, (lbl, var, opts) in enumerate([
            ("Detect model", self.detect, list(DETECT_CHAINS)),
            ("Verify model", self.verify, list(VERIFY_BACKENDS)),
            ("Ship policy", self.policy, list(POLICIES)),
        ]):
            ttk.Label(cfg, text=lbl).grid(row=0, column=i*2, sticky="e", padx=4, pady=6)
            ttk.Combobox(cfg, textvariable=var, values=opts, state="readonly",
                         width=18).grid(row=0, column=i*2+1, sticky="w", padx=4)
        ttk.Label(cfg, text="Concurrency").grid(row=1, column=0, sticky="e", padx=4)
        ttk.Entry(cfg, textvariable=self.conc, width=6).grid(row=1, column=1, sticky="w")

        # Target row
        tgt = ttk.LabelFrame(self, text="Target"); tgt.pack(fill="x", **pad)
        self.mode = tk.StringVar(value="benchmark")
        ttk.Radiobutton(tgt, text="Benchmark", variable=self.mode, value="benchmark",
                        command=self._mode).grid(row=0, column=0, sticky="w")
        self.bench = tk.StringVar(value="dvd")
        self.bench_cb = ttk.Combobox(tgt, textvariable=self.bench, values=BENCHMARKS,
                                     state="readonly", width=20)
        self.bench_cb.grid(row=0, column=1, sticky="w", padx=4)

        ttk.Radiobutton(tgt, text="Local path", variable=self.mode, value="local",
                        command=self._mode).grid(row=1, column=0, sticky="w")
        self.local = tk.StringVar()
        self.local_e = ttk.Entry(tgt, textvariable=self.local, width=60)
        self.local_e.grid(row=1, column=1, sticky="w", padx=4)
        self.browse_b = ttk.Button(tgt, text="Browse…", command=self._browse)
        self.browse_b.grid(row=1, column=2, padx=4)

        ttk.Radiobutton(tgt, text="GitHub repo", variable=self.mode, value="github",
                        command=self._mode).grid(row=2, column=0, sticky="w")
        self.gh = tk.StringVar()
        self.gh_e = ttk.Entry(tgt, textvariable=self.gh, width=60)
        self.gh_e.grid(row=2, column=1, sticky="w", padx=4)
        self.gh_e.insert(0, "https://github.com/owner/repo")

        # Controls
        ctl = ttk.Frame(self); ctl.pack(fill="x", **pad)
        self.run_b = ttk.Button(ctl, text="▶ Run", command=self._run)
        self.run_b.pack(side="left")
        self.stop_b = ttk.Button(ctl, text="■ Stop", command=self._stop, state="disabled")
        self.stop_b.pack(side="left", padx=6)
        self.status_lbl = ttk.Label(ctl, text="idle", foreground="#888")
        self.status_lbl.pack(side="left", padx=12)

        # Status table
        st = ttk.LabelFrame(self, text="Ablation status"); st.pack(fill="both", expand=False, **pad)
        self.tree = ttk.Treeview(st, columns=CONFIGS, show="tree headings", height=6)
        self.tree.heading("#0", text="benchmark")
        self.tree.column("#0", width=160)
        for c in CONFIGS:
            self.tree.heading(c, text=c); self.tree.column(c, width=170)
        self.tree.pack(fill="x", padx=4, pady=4)

        # Log tail
        lg = ttk.LabelFrame(self, text="Log"); lg.pack(fill="both", expand=True, **pad)
        self.log = tk.Text(lg, height=12, bg="#111", fg="#ddd", font=("Menlo", 10),
                           wrap="none")
        self.log.pack(fill="both", expand=True, padx=4, pady=4)
        self._mode()

    def _mode(self):
        m = self.mode.get()
        self.bench_cb.configure(state="readonly" if m == "benchmark" else "disabled")
        self.local_e.configure(state="normal" if m == "local" else "disabled")
        self.browse_b.configure(state="normal" if m == "local" else "disabled")
        self.gh_e.configure(state="normal" if m == "github" else "disabled")

    def _browse(self):
        d = filedialog.askdirectory(title="Select repo directory")
        if d:
            self.local.set(d)

    # ---- run -------------------------------------------------------------
    def _run(self):
        if self.proc and self.proc.poll() is None:
            messagebox.showwarning("Busy", "A run is already in progress."); return
        threading.Thread(target=self._run_thread, daemon=True).start()

    def _run_thread(self):
        try:
            target = self._resolve_target()
        except Exception as e:  # noqa: BLE001
            self._ui(lambda: messagebox.showerror("Target error", str(e))); return
        if not target:
            return
        env = dict(os.environ)
        env["AISEC_FAST_CHAIN"] = DETECT_CHAINS[self.detect.get()]
        env["AISEC_VERIFY_BACKEND_OVERRIDE"] = VERIFY_BACKENDS[self.verify.get()]
        env["AISEC_SHIP_MIN_SEVERITY"] = POLICIES[self.policy.get()]
        env["AISEC_LAB_CONCURRENCY"] = self.conc.get().strip() or "8"
        env["AISEC_LLM_TIMEOUT"] = "240"
        name = target if target in BENCHMARKS else Path(target).name
        self.cur_name.set(name)
        self.logpath = LOGDIR / f"{name}.log"
        self._ui(lambda: self._set_running(True, f"running {name}…"))
        with open(self.logpath, "w") as lf:
            self.proc = subprocess.Popen(
                [VENV_PY, str(EXP / "run_ablation_fast.py"), target],
                cwd=str(EXP), env=env, stdout=lf, stderr=subprocess.STDOUT)
        rc = self.proc.wait()
        self._ui(lambda: self._set_running(False, f"{name} finished (rc={rc})"))

    def _resolve_target(self) -> str | None:
        m = self.mode.get()
        if m == "benchmark":
            return self.bench.get()
        if m == "local":
            p = self.local.get().strip()
            if not p or not Path(p).is_dir():
                raise ValueError("Local path is not a directory")
            return p
        # github
        url = self.gh.get().strip()
        if not url.startswith(("http://", "https://", "git@")):
            raise ValueError("Enter a valid git URL")
        CLONES.mkdir(parents=True, exist_ok=True)
        name = url.rstrip("/").split("/")[-1].removesuffix(".git")
        dest = CLONES / name
        self._ui(lambda: self._set_running(True, f"cloning {name}…"))
        if dest.exists():
            self._log_line(f"[clone] {dest} exists — reusing\n")
            return str(dest)
        r = subprocess.run(["git", "clone", "--depth", "1", url, str(dest)],
                           capture_output=True, text=True)
        self._log_line((r.stdout or "") + (r.stderr or "") + "\n")
        if r.returncode != 0:
            self._ui(lambda: messagebox.showerror("Clone failed", r.stderr[-300:]))
            self._ui(lambda: self._set_running(False, "clone failed"))
            return None
        return str(dest)

    def _stop(self):
        if self.proc and self.proc.poll() is None:
            subprocess.run(["pkill", "-f", "run_ablation_fast"], check=False)
            self._set_running(False, "stopped")

    def _set_running(self, running: bool, msg: str):
        self.status_lbl.configure(text=msg, foreground="#c60" if running else "#888")
        self.run_b.configure(state="disabled" if running else "normal")
        self.stop_b.configure(state="normal" if running else "disabled")

    # ---- refresh loops ---------------------------------------------------
    def _refresh_status(self):
        # table: current target's benchmark row(s)
        name = self.cur_name.get()
        rows = [name] if name else BENCHMARKS
        self.tree.delete(*self.tree.get_children())
        for bm in rows:
            vals = []
            for c in CONFIGS:
                fin = LAB._final(bm, c); live = LAB._live_state(bm, c)
                if fin:
                    vals.append(f"✓ ship {fin.get('shipped','?')}/{fin.get('findings_count','?')}")
                elif live:
                    vals.append(f"● {live.get('current_phase','run')}")
                else:
                    vals.append("○")
            self.tree.insert("", "end", text=bm, values=vals)
        # log tail
        if self.logpath and self.logpath.exists():
            try:
                txt = self.logpath.read_text(errors="ignore")
                tail = "\n".join(l for l in txt.splitlines()
                                 if "LiteLLM" not in l and "botocore" not in l)[-4000:]
                self.log.delete("1.0", "end"); self.log.insert("1.0", tail)
                self.log.see("end")
            except OSError:
                pass
        self.after(3000, self._refresh_status)

    def _refresh_health(self):
        def probe():
            try:
                ok, msg = LAB._vllm_health()
            except Exception:  # noqa: BLE001
                ok, msg = False, "health check failed"
            self._ui(lambda: self.health.configure(
                text=("● " if ok else "✗ ") + msg,
                foreground="#2a2" if ok else "#c22"))
        threading.Thread(target=probe, daemon=True).start()
        self.after(15000, self._refresh_health)

    def _ui(self, fn):
        self.after(0, fn)

    def _log_line(self, s: str):
        self._ui(lambda: (self.log.insert("end", s), self.log.see("end")))


if __name__ == "__main__":
    App().mainloop()
