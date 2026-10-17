#!/usr/bin/env python3
"""Run a practice scenario for real on a throwaway machine (CI: GitHub's Ubuntu / Windows runners),
as root/administrator, using the agent's own engine:
  1. setup        -> nothing may score yet (every problem is in place)
  2. the fixes    -> every problem must score, and no penalty
  3. the penalty script, if there is one (<name>.penalty.sh / .ps1 next to the fix script)
                  -> every penalty must fire
  4. setup again  -> nothing may score (setup forces each problem back, even on a hardened machine)
Usage: run_scenario.py <scenario.json> <fix script>.   Never run this on a real computer."""
import importlib.util, json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("pt_agent", os.path.join(HERE, "..", "..", "pt_agent.py"))
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)


def score(scen, answers=None):
    """-> (each problem's state, each penalty's state). `answers` stands in for the forensics
    answers a student would type; pass them only when simulating a fully-worked machine."""
    items = A.ScenarioChecks(answers).score(scen["checks"])
    for i in items:
        print(f"  [{'x' if i['earned'] else ' '}] {i['name']} ({i['points']})")
    return ([i["earned"] for i in items if i["points"] >= 0], [i["earned"] for i in items if i["points"] < 0])


def setup(scen):
    code, out, err = A.run_script(scen["setup"], timeout=900)
    print(out + err)
    if code != 0:
        sys.exit(f"setup failed: exit {code}")


def run(script):
    argv = (["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script] if A.host_os() == "windows"
            else ["bash", script])
    if subprocess.run(argv).returncode != 0:
        sys.exit(f"{script} failed")


def main():
    path, fix = sys.argv[1], sys.argv[2]
    if not A.is_admin():
        sys.exit("run as root / administrator")
    scen = json.load(open(path, encoding="utf-8"))
    if scen["os"] != A.host_os():
        sys.exit(f"{path} is for {scen['os']}, this is {A.host_os()}")
    # Forensics answers a worked machine would have typed (see AnswerHash checks). Fed only on the
    # fixed/penalty passes, never at setup, so "nothing scores at setup" still holds.
    import re as _re
    answers_path = _re.sub(r"\.fix\.(sh|ps1)$", ".answers.json", fix)
    answers = json.load(open(answers_path, encoding="utf-8")) if os.path.exists(answers_path) else {}
    bad = []
    print("== setup"); setup(scen)
    fixed, pens = score(scen)                         # no answers: forensics must not score here
    if any(fixed) or any(pens):
        bad.append("something already counts right after setup")
    print("== fixes"); run(fix)
    fixed, pens = score(scen, answers)                # fixes applied + forensics answered
    if not all(fixed):
        bad.append("not every problem scores after the fixes")
    if any(pens):
        bad.append("the fixes set off a penalty")
    penalty = fix.replace(".fix.", ".penalty.")
    if pens and os.path.exists(penalty):
        print("== penalties"); run(penalty)
        if not all(score(scen, answers)[1]):
            bad.append("not every penalty fires")
    elif pens:
        print(f"(no {os.path.basename(penalty)}: penalties not exercised)")
    print("== setup again (on the fixed machine)"); setup(scen)
    fixed, pens = score(scen)                         # no answers again
    if any(fixed) or any(pens):
        bad.append("setup didn't put every problem back")
    if bad:
        sys.exit("FAILED: " + "; ".join(bad))
    print(f"OK: {scen['title']} ({len(scen['checks'])} checks)")


if __name__ == "__main__":
    main()
