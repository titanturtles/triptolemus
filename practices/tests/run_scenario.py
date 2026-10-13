#!/usr/bin/env python3
"""Run a practice scenario for real on a throwaway machine (CI: GitHub's Ubuntu / Windows runners),
as root/administrator, using the agent's own engine:
  1. setup        -> nothing may score yet (every problem is in place)
  2. the fixes    -> every check must score
  3. setup again  -> nothing may score (setup forces each problem back, even on a hardened machine)
Usage: run_scenario.py <scenario.json> <fix script>.   Never run this on a real computer."""
import importlib.util, json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("pt_agent", os.path.join(HERE, "..", "..", "pt_agent.py"))
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)


def score(scen):
    items = A.ScenarioChecks().score(scen["checks"])
    for i in items:
        print(f"  [{'x' if i['earned'] else ' '}] {i['name']} ({i['points']})")
    return [i["earned"] for i in items]


def setup(scen):
    code, out, err = A.run_script(scen["setup"], timeout=900)
    print(out + err)
    if code != 0:
        sys.exit(f"setup failed: exit {code}")


def main():
    path, fix = sys.argv[1], sys.argv[2]
    if not A.is_admin():
        sys.exit("run as root / administrator")
    scen = json.load(open(path, encoding="utf-8"))
    if scen["os"] != A.host_os():
        sys.exit(f"{path} is for {scen['os']}, this is {A.host_os()}")
    bad = []
    print("== setup"); setup(scen)
    if any(score(scen)):
        bad.append("something already scores right after setup")
    print("== fixes")
    argv = (["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", fix] if A.host_os() == "windows"
            else ["bash", fix])
    if subprocess.run(argv).returncode != 0:
        sys.exit("the fix script failed")
    if not all(score(scen)):
        bad.append("not every check scores after the fixes")
    print("== setup again (on the fixed machine)"); setup(scen)
    if any(score(scen)):
        bad.append("setup didn't put every problem back")
    if bad:
        sys.exit("FAILED: " + "; ".join(bad))
    print(f"OK: {scen['title']} ({len(scen['checks'])} checks)")


if __name__ == "__main__":
    main()
