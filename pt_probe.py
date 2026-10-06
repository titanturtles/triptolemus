#!/usr/bin/env python3
"""pt_probe.py — discover what per-item assessment detail Packet Tracer's IPC exposes.

Read-only. Run it on a machine with Packet Tracer open and a graded .pka loaded
(unlock the activity first, or pass --pt-password <stored-hash> from `pka_tool -pass`).
It calls a batch of candidate ActivityFile IPC methods and prints what each returns,
so we can see whether per-item scoring (titles / points / correct-incorrect) is reachable
beyond the aggregate counts the agent already uses.

  python3 pt_probe.py
  python3 pt_probe.py --pt-password <32-hex-hash>
  python3 pt_probe.py -c pt_agent.bootstrap.json
"""
import argparse
import sys

import pt_agent as A

# no-argument methods to try on getActiveFile()
NOARG = [
    "getSavedFilename", "isActivityFile", "isPasswordConfirmed",
    "getPercentageComplete", "getPercentageCompleteScore", "getScore", "getMaxScore",
    "getAssessmentItemsCount", "getCorrectAssessmentItemsCount",
    "getConnectivityTestsCount", "getCorrectConnectivityTestsCount",
    "getNetworkComponentsCount", "getCorrectNetworkComponentsCount",
    "getItemCount", "getActivityItemCount",
    "getActivityFeedback", "getFeedback", "getFeedbackString", "getResultsHtml",
    "getActivitySummary", "getActivity", "getAssessmentTree", "getAssessmentModel",
    "getUserProfile",
]
# indexed accessors that might return an item/object for index 0
INDEXED = ["getAssessmentItem", "getItem", "getActivityItem", "getChild"]
# detail getters to try on whatever an indexed accessor returns
DETAIL = ["getName", "getDescription", "getText", "getFeedback", "isCorrect",
          "getScore", "getPoints", "getMaxScore", "getPercentageComplete"]


def pc(client, *steps):
    try:
        return repr(client.call(*steps))
    except Exception as e:
        return "ERR: " + str(e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-c", "--config", default=A.CONF_DEFAULT)
    ap.add_argument("--pt-password", help="stored activity hash to unlock (pka_tool -pass file.pka)")
    args = ap.parse_args()

    cfg = A.load_cfg(A.resolve_config(args.config))
    shared, _comps, _d = A.resolve_enrollment(cfg)
    app_id, secret = shared.get("pt_app_id"), shared.get("pt_secret")
    if not (app_id and secret):
        sys.exit("no pt_app_id/pt_secret available from the config/enroll")

    client = A.PTMPClient(app_id, secret).connect()
    print(f"connected to Packet Tracer on port {client.port}")
    af = (("appWindow",), ("getActiveFile",))
    if not client.active("isActivityFile"):
        sys.exit("open a graded .pka in Packet Tracer first")
    if not client.active("isPasswordConfirmed"):
        if args.pt_password and client.active("confirmPassword", args.pt_password):
            print("activity unlocked with --pt-password")
        else:
            print("WARNING: activity is locked; pass --pt-password <hash> for full detail")

    print("\n== no-arg methods on getActiveFile() ==")
    for m in NOARG:
        print(f"  {m:34s} -> {pc(client, *af, (m,))}")

    print("\n== indexed item access (index 0) + detail getters ==")
    for acc in INDEXED:
        base = pc(client, *af, (acc, 0))
        print(f"  {acc}(0) -> {base}")
        if base.startswith("ERR"):
            continue
        for d in DETAIL:
            print(f"      .{d:26s} -> {pc(client, *af, (acc, 0), (d,))}")

    print("\n== getUserProfile() object methods (it returned an object handle) ==")
    up = af + (("getUserProfile",),)
    for m in ["getName", "getUserName", "getFirstName", "getLastName", "getEmail",
              "getActivity", "getItemCount", "getChildCount", "getAssessmentItemsCount",
              "getCorrectAssessmentItemsCount", "getScore", "getPercentageComplete",
              "getPercentageCompleteScore", "getItems", "getChildren", "getFeedback",
              "toString", "getClassName"]:
        print(f"  userProfile.{m:30s} -> {pc(client, *up, (m,))}")
    for acc in ["getItem", "getChild", "getAssessmentItem", "getResult"]:
        r = pc(client, *up, (acc, 0))
        print(f"  userProfile.{acc}(0) -> {r}")
        if not r.startswith("ERR"):
            for d in DETAIL:
                print(f"      .{d:26s} -> {pc(client, *up, (acc, 0), (d,))}")

    print("\n== more ActivityFile candidates ==")
    for m in ["getActivityItemList", "getItems", "getAssessmentItemList", "getActivityResults",
              "getNetworkDescription", "getInstructions", "getTree", "getModel",
              "getActivityItems", "getAssessmentItems"]:
        print(f"  {m:30s} -> {pc(client, *af, (m,))}")
    for m in ["getItemResult", "getItemScore", "getItemName", "getItemFeedback",
              "getItemAt", "getAssessmentItemAt", "isItemCorrect"]:
        print(f"  {m}(0) -> {pc(client, *af, (m, 0))}")

    print("\n== score-count totals ==")
    for m in ["getAssessmentScoreCount", "getCorrectAssessmentScoreCount"]:
        print(f"  {m:30s} -> {pc(client, *af, (m,))}")

    print("\n== comparator tree (THE per-item path) ==")
    for tm in ["getComparatorTree", "getAssessedComparatorTree", "getLastAssessedComparatorTree"]:
        print(f"  {tm}() -> {pc(client, *af, (tm,))}")

    TREE = "getAssessedComparatorTree"   # the live assessed tree

    def node(path, prop, *a):
        steps = list(af) + [(TREE,)] + [("getChildNodeAt", i) for i in path] + [(prop,) + a]
        try:
            return client.call(*steps)
        except Exception as e:
            return "ERR:" + str(e)

    print(f"\n  -- node getters on {TREE}() root --")
    for g in ["getNodeId", "getNodeName", "getNodeValue", "getCheckType", "getChildCount",
              "getTotalLeafPoints", "getCompPointPair", "getIncorrectFeedback"]:
        print(f"    root.{g:22s} -> {node((), g)!r}")

    def walk(path=(), depth=0, maxdepth=6):
        name = node(path, "getNodeName")
        ct = node(path, "getCheckType")
        pts = node(path, "getTotalLeafPoints")
        n = node(path, "getChildCount")
        mark = {0: "X ", 1: "~ ", 2: "OK"}.get(ct if isinstance(ct, int) else None, f"? ({ct})")
        print("    " + "  " * depth + f"[{mark}] {name!r}  pts={pts} children={n}")
        if isinstance(n, (int, float)) and int(n) > 0 and depth < maxdepth:
            for i in range(int(n)):
                walk(path + (i,), depth + 1, maxdepth)

    print(f"\n  -- walk of {TREE}() --")
    try:
        walk()
    except Exception as e:
        print("    walk failed:", e)

    client.close()
    print("\ndone — paste this output back to wire up detailed per-item scoring.")


if __name__ == "__main__":
    main()
