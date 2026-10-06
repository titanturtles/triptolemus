# pka_tool — Packet Tracer activity password-hash extractor

The PT scoring agent needs to unlock a **password-protected** activity over IPC
before Packet Tracer will report its score. Packet Tracer's IPC `confirmPassword`
does **not** take the plaintext Activity Wizard password — it takes the activity's
**stored MD5 hash** (the `PASS="…"` value baked into the `.pka`). This tool
extracts that hash so you can put it in the agent config as the activity's
`pt_password`.

(Mechanism: a `.pka` is Twofish-EAX encrypted — key `{137}×16`, iv `{16}×16` —
with a byte-scramble and zlib, the same scheme as the `pka2xml` project. This tool
reimplements the decrypt in Go using `golang.org/x/crypto/twofish`.)

## Usage

**`-conf` (recommended)** — print both config pieces for a new activity: the
sarpedon `[[image]]` block (with a freshly generated per-image key) and the
matching `pt_agent.conf.json` entry (same key + the extracted `pt_password` hash):

```
./pka_tool_linux_amd64 -conf "2025-2026 Cisco Test.pka"
# optional: override the image name ->  -conf "file.pka" "PT-My-Name"
```

**`-pass`** — just the activity password hash (the `pt_password` value):

```
./pka_tool_linux_amd64 -pass "2025-2026 Cisco Test.pka"
# -> 84CD04F5E4B1A695593DAA84309A4F6F
```

**Decrypt to XML** (inspection/debug; this is the full answer key — handle carefully):

```
./pka_tool_linux_amd64 "activity.pka" activity.xml
```

If `-pass` prints nothing (and `-conf` omits `pt_password`), the activity has no
Activity Wizard password (unlocked) — the agent needs no `pt_password` for it.

## Add a new activity — step by step

1. **Get the config blocks** (instructor machine, where `pka_tool` lives):
   ```
   ./pka_tool_linux_amd64 -conf "New Lab.pka"
   ```
2. **Scoreboard:** paste block #1 (the `[[image]]`) into `/opt/sarpedon/sarpedon.conf`
   and restart sarpedon — use the `~/deploy/add_pt_image.sh` pattern (backs up,
   appends, restarts, auto-rolls-back). Needs sudo.
3. **Agent config:** paste block #2 into the `"activities": [ ... ]` array in
   `pt_agent.conf.json`.
4. **Distribute:** ship `New Lab.pka` to students alongside the agent. (They
   register `ptagent.pta` in PT once per machine if they haven't already.)
5. Students open the `.pka` in Packet Tracer, run the agent, enter Team ID, pick
   the `.pka`, Start. Scores appear on the board under the new image column.

**Never ship `pka_tool` to students** — it decrypts activities (answer keys). It's
an instructor-only tool.

## Build (other platforms)

Requires Go. From this directory:

```
go build -o pka_tool .            # current platform
GOOS=windows GOARCH=amd64 go build -o pka_tool.exe .
GOOS=darwin  GOARCH=arm64 go build -o pka_tool_macos .
```

The checked-in `pka_tool_linux_amd64` is a static Linux/amd64 build.
