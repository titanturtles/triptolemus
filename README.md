# Cisco Packet Tracer Competition — Test Creator Guide

This is everything you need to run Packet Tracer competitions on the TitanTurtles
scoreboard. You do all of it from the **Cisco Scoreboard Manager** app over HTTPS —
no SSH, no server login.

- **You** use `scoreboard_manager` (the manager app) — **or** the browser web console
  built into the sarpedon scoreboard (log in → **PT Competitions**). Both do the same
  thing (create / edit / default / hide / remove / review); they drive this repo's
  `levelsvc` and are interchangeable. The web console lives in the TitanTurtles
  **sarpedon** fork (`github.com/titanturtles/sarpedon`).
- **Students** use `pt_agent` (the competition app) on their machines/VMs.
- The scoreboard server runs sarpedon + `levelsvc` (this repo); it's already set up.
- This repo (**triptolemus**) is the PT‑competition half: `levelsvc` (server engine),
  `pt_agent` (student app), `pka_tool`, and the setup docs. The scoreboard UI/auth lives
  in the sarpedon fork.

The two sibling docs:
- `WINDOWS_VM_SETUP.md` — building the student Windows VM image (one time).
- `FIRST_TIME_SETUP.md` — the printable student handout.

---

## 0. What you need from the instructor

Get these once and keep them private (they are **not** in this folder):

| Setting | Example |
|---|---|
| Scoreboard URL | `https://scoreboard.titanturtles.xyz` |
| Levels service URL | `https://scoreboard.titanturtles.xyz/levels` |
| ExApp id | `xyz.titanturtles.ptagent` |
| ExApp secret (KEY) | *(from the instructor)* |
| Admin token | *(from the instructor)* |

Keep the `pka_tool/` folder next to the manager — it reads each activity's password
hash out of the `.pka` for you.

---

## 1. Open the manager and sign in

Run the app:
- Windows: double-click `scoreboard_manager.exe`
- Mac/Linux: `python3 scoreboard_manager.py`

At the top, fill in the five settings from the table above and click **Save + Refresh**.
They're stored locally in `manager_data/settings.json`, so you only do this once.
The list then shows every competition on the server (name, id, # of levels, default,
hidden, submissions).

---

## 2. Create and deploy a competition

Click **New competition**. You can use the **Wizard** (step by step) or **One page**.

1. **Name** — e.g. `Round 1 Routing`. The id is derived automatically (`round-1-routing`).
2. **Levels** — for each level:
   - **Browse .pka…** and pick the Packet Tracer activity file.
   - `image` auto-fills (the scoreboard image name) — leave it.
   - `clear %` is the completion needed to clear the level and unlock the next one
     (default 100). Use a lower number if you want an easier gate.
   - **+ Add level** for more levels. Students only see level 1 until they clear it,
     then level 2 unlocks, and so on.
3. **Build:**
   - **1. Generate** — builds the competition locally. It copies the `.pka`s, makes a
     scoring key per level, reads each activity's password hash (via `pka_tool`), and
     saves a reloadable copy in `manager_data/<id>.json`.
   - **2. Deploy** — uploads it to the server. The competition is live immediately.

That's it — no files to copy to the server by hand.

> **Password-locked activities:** if a `.pka`'s activity wizard is password-protected,
> `pka_tool` still extracts the stored hash automatically, so the agent can read the
> completion. You don't type the activity password anywhere.

---

## 3. Pick the default competition

Select a competition and click **Set as default** (it gets a ★). When a student opens
the agent, the default is pre-selected — they can just click Start. They can still pick
any other (non-hidden) competition from the dropdown.

---

## 4. Give it to students

Students need three things once per machine/VM: the `pt_agent` app, a small
`pt_agent.conf.json`, and `ptagent.pta`.

1. Click **Student bootstrap…** — it writes a tiny `pt_agent.conf.json` (just the server
   URL + a shared class token). The agent uses it to pull the competition list, the
   default, and the scoring keys from the server **on every open** — so when you add,
   hide, or change a competition on the server, students get it automatically (they click
   **Reload** or reopen). You do **not** re-hand-out files when competitions change.
2. Build the student Windows VM once using **`WINDOWS_VM_SETUP.md`**. The one-step installer
   both writes that config and sets up the app, so **students never touch a config file** —
   they just open the icon and every competition loads:
   ```
   install_student.bat -Levelsvc "https://scoreboard.titanturtles.xyz/levels" -ClassToken "<class token>"
   ```
   (class token = the `class_token` value inside the Student bootstrap file).

(If you ever want a self-contained config with the keys baked in instead of the
server-served flow, select a competition and use **Export agent config**.)

---

## 5. During and after the test — review & restore

Select a competition and click **Review submissions**:

- **paused (live)** rows — each team's current work, uploaded the instant a student clicks
  **Save & keep working** or **Stop (save & close)**. One per team & level, always the
  latest. You can watch progress without waiting for anyone to finish.
- **final** rows — the timestamped copies saved when a student clicks **Finish Competition**.
- **Download selected** — save a `.pka` to open in Packet Tracer.
- **Restore (let team resume)** — copy any saved version back into a team's resumable slot.
  The student reopens the agent, picks the same competition + Team ID, clicks **Start**,
  and continues from that exact file — **even after they clicked Finish**.
- **Refresh** — re-pull the lists.

---

## 6. Managing competitions

- **Edit** — change name/levels and re-Deploy. (Only works on the machine that generated
  it, since it uses the local copy in `manager_data/`. If it was made elsewhere, make a
  New one or use Export agent config.)
- **Hide / Show** — hide a competition from students without deleting it.
- **Set as default** — see section 3.
- **Remove** — delete it from the server (level files and scoreboard images are removed;
  student submissions are kept for your records).

---

## 7. What students see (for reference)

See `FIRST_TIME_SETUP.md` for the student handout. In short, the agent window has:

- **Competition** dropdown (default pre-selected) and **Team ID**.
- **Start** — opens Packet Tracer and loads the current level automatically.
- **Save & keep working** — checkpoint: saves + uploads, keeps working.
- **Stop (save & close)** — saves + uploads, closes PT; **Resume** later to continue.
- **Start from beginning** — reload a clean copy of the current level.
- **Finish Competition** — saves, uploads for review, closes PT, wipes local files.
- **Reset (new student)** — clears the Team ID + local files for the next student.
  It does **not** touch Packet Tracer's registration, so first-time setup is never repeated.

Scoring: the agent reports the activity's completion % (truncated, to match Packet
Tracer's on-screen number). When a team's score reaches a level's **clear %**, the next
level unlocks.

---

## 8. Files in this folder

| Item | What it is |
|---|---|
| `scoreboard_manager(.exe)` | the manager app (you) |
| `pt_agent(.exe)` | the student competition app |
| `pka_tool/` | helper binaries the manager uses to read `.pka` hashes — keep it here |
| `manager_data/` | your saved settings + a reloadable copy of each competition you built |
| `ptagent.pta` | the Packet Tracer app registration file students import once |
| `install_student.ps1` / `.bat` | one-step student VM installer (build + shortcuts) |
| `WINDOWS_VM_SETUP.md` | one-time student VM image build |
| `FIRST_TIME_SETUP.md` | printable student handout |

---

## 9. Quick troubleshooting

- **Manager can't reach the server** — check the Levels service URL and Admin token, then
  Save + Refresh.
- **Deploy fails** — make sure you clicked **Generate** first; re-open the editor and retry.
- **A student's app shows no competitions** — their machine can't reach the server, or the
  class token changed; click **Reload** in the agent, or re-run **Student bootstrap…** and
  redistribute the small config.
- **"pt_password was rejected"** — the competition's config on the student side is stale;
  with the server-served flow this shouldn't happen (keys come from the server). Re-Deploy
  the competition and have the student Reload.
- **Buttons missing / app looks old** — rebuild `pt_agent.exe` from the latest `pt_agent.py`
  (`install_student.bat -ForceBuild`).
