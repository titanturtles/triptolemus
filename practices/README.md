# Windows / Linux practices

Each file here is one practice level that PT Comp runs inside a student's practice VM (the
**Windows 11 / Server** and **Linux / FreeBSD** tabs). PT Comp downloads the level from levelsvc,
runs `setup` as administrator/root to plant the problems, then scores `checks` every 20 seconds
and posts the score to the scoreboard like a Cisco level. Students start from their VM's
**Clean** snapshot and restore it to redo a practice or load another one.

The VM can't see its own snapshots, so before the first setup on a VM PT Comp asks whether there is
a Clean snapshot (*Yes, start* / *Not yet, I'll take it now* / *Cancel*). It saves the answer on the
VM before the student takes the snapshot, so the snapshot keeps it and a restored VM doesn't ask
again. When the VM isn't clean, Start says so: with the same practice already set up it offers
*Continue where I left off* or *Start over* (= go back to Clean); with a different practice set
up, or after a setup that failed or was interrupted (the marker is written as `setup` before the
script runs and becomes `ready` only once it works), it shows how to go back to the Clean snapshot.
The tab also shows the VM's state under the practice picker.

| File | Problems |
|---|---|
| `linux-basics-1.json` | unauthorized user, unauthorized admin (sudo), ufw off, passwords never expire, `/etc/shadow` world-readable; penalty for deleting alice or bob |
| `windows-basics-1.json` | unauthorized user, unauthorized admin, Guest enabled, firewall off, minimum password length 0; penalty for deleting alice or bob |

## Format

```json
{
  "format": 1,
  "os": "linux",                 // "windows", "linux" or "freebsd"
  "title": "Linux Basics 1",
  "readme": "Shown to the student: scenario, authorized users, policy.",
  "setup": "bash (PowerShell on Windows), run once as root/administrator",
  "checks": [
    {"message": "Removed the unauthorized user hacker", "points": 20,
     "pass": [{"type": "UserExistsNot", "user": "hacker"}]},
    {"message": "Deleted the authorized user alice", "points": -10,
     "pass": [{"type": "UserExistsNot", "user": "alice"}]}
  ],
  "complete_message": "optional: shown when the level is cleared (e.g. a password)"
}
```

A check scores when every `pass` condition holds and no `fail` condition does. Put `Not` after a
type to negate it (`UserExistsNot`). A condition that errors (missing file, unknown group) counts
as false, in the `Not` form too, so a broken check never gives free points.

A check with **negative points is a penalty** (as in aeacus): it costs its points while its
conditions hold, and goes away when the student undoes the damage. Penalties lower the score but
don't count as problems (a level clears on the share of problems fixed). PT Comp shows them in red,
and plays a rising chime when the score goes up and a low one when it drops (a lost fix or a
penalty); students can turn the sound off with the **Sound** box. Penalties need PT Comp 1.2.1+
(1.2.0 sends a penalty in a form the scoreboard rejects).

| Type | Fields | Notes |
|---|---|---|
| `Command` | `cmd` | exit code 0 (bash; PowerShell on Windows) |
| `CommandContains` | `cmd`, `value` | output contains `value`; `CommandContainsRegex` for a regex |
| `CommandOutput` | `cmd`, `value` | trimmed output equals `value` |
| `FileContains` | `path`, `value` | `FileContainsRegex` for a regex (multi-line) |
| `PathExists` | `path` | |
| `UserExists` | `user` | local user |
| `UserInGroup` | `user`, `group` | Windows built-in groups (Administrators, Users, …) also work on translated Windows |
| `FirewallUp` | | ufw/firewalld; Windows: every profile on |
| `ServiceUp` | `name` | systemd (or `service`); Windows service running |
| `PermissionIs` | `path`, `value` | Linux mode pattern, `?` = any: `"???????---"` = no access for others |
| `SecurityPolicy` | `key`, `min`/`max`/`value` | Windows local security policy (secedit names, e.g. `MinimumPasswordLength`) |

## Writing a practice

- **Setup must force every problem into place**, not assume the base VM's defaults (create the
  user if missing, *add* bob to sudo, *turn* the firewall off). Then a VM a student already
  hardened still starts with every problem, and PT Comp refuses to start if anything already
  scores right after setup.
- **No internet in setup if you can avoid it** (no `apt install`): students' VMs may be offline.
- Each problem's check should accept every reasonable fix (e.g. `/etc/shadow` 640 *or* 600).
- Add a fix script in `tests/` (`<name>.fix.sh` / `<name>.fix.ps1`), and a penalty script
  (`<name>.penalty.sh` / `.ps1`) that sets off every penalty. The **Test practices** GitHub Action
  runs setup → nothing counts, fixes → every problem scores and no penalty, penalties → every
  penalty fires, setup again → nothing counts, on real Ubuntu 22.04 and Windows Server runners.
  Test scripts are never uploaded.

## Publishing

A practice is a levelsvc competition with `kind` = `windows` or `linux` (each level is one of
these files, stored as `.json`, with its own scoreboard image and key). Create it with
`POST /levels/admin/create` (fields `name`, `kind`, `practice=1`, `levelname1`, file `level1`).
Only PT Comp 1.2.0 and later is offered Windows/Linux practices.
