# First-time setup (students) — do this once per computer

You have a folder with three things:
- the **agent** (`pt_agent.exe` on Windows / `pt_agent` on Mac/Linux)
- **`pt_agent.conf.json`**
- **`ptagent.pta`**

And you need **Cisco Packet Tracer** installed and signed in (NetAcad / Skills for All).

## 1. Register the agent in Packet Tracer (one time)
Packet Tracer only talks to the agent after you add it once:

1. **Run the agent** and click **Start** — it will open Packet Tracer for you
   (log in to NetAcad if prompted). *Or* open Packet Tracer yourself.
2. In Packet Tracer's top menu: **Extensions → IPC → Configure Apps**.
3. Click **Add**, then select the **`ptagent.pta`** file from your folder, and click **Ok**.
   - "TitanTurtles PT Agent" now shows in the list.
4. **Quit Packet Tracer normally** (**File → Exit**) so it saves the registration.
   *(This step matters — if Packet Tracer crashes or is force‑closed, the
   registration is lost and you'd repeat these steps.)*

> In the agent, the **"First-time setup (register the agent)…"** button shows these
> same steps and can open the folder that contains `ptagent.pta`.

## 2. Compete
1. Run the agent, pick your **Competition** (the default is already selected),
   enter your **Team ID**, and click **Start**.
   - It opens Packet Tracer (if needed) and loads **Level 1** automatically.
2. Work on the activity. Reaching the target score **unlocks the next level**.
3. Buttons while you work:
   - **Save & keep working** — saves + uploads your progress but keeps Packet Tracer
     open so you can keep going (a checkpoint).
   - **Stop (save & close)** — saves + uploads your progress and closes Packet Tracer;
     come back later and click **Resume** to pick up where you left off.
   - **Start from beginning** — throws away this level's progress and loads a clean copy.
4. When you're done, click **Finish Competition** — it saves your work, uploads it
   for review, closes Packet Tracer, and removes the local activity files.

## Trouble?
- **"Packet Tracer isn't running…"** — install/open Packet Tracer, then Start again.
- **"…rejected the agent / register…"** — you haven't done Step 1 on this computer
  yet (or Packet Tracer wasn't quit normally after adding it). Use the
  **First-time setup** button and redo Step 1.
