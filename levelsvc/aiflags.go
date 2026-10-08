package main

// aiflags.go: the AI-use check. While a level runs in a competition with AICheck on, the student
// agent looks for AI assistants (open window titles, browser history since the run started, Windows
// DNS lookups) and reports what it finds to POST /aiflag. Nothing is shown to the student; admins
// read the reports through GET /admin/aiflags (sarpedon's "AI-use flags" page). Reports are kept as
// one JSON file per team per competition, named by the team's alias like the review files.

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	aiMaxBody    = 512 << 10 // bytes per report (clipboard full-text can be large)
	aiMaxEvents  = 100       // events per report
	aiMaxPerTeam = 400       // distinct (signal, service, evidence) rows kept per team
)

var aiSources = map[string]bool{"title": true, "history": true, "dns": true, "clipboard": true, "process": true}

type aiEvent struct {
	Source   string `json:"source"`   // title | history | dns
	Service  string `json:"service"`  // e.g. ChatGPT
	Evidence string `json:"evidence"` // the window title, visited URL, or looked-up domain
	First    int64  `json:"first"`    // unix seconds
	Last     int64  `json:"last"`
	Count    int    `json:"count"`
	Level    int    `json:"level,omitempty"`
	Full     string `json:"full,omitempty"` // full captured text (clipboard), when the snippet is truncated
}

type aiRecord struct {
	Team     string              `json:"team"` // alias
	LastSeen int64               `json:"lastSeen"`
	Since    int64               `json:"since,omitempty"` // when the reporting run started
	Version  string              `json:"version,omitempty"`
	Platform string              `json:"platform,omitempty"`
	Checks   map[string]string   `json:"checks,omitempty"` // per signal: what the agent could check
	IP       string              `json:"ip,omitempty"`
	Events   map[string]*aiEvent `json:"events"`
}

var aiMu sync.Mutex

func aiDir(c Config, comp string) string { return filepath.Join(c.AIFlagDir, safeFilePart(comp)) }

// knownTeam reports whether team is a [[team]] id or alias in sarpedon.conf.
func knownTeam(sarpConf, team string) bool {
	for _, r := range parseTeams(sarpConf) {
		if strings.EqualFold(r.ID, team) || (r.Alias != "" && strings.EqualFold(r.Alias, team)) {
			return true
		}
	}
	return false
}

// clip trims s and cuts it to at most n runes.
func clip(s string, n int) string {
	s = strings.TrimSpace(strings.ToValidUTF8(s, ""))
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// clientIP is the student's address: nginx proxies /levels from loopback and passes X-Real-IP.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if x := strings.TrimSpace(r.Header.Get("X-Real-IP")); x != "" {
			return x
		}
		if x := r.Header.Get("X-Forwarded-For"); x != "" {
			return strings.TrimSpace(strings.Split(x, ",")[0])
		}
	}
	return host
}

func readAIRecord(path string) *aiRecord {
	rec := &aiRecord{}
	if raw, err := os.ReadFile(path); err == nil {
		json.Unmarshal(raw, rec)
	}
	if rec.Events == nil {
		rec.Events = map[string]*aiEvent{}
	}
	return rec
}

func writeAIRecord(path string, rec *aiRecord) error {
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// clampTime keeps an agent-supplied timestamp within a sane window around the server clock.
func clampTime(t, now int64) int64 {
	if t <= 0 || t > now+86400 || t < now-30*86400 {
		return now
	}
	return t
}

// aiflagHandler takes a report from a student agent: {version, platform, since, checks, events}.
// Each event is merged into the team's record by (source, service, evidence): first/last widen,
// counts add up. A report with no events is a heartbeat (shows the check is running).
func aiflagHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	c := snapshot()
	cp := resolveComp(c, r.URL.Query().Get("comp"))
	team := r.URL.Query().Get("team")
	if cp == nil || team == "" {
		http.Error(w, "comp and team required", 400)
		return
	}
	if !knownTeam(c.SarpConf, team) {
		http.Error(w, "unknown team", 404)
		return
	}
	if msg := lockedFor(cp, team, c.SarpConf); msg != "" {
		http.Error(w, msg, http.StatusLocked)
		return
	}
	if !cp.AICheck {
		writeJSON(w, map[string]interface{}{"status": "off"}) // the agent stops checking
		return
	}
	var in struct {
		Version  string            `json:"version"`
		Platform string            `json:"platform"`
		Since    int64             `json:"since"`
		Checks   map[string]string `json:"checks"`
		Events   []aiEvent         `json:"events"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, aiMaxBody)).Decode(&in); err != nil {
		http.Error(w, "bad report", 400)
		return
	}
	if len(in.Events) > aiMaxEvents {
		in.Events = in.Events[:aiMaxEvents]
	}
	now := time.Now().Unix()

	aiMu.Lock()
	defer aiMu.Unlock()
	dir := aiDir(c, cp.ID)
	if err := os.MkdirAll(dir, 0750); err != nil {
		http.Error(w, "server write error", 500)
		return
	}
	path := filepath.Join(dir, storageKey(c.SarpConf, team)+".json")
	rec := readAIRecord(path)
	rec.Team = aliasForID(c.SarpConf, team)
	rec.LastSeen = now
	rec.Version = clip(in.Version, 20)
	rec.Platform = clip(in.Platform, 20)
	rec.IP = clientIP(r)
	if in.Since > 0 {
		rec.Since = clampTime(in.Since, now)
	}
	if len(in.Checks) > 0 {
		rec.Checks = map[string]string{}
		for k, v := range in.Checks {
			if len(rec.Checks) < 8 {
				rec.Checks[clip(k, 16)] = clip(v, 120)
			}
		}
	}
	stored, dropped := 0, 0
	for _, e := range in.Events {
		src, svc, ev := clip(e.Source, 10), clip(e.Service, 40), clip(e.Evidence, 300)
		full := clip(e.Full, 20000)
		if !aiSources[src] || svc == "" {
			continue
		}
		first, last := clampTime(e.First, now), clampTime(e.Last, now)
		if last < first {
			last = first
		}
		cnt := e.Count
		if cnt < 1 {
			cnt = 1
		} else if cnt > 10000 {
			cnt = 10000
		}
		key := src + "|" + svc + "|" + ev
		if x, ok := rec.Events[key]; ok {
			if first < x.First {
				x.First = first
			}
			if last > x.Last {
				x.Last = last
			}
			x.Count += cnt
			if e.Level > 0 {
				x.Level = e.Level
			}
			if full != "" {
				x.Full = full
			}
		} else if len(rec.Events) < aiMaxPerTeam {
			rec.Events[key] = &aiEvent{src, svc, ev, first, last, cnt, e.Level, full}
		} else {
			dropped++
			continue
		}
		stored++
	}
	if err := writeAIRecord(path, rec); err != nil {
		http.Error(w, "server write error", 500)
		return
	}
	if stored > 0 {
		log.Printf("aiflag comp=%s team=%s events=%d dropped=%d", cp.ID, rec.Team, stored, dropped)
	}
	writeJSON(w, map[string]interface{}{"status": "OK", "stored": stored, "dropped": dropped})
}

type aiTeamOut struct {
	Team     string            `json:"team"`
	LastSeen int64             `json:"lastSeen"`
	Since    int64             `json:"since,omitempty"`
	Version  string            `json:"version,omitempty"`
	Platform string            `json:"platform,omitempty"`
	Checks   map[string]string `json:"checks,omitempty"`
	IP       string            `json:"ip,omitempty"`
	Events   []aiEvent         `json:"events"`
}

// loadAIFlags reads every team's record for a competition, events newest first, flagged teams first.
func loadAIFlags(c Config, comp string) []aiTeamOut {
	entries, _ := os.ReadDir(aiDir(c, comp))
	out := []aiTeamOut{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		rec := readAIRecord(filepath.Join(aiDir(c, comp), e.Name()))
		t := aiTeamOut{rec.Team, rec.LastSeen, rec.Since, rec.Version, rec.Platform, rec.Checks, rec.IP, []aiEvent{}}
		for _, ev := range rec.Events {
			t.Events = append(t.Events, *ev)
		}
		sort.Slice(t.Events, func(i, j int) bool { return t.Events[i].Last > t.Events[j].Last })
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if (len(out[i].Events) > 0) != (len(out[j].Events) > 0) {
			return len(out[i].Events) > 0
		}
		return strings.ToLower(out[i].Team) < strings.ToLower(out[j].Team)
	})
	return out
}

// countAIFlagged is the number of teams with at least one AI-use report in a competition.
func countAIFlagged(c Config, comp string) int {
	n := 0
	for _, t := range loadAIFlags(c, comp) {
		if len(t.Events) > 0 {
			n++
		}
	}
	return n
}

// adminAIFlags: GET lists a competition's AI-use reports; POST action=clear&team=<alias> deletes
// one team's reports (after review, or to clear a false alarm).
func adminAIFlags(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if !admin(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	c := snapshot()
	cp := resolveComp(c, r.URL.Query().Get("comp"))
	if cp == nil {
		http.Error(w, "no such competition", 404)
		return
	}
	if r.Method == http.MethodPost {
		team := r.URL.Query().Get("team")
		if r.URL.Query().Get("action") != "clear" || team == "" {
			http.Error(w, "action=clear and team required", 400)
			return
		}
		aiMu.Lock()
		err := os.Remove(filepath.Join(aiDir(c, cp.ID), storageKey(c.SarpConf, team)+".json"))
		aiMu.Unlock()
		if err != nil && !os.IsNotExist(err) {
			http.Error(w, "could not clear: "+err.Error(), 500)
			return
		}
		log.Printf("aiflag comp=%s team=%s cleared", cp.ID, team)
		writeJSON(w, map[string]interface{}{"status": "OK"})
		return
	}
	writeJSON(w, map[string]interface{}{"comp": cp.ID, "name": cp.Name, "aiCheck": cp.AICheck,
		"teams": loadAIFlags(c, cp.ID)})
}
