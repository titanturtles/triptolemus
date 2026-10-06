// levelsvc: the Cisco Scoreboard Manager backend — multi-competition progressive
// levels gating + deploy + review service, on the scoreboard box next to sarpedon.
//
// Each competition has an id, a name, a hidden flag, and its own ordered levels
// (each a sarpedon image + clear-% + .pka). A level is released to a team only
// once it cleared the previous level, read from sarpedon's Mongo `scores`.
//
//	GET  /status?comp=C&team=T          per-level score/cleared/unlocked (+ hidden)
//	GET  /level?comp=C&team=T&n=N        the level-N .pka iff unlocked (else 403)
//	POST /upload?comp=C&team=T&n=N       store a finished .pka for review
//	--- admin (header X-Admin-Token) ---
//	GET  /admin/competitions             list competitions (+ level/submission counts)
//	POST /admin/deploy?comp=C&name=NAME  body=zip of a Generate folder; create/update C
//	POST /admin/competition?comp=C&action=hide|show|remove
//	GET  /admin/submissions?comp=C       list submissions for C
//	GET  /admin/submission?comp=C&name=  download one submission
//
// comp defaults to the first competition when omitted (back-compat).
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Level struct {
	Level      int    `json:"level"`
	Name       string `json:"name,omitempty"` // human label shown to students
	Image      string `json:"image"`
	Threshold  int    `json:"threshold"`
	File       string `json:"file"`
	Password   string `json:"password,omitempty"`   // sarpedon per-image key (never sent to students)
	PtPassword string `json:"ptPassword,omitempty"` // activity hash (never sent to students)
}

// agentConf mirrors the student pt_agent.conf.json inside a deploy bundle, so the
// server can remember each level's key + hash (and the shared agent settings) and
// re-export the config later or serve it to students via /enroll.
type agentConf struct {
	Remote   string `json:"remote"`
	PtAppID  string `json:"pt_app_id"`
	PtSecret string `json:"pt_secret"`
	Levels   []struct {
		Level      int    `json:"level"`
		Password   string `json:"password"`
		PtPassword string `json:"pt_password"`
	} `json:"levels"`
}

type Competition struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Hidden   bool    `json:"hidden"`
	Default  bool    `json:"default,omitempty"`
	Practice bool    `json:"practice,omitempty"` // label only; no behavior change
	Levels   []Level `json:"levels"`
}

type Config struct {
	DB           string        `json:"db"`
	DBName       string        `json:"dbName"`
	Listen       string        `json:"listen"`
	FilesDir     string        `json:"filesDir"`
	UploadDir    string        `json:"uploadDir"`
	MaxUpload    int64         `json:"maxUploadMB"`
	AdminToken   string        `json:"adminToken"`
	ClassToken   string        `json:"classToken"` // student-facing token for GET /enroll
	SarpConf     string        `json:"sarpConf"`
	ProgressDir  string        `json:"progressDir"`
	PkaTool      string        `json:"pkaTool"`  // path to the pka_tool binary (for server-side hash extraction)
	Remote       string        `json:"remote"`   // sarpedon base URL students POST scores to
	PtAppID      string        `json:"ptAppId"`  // shared ExApp id (same for all competitions)
	PtSecret     string        `json:"ptSecret"` // shared ExApp secret
	Competitions []Competition `json:"competitions"`
	Levels       []Level       `json:"levels,omitempty"` // legacy single-competition; migrated on load
}

var (
	cfg      Config
	cfgMu    sync.RWMutex
	confPath string
	scores   *mongo.Collection
)

func snapshot() Config {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return cfg
}

func persistLocked() {
	if raw, err := json.MarshalIndent(cfg, "", "  "); err == nil {
		os.WriteFile(confPath, raw, 0644)
	}
}

func resolveComp(c Config, id string) *Competition {
	if id == "" && len(c.Competitions) > 0 {
		id = c.Competitions[0].ID
	}
	for i := range c.Competitions {
		if c.Competitions[i].ID == id {
			return &c.Competitions[i]
		}
	}
	return nil
}

// maxPoints returns a team's best item-completion percentage (0-100) on an image,
// computed from the recorded vuln counts (sarpedon stores vulnsscored/vulnstotal).
// Gating keys off item completion %, which matches Packet Tracer's on-screen % and is
// independent of the points the board shows. Name kept for the single caller below.
func maxPoints(team, image string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var res struct {
		Vulns struct {
			Scored int `bson:"vulnsscored"`
			Total  int `bson:"vulnstotal"`
		} `bson:"vulns"`
	}
	err := scores.FindOne(ctx,
		bson.M{"team.id": team, "image.name": image},
		options.FindOne().SetSort(bson.D{{Key: "vulns.vulnsscored", Value: -1}}),
	).Decode(&res)
	if err != nil || res.Vulns.Total <= 0 {
		return 0
	}
	return res.Vulns.Scored * 100 / res.Vulns.Total
}

type levelStatus struct {
	Level     int    `json:"level"`
	Image     string `json:"image"`
	Threshold int    `json:"threshold"`
	Score     int    `json:"score"`
	Cleared   bool   `json:"cleared"`
	Unlocked  bool   `json:"unlocked"`
}

func computeStatus(team string, levels []Level) (int, []levelStatus) {
	out := make([]levelStatus, 0, len(levels))
	maxUnlocked := 0
	prevCleared := true
	for _, l := range levels {
		score := maxPoints(team, l.Image)
		cleared := score >= l.Threshold
		unlocked := prevCleared
		if unlocked && l.Level > maxUnlocked {
			maxUnlocked = l.Level
		}
		out = append(out, levelStatus{l.Level, l.Image, l.Threshold, score, cleared, unlocked})
		prevCleared = prevCleared && cleared
	}
	return maxUnlocked, out
}

func cors(w http.ResponseWriter) { w.Header().Set("Access-Control-Allow-Origin", "*") }
func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	team := r.URL.Query().Get("team")
	if team == "" {
		http.Error(w, "team required", 400)
		return
	}
	c := snapshot()
	cp := resolveComp(c, r.URL.Query().Get("comp"))
	if cp == nil {
		http.Error(w, "no such competition", 404)
		return
	}
	if cp.Hidden {
		writeJSON(w, map[string]interface{}{"comp": cp.ID, "name": cp.Name, "team": team,
			"hidden": true, "unlocked": 0, "levels": []levelStatus{}})
		return
	}
	unlocked, levels := computeStatus(team, cp.Levels)
	writeJSON(w, map[string]interface{}{"comp": cp.ID, "name": cp.Name, "team": team,
		"unlocked": unlocked, "levels": levels})
}

func levelHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	team := r.URL.Query().Get("team")
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if team == "" || n == 0 {
		http.Error(w, "team and n required", 400)
		return
	}
	c := snapshot()
	cp := resolveComp(c, r.URL.Query().Get("comp"))
	if cp == nil || cp.Hidden {
		http.Error(w, "competition not available", 403)
		return
	}
	var lvl *Level
	for i := range cp.Levels {
		if cp.Levels[i].Level == n {
			lvl = &cp.Levels[i]
		}
	}
	if lvl == nil {
		http.Error(w, "no such level", 404)
		return
	}
	_, levels := computeStatus(team, cp.Levels)
	for _, ls := range levels {
		if ls.Level == n && !ls.Unlocked {
			http.Error(w, "level locked: clear the previous level first", 403)
			return
		}
	}
	f, err := os.Open(filepath.Join(c.FilesDir, cp.ID, lvl.File))
	if err != nil {
		http.Error(w, "level file missing on server", 500)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="level%d.pka"`, n))
	io.Copy(w, f)
	log.Printf("served comp=%s level=%d team=%s", cp.ID, n, team)
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	c := snapshot()
	cp := resolveComp(c, r.URL.Query().Get("comp"))
	team := r.URL.Query().Get("team")
	n := r.URL.Query().Get("n")
	if cp == nil || team == "" || n == "" {
		http.Error(w, "comp, team and n required", 400)
		return
	}
	limit := c.MaxUpload
	if limit <= 0 {
		limit = 128
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit*1024*1024))
	if err != nil {
		http.Error(w, "upload too large or read error", 400)
		return
	}
	dir := filepath.Join(c.UploadDir, cp.ID)
	os.MkdirAll(dir, 0750)
	name := fmt.Sprintf("%s_L%s_%s.pka", filepath.Base(team), filepath.Base(n), time.Now().UTC().Format("20060102-150405"))
	if err := os.WriteFile(filepath.Join(dir, name), data, 0640); err != nil {
		http.Error(w, "server write error", 500)
		return
	}
	log.Printf("submission comp=%s team=%s level=%s bytes=%d", cp.ID, team, n, len(data))
	writeJSON(w, map[string]interface{}{"status": "OK", "stored": name, "bytes": len(data)})
}

// progressHandler stores (POST) or returns (GET) a team's in-progress .pka for a
// level, so a student can Stop (save) and later Resume (download) their own work.
func progressHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	c := snapshot()
	cp := resolveComp(c, r.URL.Query().Get("comp"))
	team := r.URL.Query().Get("team")
	n := r.URL.Query().Get("n")
	if cp == nil || team == "" || n == "" {
		http.Error(w, "comp, team and n required", 400)
		return
	}
	dir := filepath.Join(c.ProgressDir, cp.ID)
	path := filepath.Join(dir, fmt.Sprintf("%s_L%s.pka", filepath.Base(team), filepath.Base(n)))
	if r.Method == http.MethodPost {
		limit := c.MaxUpload
		if limit <= 0 {
			limit = 128
		}
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit*1024*1024))
		if err != nil {
			http.Error(w, "upload too large or read error", 400)
			return
		}
		os.MkdirAll(dir, 0750)
		if err := os.WriteFile(path, data, 0640); err != nil {
			http.Error(w, "server write error", 500)
			return
		}
		log.Printf("progress saved comp=%s team=%s L%s bytes=%d", cp.ID, team, n, len(data))
		writeJSON(w, map[string]interface{}{"status": "OK", "bytes": len(data)})
		return
	}
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "no saved progress", 404)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="level%s.pka"`, n))
	io.Copy(w, f)
}

// ---- admin ----
func admin(r *http.Request) bool {
	c := snapshot()
	tok := r.Header.Get("X-Admin-Token")
	if c.AdminToken == "" || tok == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(c.AdminToken)) == 1
}

func countSubmissions(uploadDir, comp string) int {
	entries, _ := os.ReadDir(filepath.Join(uploadDir, comp))
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			n++
		}
	}
	return n
}

func adminCompetitions(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if !admin(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	c := snapshot()
	list := []map[string]interface{}{}
	for _, cp := range c.Competitions {
		list = append(list, map[string]interface{}{
			"id": cp.ID, "name": cp.Name, "hidden": cp.Hidden, "default": cp.Default,
			"practice": cp.Practice,
			"levels":   len(cp.Levels), "submissions": countSubmissions(c.UploadDir, cp.ID),
		})
	}
	writeJSON(w, map[string]interface{}{"competitions": list})
}

var imgLine = regexp.MustCompile(`^\s*(\[\[image\]\]|name\s*=|color\s*=|password\s*=|#|$)`)
var nameRe = regexp.MustCompile(`name\s*=\s*"([^"]+)"`)

func appendSarpImages(blocks, sarpConf string) (int, error) {
	for _, ln := range strings.Split(blocks, "\n") {
		if !imgLine.MatchString(ln) {
			return 0, fmt.Errorf("refusing sarpedon blocks: unexpected line %q", strings.TrimSpace(ln))
		}
	}
	cur, _ := os.ReadFile(sarpConf)
	text := string(cur)
	var add []string
	for _, p := range strings.Split(blocks, "[[image]]")[1:] {
		blk := "[[image]]\n" + strings.Trim(p, "\n ")
		m := nameRe.FindStringSubmatch(blk)
		if m == nil {
			continue
		}
		if strings.Contains(text, `"`+m[1]+`"`) {
			continue
		}
		add = append(add, blk)
	}
	if len(add) == 0 {
		return 0, nil
	}
	os.WriteFile(fmt.Sprintf("%s.bak-%d", sarpConf, time.Now().Unix()), cur, 0644)
	f, err := os.OpenFile(sarpConf, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if _, err := f.WriteString("\n\n" + strings.Join(add, "\n\n") + "\n"); err != nil {
		return 0, err
	}
	return len(add), nil
}

// removeSarpImages deletes the [[image]] blocks whose name is in `names` from
// sarpedon.conf, leaving all other sections untouched. A block runs from its
// "[[image]]" line to the next section header ("[" ...) or EOF.
func removeSarpImages(names map[string]bool, sarpConf string) (int, error) {
	cur, err := os.ReadFile(sarpConf)
	if err != nil {
		return 0, err
	}
	lines := strings.Split(string(cur), "\n")
	out := make([]string, 0, len(lines))
	removed, i := 0, 0
	for i < len(lines) {
		if strings.TrimSpace(lines[i]) == "[[image]]" {
			j := i + 1
			name := ""
			for j < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[j]), "[") {
				if name == "" {
					if m := nameRe.FindStringSubmatch(lines[j]); m != nil {
						name = m[1]
					}
				}
				j++
			}
			if names[name] {
				removed++
				i = j
				continue
			}
			out = append(out, lines[i:j]...)
			i = j
			continue
		}
		out = append(out, lines[i])
		i++
	}
	if removed == 0 {
		return 0, nil
	}
	os.WriteFile(fmt.Sprintf("%s.bak-%d", sarpConf, time.Now().Unix()), cur, 0644)
	return removed, os.WriteFile(sarpConf, []byte(strings.Join(out, "\n")), 0644)
}

func adminDeploy(w http.ResponseWriter, r *http.Request) {
	cors(w)
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("deploy panic: %v", rec)
			http.Error(w, fmt.Sprintf("deploy error: %v", rec), 500)
		}
	}()
	if !admin(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	comp := r.URL.Query().Get("comp")
	name := r.URL.Query().Get("name")
	if comp == "" {
		http.Error(w, "comp required", 400)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 512*1024*1024))
	if err != nil {
		http.Error(w, "bundle too large or read error", 400)
		return
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		http.Error(w, "not a valid zip bundle", 400)
		return
	}
	c := snapshot()
	var newLevels []Level
	var sarpBlocks string
	var agentBytes []byte
	pkas := map[string][]byte{}
	for _, f := range zr.File {
		base := filepath.Base(f.Name)
		rc, err := f.Open()
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		switch {
		case base == "levels.json":
			var parsed Config
			if err := json.Unmarshal(b, &parsed); err != nil {
				http.Error(w, "levels.json in bundle is invalid", 400)
				return
			}
			newLevels = parsed.Levels
			if newLevels == nil && len(parsed.Competitions) > 0 {
				newLevels = parsed.Competitions[0].Levels
			}
		case base == "sarpedon_images.conf":
			sarpBlocks = string(b)
		case base == "pt_agent.conf.json":
			agentBytes = b
		case strings.HasSuffix(strings.ToLower(base), ".pka"):
			pkas[base] = b
		}
	}
	if newLevels == nil {
		http.Error(w, "bundle missing levels.json", 400)
		return
	}
	// remember each level's key + hash (from the bundle's agent config) so the
	// manager can re-export pt_agent.conf.json and /enroll can serve students.
	var gRemote, gAppID, gSecret string
	if agentBytes != nil {
		var ac agentConf
		if json.Unmarshal(agentBytes, &ac) == nil {
			gRemote, gAppID, gSecret = ac.Remote, ac.PtAppID, ac.PtSecret
			keyByLevel := map[int][2]string{}
			for _, al := range ac.Levels {
				keyByLevel[al.Level] = [2]string{al.Password, al.PtPassword}
			}
			for i := range newLevels {
				if kv, ok := keyByLevel[newLevels[i].Level]; ok {
					newLevels[i].Password = kv[0]
					newLevels[i].PtPassword = kv[1]
				}
			}
		}
	}
	dir := filepath.Join(c.FilesDir, comp)
	os.MkdirAll(dir, 0755)
	for base, b := range pkas {
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(base)), b, 0644); err != nil {
			http.Error(w, "could not write level file: "+err.Error(), 500)
			return
		}
	}
	// create or update the competition (preserve Hidden)
	cfgMu.Lock()
	if gRemote != "" {
		cfg.Remote = gRemote
	}
	if gAppID != "" {
		cfg.PtAppID = gAppID
	}
	if gSecret != "" {
		cfg.PtSecret = gSecret
	}
	found := false
	for i := range cfg.Competitions {
		if cfg.Competitions[i].ID == comp {
			cfg.Competitions[i].Levels = newLevels
			if name != "" {
				cfg.Competitions[i].Name = name
			}
			found = true
		}
	}
	if !found {
		if name == "" {
			name = comp
		}
		cfg.Competitions = append(cfg.Competitions, Competition{ID: comp, Name: name, Levels: newLevels})
	}
	persistLocked()
	cfgMu.Unlock()

	imgs := 0
	if sarpBlocks != "" && c.SarpConf != "" {
		if n, err := appendSarpImages(sarpBlocks, c.SarpConf); err != nil {
			http.Error(w, "sarpedon image update failed: "+err.Error(), 400)
			return
		} else {
			imgs = n
		}
	}
	log.Printf("deploy comp=%s: %d levels, %d files, %d new images", comp, len(newLevels), len(pkas), imgs)
	writeJSON(w, map[string]interface{}{"status": "OK", "comp": comp, "levels": len(newLevels),
		"level_files": len(pkas), "images_added": imgs})
}

func adminCompetition(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if !admin(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	comp := r.URL.Query().Get("comp")
	action := r.URL.Query().Get("action")
	if comp == "" || action == "" {
		http.Error(w, "comp and action required", 400)
		return
	}
	cfgMu.Lock()
	idx := -1
	for i := range cfg.Competitions {
		if cfg.Competitions[i].ID == comp {
			idx = i
		}
	}
	if idx < 0 {
		cfgMu.Unlock()
		http.Error(w, "no such competition", 404)
		return
	}
	sarpConf := cfg.SarpConf
	var removeImages map[string]bool
	switch action {
	case "hide":
		cfg.Competitions[idx].Hidden = true
	case "show":
		cfg.Competitions[idx].Hidden = false
	case "default":
		for i := range cfg.Competitions {
			cfg.Competitions[i].Default = (i == idx) // exactly one default at a time
		}
	case "undefault":
		cfg.Competitions[idx].Default = false
	case "remove":
		removeImages = map[string]bool{}
		for _, l := range cfg.Competitions[idx].Levels {
			removeImages[l.Image] = true
		}
		os.RemoveAll(filepath.Join(cfg.FilesDir, comp)) // delete level files; submissions kept for records
		cfg.Competitions = append(cfg.Competitions[:idx], cfg.Competitions[idx+1:]...)
	default:
		cfgMu.Unlock()
		http.Error(w, "action must be hide|show|default|undefault|remove", 400)
		return
	}
	persistLocked()
	cfgMu.Unlock()
	imgsRemoved := 0
	if action == "remove" && sarpConf != "" && len(removeImages) > 0 {
		if n, err := removeSarpImages(removeImages, sarpConf); err == nil {
			imgsRemoved = n // modifying sarpedon.conf triggers the auto-restart watcher
		} else {
			log.Printf("removeSarpImages: %v", err)
		}
	}
	log.Printf("competition %s: %s (images removed: %d)", comp, action, imgsRemoved)
	writeJSON(w, map[string]interface{}{"status": "OK", "comp": comp, "action": action, "images_removed": imgsRemoved})
}

func adminSubmissions(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if !admin(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	c := snapshot()
	comp := r.URL.Query().Get("comp")
	if comp == "" && len(c.Competitions) > 0 {
		comp = c.Competitions[0].ID
	}
	entries, _ := os.ReadDir(filepath.Join(c.UploadDir, comp))
	list := []map[string]interface{}{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if info, err := e.Info(); err == nil {
			list = append(list, map[string]interface{}{
				"name": e.Name(), "bytes": info.Size(), "modified": info.ModTime().UTC().Format(time.RFC3339)})
		}
	}
	writeJSON(w, map[string]interface{}{"comp": comp, "submissions": list})
}

func adminSubmission(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if !admin(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	c := snapshot()
	comp := r.URL.Query().Get("comp")
	if comp == "" && len(c.Competitions) > 0 {
		comp = c.Competitions[0].ID
	}
	name := filepath.Base(r.URL.Query().Get("name"))
	if name == "" || name == "." || name == "/" {
		http.Error(w, "name required", 400)
		return
	}
	f, err := os.Open(filepath.Join(c.UploadDir, comp, name))
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, name))
	io.Copy(w, f)
}

// parseProgressName turns a progress filename "TEAM_L3.pka" into ("TEAM", "3").
func parseProgressName(name string) (string, string) {
	base := strings.TrimSuffix(name, ".pka")
	if i := strings.LastIndex(base, "_L"); i >= 0 {
		return base[:i], base[i+2:]
	}
	return base, ""
}

// adminProgress lists the in-progress/paused .pka files (one per team+level, the
// latest saved by Stop/Finish), so instructors can review work without waiting for Finish.
func adminProgress(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if !admin(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	c := snapshot()
	comp := r.URL.Query().Get("comp")
	if comp == "" && len(c.Competitions) > 0 {
		comp = c.Competitions[0].ID
	}
	entries, _ := os.ReadDir(filepath.Join(c.ProgressDir, comp))
	list := []map[string]interface{}{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		team, level := parseProgressName(e.Name())
		list = append(list, map[string]interface{}{
			"name": e.Name(), "team": team, "level": level,
			"bytes": info.Size(), "modified": info.ModTime().UTC().Format(time.RFC3339)})
	}
	writeJSON(w, map[string]interface{}{"comp": comp, "progress": list})
}

// adminProgressFile downloads one in-progress .pka.
func adminProgressFile(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if !admin(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	c := snapshot()
	comp := r.URL.Query().Get("comp")
	if comp == "" && len(c.Competitions) > 0 {
		comp = c.Competitions[0].ID
	}
	name := filepath.Base(r.URL.Query().Get("name"))
	if name == "" || name == "." || name == "/" {
		http.Error(w, "name required", 400)
		return
	}
	f, err := os.Open(filepath.Join(c.ProgressDir, comp, name))
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, name))
	io.Copy(w, f)
}

// adminRestore copies a saved .pka (a final submission or an existing progress file)
// into a team's resumable progress slot, so a student can reopen the agent and
// continue from it — even after they clicked Finish Competition.
func adminRestore(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if !admin(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	c := snapshot()
	comp := r.URL.Query().Get("comp")
	if comp == "" && len(c.Competitions) > 0 {
		comp = c.Competitions[0].ID
	}
	name := filepath.Base(r.URL.Query().Get("name"))
	kind := r.URL.Query().Get("kind") // "submission" | "progress"
	team := r.URL.Query().Get("team")
	n := r.URL.Query().Get("n")
	if comp == "" || name == "" || name == "." || team == "" || n == "" {
		http.Error(w, "comp, name, team and n required", 400)
		return
	}
	srcDir := c.UploadDir
	if kind == "progress" {
		srcDir = c.ProgressDir
	}
	data, err := os.ReadFile(filepath.Join(srcDir, comp, name))
	if err != nil {
		http.Error(w, "source not found", 404)
		return
	}
	dstDir := filepath.Join(c.ProgressDir, comp)
	os.MkdirAll(dstDir, 0750)
	dst := filepath.Join(dstDir, fmt.Sprintf("%s_L%s.pka", filepath.Base(team), filepath.Base(n)))
	if err := os.WriteFile(dst, data, 0640); err != nil {
		http.Error(w, "server write error", 500)
		return
	}
	log.Printf("restore comp=%s team=%s L%s from %s/%s (%d bytes)", comp, team, n, kind, name, len(data))
	writeJSON(w, map[string]interface{}{"status": "OK", "comp": comp, "team": team, "level": n, "bytes": len(data)})
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func slug(s string) string {
	s = slugRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(s)), "-")
	s = strings.Trim(s, "-")
	if s == "" {
		s = "comp"
	}
	return s
}

var hex32 = regexp.MustCompile(`^[0-9A-Fa-f]{32}$`)
var keepChars = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

// slugImage builds a human-readable image/file name from the uploaded .pka filename,
// e.g. comp "test2", level 1, file "test2-L1-276.pka" -> "test2-L1-276".
func slugImage(comp string, level int, filename string) string {
	base := strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))
	base = keepChars.ReplaceAllString(strings.ReplaceAll(base, " ", "-"), "")
	img := fmt.Sprintf("%s-L%d-%s", comp, level, base)
	if len(img) > 60 {
		img = img[:60]
	}
	return strings.Trim(img, "-")
}

func imageBlock(image, key string) string {
	return fmt.Sprintf("[[image]]\nname = %q\ncolor = \"#1BA0E2\"\npassword = %q\n\n", image, key)
}

// pkaHash shells out to pka_tool -pass to read an activity's stored password hash;
// returns "" for unlocked activities (or if pka_tool is unavailable).
func pkaHash(tool, pkaPath string) string {
	if tool == "" {
		return ""
	}
	out, err := exec.Command(tool, "-pass", pkaPath).Output()
	if err != nil {
		return ""
	}
	h := strings.TrimSpace(string(out))
	if hex32.MatchString(h) {
		return h
	}
	return ""
}

// adminCreate builds and deploys a competition from uploaded .pka files (the web
// path): for each level it extracts the activity hash, generates a scoring key and
// sarpedon image block, stores the file, and registers the competition.
func adminCreate(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if !admin(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	if err := r.ParseMultipartForm(512 << 20); err != nil {
		http.Error(w, "bad multipart form: "+err.Error(), 400)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Error(w, "name required", 400)
		return
	}
	comp := r.FormValue("comp")
	if comp == "" {
		comp = slug(name)
	}
	practice := r.FormValue("practice") != ""
	c := snapshot()
	dir := filepath.Join(c.FilesDir, comp)
	os.MkdirAll(dir, 0755)

	var newLevels []Level
	var sarpBlocks strings.Builder
	for i := 1; ; i++ {
		fhs := r.MultipartForm.File[fmt.Sprintf("level%d", i)]
		if len(fhs) == 0 {
			break
		}
		f, err := fhs[0].Open()
		if err != nil {
			http.Error(w, "cannot read uploaded level", 400)
			return
		}
		data, _ := io.ReadAll(f)
		f.Close()
		image := slugImage(comp, i, fhs[0].Filename)
		fn := image + ".pka"
		pkaPath := filepath.Join(dir, fn)
		if err := os.WriteFile(pkaPath, data, 0644); err != nil {
			http.Error(w, "cannot store level file: "+err.Error(), 500)
			return
		}
		hash := pkaHash(c.PkaTool, pkaPath)
		key := "ptk_" + randHex(16)
		thr, _ := strconv.Atoi(strings.TrimSpace(r.FormValue(fmt.Sprintf("threshold%d", i))))
		if thr <= 0 {
			thr = 100
		}
		lvName := strings.TrimSpace(r.FormValue(fmt.Sprintf("levelname%d", i)))
		if lvName == "" {
			lvName = fmt.Sprintf("Level %d", i)
		}
		newLevels = append(newLevels, Level{Level: i, Name: lvName, Image: image, Threshold: thr,
			File: fn, Password: key, PtPassword: hash})
		sarpBlocks.WriteString(imageBlock(image, key))
	}
	if len(newLevels) == 0 {
		http.Error(w, "upload at least one .pka (field level1, level2, ...)", 400)
		return
	}

	cfgMu.Lock()
	found := false
	for i := range cfg.Competitions {
		if cfg.Competitions[i].ID == comp {
			cfg.Competitions[i].Name = name
			cfg.Competitions[i].Practice = practice
			cfg.Competitions[i].Levels = newLevels
			found = true
		}
	}
	if !found {
		cfg.Competitions = append(cfg.Competitions, Competition{ID: comp, Name: name, Practice: practice, Levels: newLevels})
	}
	persistLocked()
	cfgMu.Unlock()

	imgs := 0
	if c.SarpConf != "" {
		if n, err := appendSarpImages(sarpBlocks.String(), c.SarpConf); err == nil {
			imgs = n
		} else {
			log.Printf("adminCreate appendSarpImages: %v", err)
		}
	}
	log.Printf("create comp=%s: %d levels, %d images", comp, len(newLevels), imgs)
	writeJSON(w, map[string]interface{}{"status": "OK", "comp": comp, "levels": len(newLevels), "images_added": imgs})
}

// adminUpdate edits an existing competition: rename, change per-level thresholds, and
// add / remove / replace / reorder levels. Each submitted row either uploads a new .pka
// (regenerated) or keeps an existing level by image name (file/key/hash reused).
func adminUpdate(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if !admin(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	if err := r.ParseMultipartForm(512 << 20); err != nil {
		http.Error(w, "bad multipart form: "+err.Error(), 400)
		return
	}
	comp := r.FormValue("comp")
	name := strings.TrimSpace(r.FormValue("name"))
	practice := r.FormValue("practice") != ""
	if comp == "" {
		http.Error(w, "comp required", 400)
		return
	}
	c := snapshot()
	byImage := map[string]Level{}
	found := false
	for _, cp := range c.Competitions {
		if cp.ID == comp {
			found = true
			for _, l := range cp.Levels {
				byImage[l.Image] = l
			}
		}
	}
	if !found {
		http.Error(w, "no such competition", 404)
		return
	}
	if name == "" {
		name = comp
	}
	dir := filepath.Join(c.FilesDir, comp)
	os.MkdirAll(dir, 0755)
	var newLevels []Level
	var sarpBlocks strings.Builder
	k := 0
	for i := 1; i <= 50; i++ {
		keep := strings.TrimSpace(r.FormValue(fmt.Sprintf("keep%d", i)))
		fhs := r.MultipartForm.File[fmt.Sprintf("level%d", i)]
		hasFile := len(fhs) > 0 && fhs[0].Filename != ""
		if !hasFile && keep == "" {
			continue
		}
		k++
		thr, _ := strconv.Atoi(strings.TrimSpace(r.FormValue(fmt.Sprintf("threshold%d", i))))
		if thr <= 0 {
			thr = 100
		}
		lvName := strings.TrimSpace(r.FormValue(fmt.Sprintf("levelname%d", i)))
		if hasFile {
			f, err := fhs[0].Open()
			if err != nil {
				http.Error(w, "cannot read uploaded level", 400)
				return
			}
			data, _ := io.ReadAll(f)
			f.Close()
			image := slugImage(comp, k, fhs[0].Filename)
			fn := image + ".pka"
			if err := os.WriteFile(filepath.Join(dir, fn), data, 0644); err != nil {
				http.Error(w, "cannot store level file: "+err.Error(), 500)
				return
			}
			hash := pkaHash(c.PkaTool, filepath.Join(dir, fn))
			key := "ptk_" + randHex(16)
			if lvName == "" {
				lvName = fmt.Sprintf("Level %d", k)
			}
			newLevels = append(newLevels, Level{Level: k, Name: lvName, Image: image, Threshold: thr, File: fn, Password: key, PtPassword: hash})
			sarpBlocks.WriteString(imageBlock(image, key))
		} else if ex, ok := byImage[keep]; ok {
			ex.Level = k
			ex.Threshold = thr
			if lvName != "" {
				ex.Name = lvName
			} else if ex.Name == "" {
				ex.Name = fmt.Sprintf("Level %d", k)
			}
			newLevels = append(newLevels, ex)
		}
	}
	if len(newLevels) == 0 {
		http.Error(w, "a competition needs at least one level", 400)
		return
	}
	cfgMu.Lock()
	for i := range cfg.Competitions {
		if cfg.Competitions[i].ID == comp {
			cfg.Competitions[i].Name = name
			cfg.Competitions[i].Practice = practice
			cfg.Competitions[i].Levels = newLevels
		}
	}
	persistLocked()
	cfgMu.Unlock()
	imgs := 0
	if c.SarpConf != "" && sarpBlocks.Len() > 0 {
		if n, err := appendSarpImages(sarpBlocks.String(), c.SarpConf); err == nil {
			imgs = n
		}
	}
	log.Printf("update comp=%s: %d levels, %d new images", comp, len(newLevels), imgs)
	writeJSON(w, map[string]interface{}{"status": "OK", "comp": comp, "levels": len(newLevels), "images_added": imgs})
}

// adminAgentConfig returns a competition's per-level key + hash so the manager can
// rebuild pt_agent.conf.json from the server (without local manifests).
func adminAgentConfig(w http.ResponseWriter, r *http.Request) {
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
	levels := []map[string]interface{}{}
	for _, l := range cp.Levels {
		levels = append(levels, map[string]interface{}{
			"level": l.Level, "levelName": l.Name, "image": l.Image, "threshold": l.Threshold,
			"password": l.Password, "ptPassword": l.PtPassword,
		})
	}
	writeJSON(w, map[string]interface{}{"comp": cp.ID, "name": cp.Name, "levels": levels})
}

// enrollHandler serves students the full competition set (keys included), gated by
// the shared class token. The student app calls it on open, so it always reflects
// the current server state: every non-hidden competition and which one is default.
func enrollHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	c := snapshot()
	tok := r.Header.Get("X-Class-Token")
	if tok == "" {
		tok = r.URL.Query().Get("token")
	}
	if c.ClassToken == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(c.ClassToken)) != 1 {
		http.Error(w, "unauthorized", 401)
		return
	}
	comps := []map[string]interface{}{}
	def := ""
	for _, cp := range c.Competitions {
		if cp.Hidden {
			continue
		}
		if cp.Default && def == "" {
			def = cp.ID
		}
		levels := []map[string]interface{}{}
		for _, l := range cp.Levels {
			levels = append(levels, map[string]interface{}{
				"level": l.Level, "name": l.Name, "image": l.Image, "threshold": l.Threshold,
				"password": l.Password, "pt_password": l.PtPassword,
			})
		}
		comps = append(comps, map[string]interface{}{"comp": cp.ID, "name": cp.Name, "levels": levels})
	}
	if def == "" && len(comps) > 0 {
		def = comps[0]["comp"].(string) // fall back to the first visible competition
	}
	writeJSON(w, map[string]interface{}{
		"remote": c.Remote, "pt_app_id": c.PtAppID, "pt_secret": c.PtSecret,
		"default": def, "competitions": comps,
	})
}

// adminClassToken returns the shared student class token (generating one if needed).
func adminClassToken(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if !admin(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	cfgMu.Lock()
	if cfg.ClassToken == "" {
		cfg.ClassToken = randHex(24)
		persistLocked()
	}
	tok := cfg.ClassToken
	cfgMu.Unlock()
	writeJSON(w, map[string]interface{}{"classToken": tok})
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func main() {
	cp := flag.String("c", "levels.json", "config file")
	flag.Parse()
	confPath = *cp
	raw, err := os.ReadFile(confPath)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		log.Fatalf("parse config: %v", err)
	}
	if cfg.DB == "" {
		cfg.DB = "mongodb://localhost:27017"
	}
	if cfg.DBName == "" {
		cfg.DBName = "sarpedon"
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8099"
	}
	if cfg.SarpConf == "" {
		cfg.SarpConf = "/opt/sarpedon/sarpedon.conf"
	}
	if cfg.ProgressDir == "" {
		cfg.ProgressDir = "/opt/levelsvc/progress"
	}
	if cfg.PkaTool == "" {
		cfg.PkaTool = "/opt/levelsvc/pka_tool"
	}
	if cfg.ClassToken == "" {
		cfg.ClassToken = randHex(24)
		persistLocked()
	}
	// migrate a legacy single-competition config
	if len(cfg.Competitions) == 0 && len(cfg.Levels) > 0 {
		cfg.Competitions = []Competition{{ID: "default", Name: "default", Levels: cfg.Levels}}
		cfg.Levels = nil
		// move existing files/<file> into files/default/
		for _, l := range cfg.Competitions[0].Levels {
			old := filepath.Join(cfg.FilesDir, l.File)
			if _, err := os.Stat(old); err == nil {
				os.MkdirAll(filepath.Join(cfg.FilesDir, "default"), 0755)
				os.Rename(old, filepath.Join(cfg.FilesDir, "default", l.File))
			}
		}
		persistLocked()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.DB))
	if err != nil {
		log.Fatalf("mongo connect: %v", err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		log.Fatalf("mongo ping: %v", err)
	}
	scores = client.Database(cfg.DBName).Collection("scores")

	http.HandleFunc("/status", statusHandler)
	http.HandleFunc("/level", levelHandler)
	http.HandleFunc("/upload", uploadHandler)
	http.HandleFunc("/progress", progressHandler)
	http.HandleFunc("/enroll", enrollHandler)
	http.HandleFunc("/admin/competitions", adminCompetitions)
	http.HandleFunc("/admin/classtoken", adminClassToken)
	http.HandleFunc("/admin/deploy", adminDeploy)
	http.HandleFunc("/admin/create", adminCreate)
	http.HandleFunc("/admin/update", adminUpdate)
	http.HandleFunc("/admin/competition", adminCompetition)
	http.HandleFunc("/admin/submissions", adminSubmissions)
	http.HandleFunc("/admin/submission", adminSubmission)
	http.HandleFunc("/admin/progress", adminProgress)
	http.HandleFunc("/admin/progressfile", adminProgressFile)
	http.HandleFunc("/admin/restore", adminRestore)
	http.HandleFunc("/admin/agentconfig", adminAgentConfig)
	log.Printf("levelsvc on %s (db=%s/%s, %d competitions, admin=%v)",
		cfg.Listen, cfg.DB, cfg.DBName, len(cfg.Competitions), cfg.AdminToken != "")
	log.Fatal(http.ListenAndServe(cfg.Listen, nil))
}
