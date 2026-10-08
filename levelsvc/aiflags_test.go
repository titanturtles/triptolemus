package main

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func aiPost(t *testing.T, comp, team, body string) (int, map[string]interface{}) {
	req := httptest.NewRequest("POST", "/aiflag?comp="+comp+"&team="+team, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:5555"
	req.Header.Set("X-Real-IP", "203.0.113.7")
	w := httptest.NewRecorder()
	aiflagHandler(w, req)
	var out map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func aiList(t *testing.T, comp string) (bool, []aiTeamOut) {
	req := httptest.NewRequest("GET", "/admin/aiflags?comp="+comp, nil)
	req.Header.Set("X-Admin-Token", "a")
	w := httptest.NewRecorder()
	adminAIFlags(w, req)
	if w.Code != 200 {
		t.Fatalf("admin list: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		AICheck bool        `json:"aiCheck"`
		Teams   []aiTeamOut `json:"teams"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	return out.AICheck, out.Teams
}

func TestAIFlags(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "sarpedon.conf")
	os.WriteFile(conf, []byte("[[team]]\nid = \"SecretID01\"\nalias = \"turtles\"\n\n[[team]]\nid = \"SecretID02\"\nalias = \"owls\"\n"), 0644)
	confPath = filepath.Join(dir, "levels.json")
	cfg = Config{AdminToken: "a", SarpConf: conf, AIFlagDir: filepath.Join(dir, "aiflags"),
		Competitions: []Competition{{ID: "comp1", Name: "Comp 1", AICheck: true}, {ID: "comp2", Name: "Comp 2"}}}
	now := time.Now().Unix()

	ev := func(src, svc, evidence string, first, last int64, n int) string {
		b, _ := json.Marshal(aiEvent{src, svc, evidence, first, last, n, 2, ""})
		return string(b)
	}
	// ev2 adds a full-text field
	ev2 := func(src, svc, evidence string, first, last int64, n int, full string) string {
		b, _ := json.Marshal(aiEvent{src, svc, evidence, first, last, n, 0, full}); return string(b)
	}
	body := `{"version":"1.1.5","platform":"windows","since":` + jsonInt(now-600) +
		`,"checks":{"titles":"ok","history":"Chrome, Edge","dns":"ok"},"events":[` +
		ev("title", "ChatGPT", "ChatGPT - Google Chrome", now-300, now-200, 20) + "," +
		ev("history", "Claude", "Chrome: https://claude.ai/new", now-100, now-100, 1) + "," +
		ev("bogus", "X", "y", now, now, 1) + "," + ev2("clipboard", "copied text", "Configure OSPF …", now-50, now-50, 1, "Configure OSPF area 0 on all interfaces and verify connectivity. clipfull-marker") + "]}"
	if code, out := aiPost(t, "comp1", "SecretID01", body); code != 200 || out["stored"].(float64) != 3 {
		t.Fatalf("first report: %d %v", code, out)
	}
	// the same title again later merges into one row (counts add, last widens)
	body2 := `{"version":"1.1.5","platform":"windows","events":[` + ev("title", "ChatGPT", "ChatGPT - Google Chrome", now-60, now-30, 6) + "]}"
	aiPost(t, "comp1", "secretid01", body2) // team id is case-insensitive
	// heartbeat only (no events) from the other team; an alias works as the team too
	aiPost(t, "comp1", "owls", `{"version":"1.1.5","platform":"linux","checks":{"titles":"unavailable"}}`)

	on, teams := aiList(t, "comp1")
	if !on || len(teams) != 2 {
		t.Fatalf("list: aiCheck=%v teams=%+v", on, teams)
	}
	tt := teams[0]
	t.Logf("flagged team: %s ip=%s checks=%v", tt.Team, tt.IP, tt.Checks)
	for _, e := range tt.Events {
		t.Logf("  %-7s %-8s %-40q count=%d span=%ds", e.Source, e.Service, e.Evidence, e.Count, e.Last-e.First)
	}
	if tt.Team != "turtles" || tt.IP != "203.0.113.7" || len(tt.Events) != 3 {
		t.Fatalf("flagged team wrong: %+v", tt)
	}
	var title aiEvent
	for _, e := range tt.Events {
		if e.Source == "title" {
			title = e
		}
	}
	if title.Count != 26 || title.First != now-300 || title.Last != now-30 {
		t.Fatalf("title merge wrong: %+v", title)
	}
	var clip aiEvent
	for _, e := range tt.Events {
		if e.Source == "clipboard" {
			clip = e
		}
	}
	if !strings.Contains(clip.Full, "clipfull-marker") {
		t.Fatalf("clipboard full text not stored: %+v", clip)
	}
	if teams[1].Team != "owls" || len(teams[1].Events) != 0 || teams[1].Checks["titles"] != "unavailable" {
		t.Fatalf("heartbeat team wrong: %+v", teams[1])
	}
	// files are named by alias, never the team id
	if _, err := os.Stat(filepath.Join(dir, "aiflags", "comp1", "turtles.json")); err != nil {
		t.Fatal("record not stored by alias")
	}
	if n := countAIFlagged(cfg, "comp1"); n != 1 {
		t.Fatalf("countAIFlagged = %d", n)
	}
	// unknown team, AI check off, and missing params are refused
	if code, _ := aiPost(t, "comp1", "nobody", body); code != 404 {
		t.Fatalf("unknown team: %d", code)
	}
	if code, out := aiPost(t, "comp2", "SecretID01", body); code != 200 || out["status"] != "off" {
		t.Fatalf("check off: %d %v", code, out)
	}
	if _, teams := aiList(t, "comp2"); len(teams) != 0 {
		t.Fatal("a competition with the check off must store nothing")
	}
	// clear one team's reports
	req := httptest.NewRequest("POST", "/admin/aiflags?comp=comp1&team=turtles&action=clear", nil)
	req.Header.Set("X-Admin-Token", "a")
	w := httptest.NewRecorder()
	adminAIFlags(w, req)
	if _, teams := aiList(t, "comp1"); w.Code != 200 || len(teams) != 1 || teams[0].Team != "owls" {
		t.Fatalf("clear: %d %+v", w.Code, teams)
	}
	// admin endpoints need the token
	req = httptest.NewRequest("GET", "/admin/aiflags?comp=comp1", nil)
	w = httptest.NewRecorder()
	adminAIFlags(w, req)
	if w.Code != 401 {
		t.Fatalf("no token: %d", w.Code)
	}
}

func TestAICheckSetting(t *testing.T) {
	dir := t.TempDir()
	confPath = filepath.Join(dir, "levels.json")
	cfg = Config{AdminToken: "a", FilesDir: dir, Competitions: []Competition{
		{ID: "c", Name: "C", Levels: []Level{{Level: 1, Image: "img-1", Threshold: 50, File: "l1.pka"}}}}}
	os.MkdirAll(filepath.Join(dir, "c"), 0755)
	os.WriteFile(filepath.Join(dir, "c", "l1.pka"), []byte("x"), 0644)
	update := func(fields map[string]string) {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		for k, v := range fields {
			mw.WriteField(k, v)
		}
		mw.Close()
		req := httptest.NewRequest("POST", "/admin/update", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("X-Admin-Token", "a")
		w := httptest.NewRecorder()
		adminUpdate(w, req)
		if w.Code != 200 {
			t.Fatalf("update: %d %s", w.Code, w.Body.String())
		}
	}
	base := map[string]string{"comp": "c", "name": "C", "threshold1": "50", "keep1": "img-1"}
	with := func(extra map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	update(with(map[string]string{"aiopt": "1", "aiCheck": "on"}))
	if !snapshot().Competitions[0].AICheck {
		t.Fatal("aiCheck not turned on")
	}
	update(base) // an older client that doesn't send aiopt leaves the setting alone
	if !snapshot().Competitions[0].AICheck {
		t.Fatal("aiCheck changed by a client that doesn't manage it")
	}
	update(with(map[string]string{"aiopt": "1"}))
	if snapshot().Competitions[0].AICheck {
		t.Fatal("aiCheck not turned off")
	}
}

func jsonInt(n int64) string { b, _ := json.Marshal(n); return string(b) }
