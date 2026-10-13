package main

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// scenarioForm builds an /admin/create or /admin/update body with level files given as contents.
func scenarioForm(t *testing.T, fields map[string]string, files map[string]string) (*bytes.Buffer, string) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		mw.WriteField(k, v)
	}
	for field, body := range files {
		fw, err := mw.CreateFormFile(field, field+".json")
		if err != nil {
			t.Fatal(err)
		}
		fw.Write([]byte(body))
	}
	mw.Close()
	return &buf, mw.FormDataContentType()
}

func TestScenarioCompetitions(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "sarpedon.conf")
	os.WriteFile(conf, []byte("[[team]]\nid = \"SecretID01\"\nalias = \"turtles\"\n"), 0644)
	confPath = filepath.Join(dir, "levels.json")
	cfg = Config{AdminToken: "a", ClassToken: "class", SarpConf: conf, FilesDir: filepath.Join(dir, "levels"),
		Competitions: []Competition{{ID: "cisco1", Name: "Cisco 1", Levels: []Level{{Level: 1, Image: "c1", File: "c1.pka"}}}}}
	post := func(path string, fields map[string]string, files map[string]string) *httptest.ResponseRecorder {
		body, ct := scenarioForm(t, fields, files)
		req := httptest.NewRequest("POST", path, body)
		req.Header.Set("Content-Type", ct)
		req.Header.Set("X-Admin-Token", "a")
		w := httptest.NewRecorder()
		if path == "/admin/create" {
			adminCreate(w, req)
		} else {
			adminUpdate(w, req)
		}
		return w
	}
	linux := `{"os": "linux", "checks": [{"message": "x", "points": 20}], "complete_message": "Round 2 password: otter"}`

	// a scenario for the wrong OS, or one without checks, is refused
	if w := post("/admin/create", map[string]string{"name": "Win 1", "kind": "windows"}, map[string]string{"level1": linux}); w.Code != 400 {
		t.Fatalf("linux scenario accepted as a windows level: %d %s", w.Code, w.Body.String())
	}
	if w := post("/admin/create", map[string]string{"name": "Lin 0", "kind": "linux"}, map[string]string{"level1": `{"os": "linux"}`}); w.Code != 400 {
		t.Fatalf("scenario without checks accepted: %d", w.Code)
	}
	if w := post("/admin/create", map[string]string{"name": "Bad", "kind": "macos"}, map[string]string{"level1": linux}); w.Code != 400 {
		t.Fatalf("unknown kind accepted: %d", w.Code)
	}

	// a Linux practice: stored as .json with no pka hash, kind kept
	if w := post("/admin/create", map[string]string{"name": "Linux Basics 1", "comp": "linux-basics-1", "kind": "linux",
		"practice": "1"}, map[string]string{"level1": linux}); w.Code != 200 {
		t.Fatalf("create linux practice: %d %s", w.Code, w.Body.String())
	}
	cp := resolveComp(snapshot(), "linux-basics-1")
	if cp == nil || cp.Kind != "linux" || len(cp.Levels) != 1 {
		t.Fatalf("linux practice not registered right: %+v", cp)
	}
	lv := cp.Levels[0]
	if !strings.HasSuffix(lv.File, ".json") || lv.PtPassword != "" || lv.Password == "" {
		t.Fatalf("scenario level stored wrong: %+v", lv)
	}
	if got := completeMessage("", filepath.Join(cfg.FilesDir, cp.ID, lv.File)); got != "Round 2 password: otter" {
		t.Fatalf("scenario completion message = %q", got)
	}

	// an update replaces a level with another scenario and keeps the kind
	linux2 := strings.Replace(linux, "otter", "heron", 1)
	if w := post("/admin/update", map[string]string{"comp": "linux-basics-1", "name": "Linux Basics 1", "practice": "1"},
		map[string]string{"level1": linux2}); w.Code != 200 {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}
	if w := post("/admin/update", map[string]string{"comp": "linux-basics-1", "name": "Linux Basics 1"},
		map[string]string{"level1": `{"os": "windows", "checks": [{}]}`}); w.Code != 400 {
		t.Fatalf("update accepted a windows scenario for a linux practice: %d", w.Code)
	}
	cp = resolveComp(snapshot(), "linux-basics-1")
	if cp.Kind != "linux" || !strings.HasSuffix(cp.Levels[0].File, ".json") {
		t.Fatalf("update lost the kind: %+v", cp)
	}

	// enroll: agents that don't name kinds (before 1.2.0) only get Cisco competitions
	enroll := func(q string) map[string]string {
		req := httptest.NewRequest("GET", "/enroll"+q, nil)
		req.Header.Set("X-Class-Token", "class")
		w := httptest.NewRecorder()
		enrollHandler(w, req)
		var out struct {
			Competitions []struct{ Comp, Kind string } `json:"competitions"`
		}
		json.Unmarshal(w.Body.Bytes(), &out)
		got := map[string]string{}
		for _, c := range out.Competitions {
			got[c.Comp] = c.Kind
		}
		return got
	}
	if got := enroll(""); len(got) != 1 || got["cisco1"] != "cisco" {
		t.Fatalf("old agent enroll = %v, want only cisco1", got)
	}
	if got := enroll("?kinds=cisco,windows,linux"); got["linux-basics-1"] != "linux" || got["cisco1"] != "cisco" {
		t.Fatalf("new agent enroll = %v", got)
	}

	// the level download keeps the scenario's extension (a practice level is always unlocked;
	// the unreachable database just reads as no score)
	scores = unreachableScores(t)
	req := httptest.NewRequest("GET", "/level?comp=linux-basics-1&team=SecretID01&n=1", nil)
	w := httptest.NewRecorder()
	levelHandler(w, req)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), `level1.json`) ||
		!strings.Contains(w.Body.String(), "heron") {
		t.Fatalf("level download: %d %q", w.Code, w.Header().Get("Content-Disposition"))
	}
}

// unreachableScores is a scores collection whose queries fail fast (no database in tests).
func unreachableScores(t *testing.T) *mongo.Collection {
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI("mongodb://127.0.0.1:1").
		SetServerSelectionTimeout(200*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	return client.Database("test").Collection("scores")
}
