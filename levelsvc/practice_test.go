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
)

// createForm builds an /admin/create multipart body: fields + one file per level.
func createForm(t *testing.T, fields map[string]string, files []string) (*bytes.Buffer, string) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		mw.WriteField(k, v)
	}
	for i, fn := range files {
		fw, err := mw.CreateFormFile("level"+itoa(i+1), fn)
		if err != nil {
			t.Fatal(err)
		}
		fw.Write([]byte("not-a-real-pka " + fn))
	}
	mw.Close()
	return &buf, mw.FormDataContentType()
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestPracticeDeferredImagesAndSync(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "sarpedon.conf")
	base := "[[team]]\nid = \"SecretID01\"\nalias = \"turtles\"\n"
	os.WriteFile(conf, []byte(base), 0644)
	confPath = filepath.Join(dir, "levels.json")
	cfg = Config{AdminToken: "a", SarpConf: conf, FilesDir: filepath.Join(dir, "levels")}

	// 1) deferred practice create: registered with unit + level names, sarpedon.conf untouched
	body, ct := createForm(t, map[string]string{"name": "13 · VLANs", "comp": "p13-vlans", "practice": "1",
		"unit": "4", "deferImages": "1", "vis": "1", "public": "1",
		"threshold1": "100", "levelname1": "13.3.12 VLAN Configuration",
		"threshold2": "100", "levelname2": "13.4.5 Configure Trunks"},
		[]string{"13.3.12-vlan-configuration.pka", "13.4.5-configure-trunks.pka"})
	req := httptest.NewRequest("POST", "/admin/create", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("X-Admin-Token", "a")
	w := httptest.NewRecorder()
	adminCreate(w, req)
	if w.Code != 200 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var cr map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &cr)
	if cr["images_added"].(float64) != 0 {
		t.Fatalf("deferred create must not touch sarpedon.conf: %v", cr)
	}
	if got, _ := os.ReadFile(conf); string(got) != base {
		t.Fatalf("sarpedon.conf changed on a deferred create:\n%s", got)
	}

	// 2) listing exposes unit + per-level labels (and never the keys)
	req = httptest.NewRequest("GET", "/admin/competitions", nil)
	req.Header.Set("X-Admin-Token", "a")
	w = httptest.NewRecorder()
	adminCompetitions(w, req)
	if strings.Contains(w.Body.String(), "ptk_") {
		t.Fatalf("listing leaked a scoring key: %s", w.Body.String())
	}
	var lst struct {
		Competitions []struct {
			ID        string `json:"id"`
			Practice  bool   `json:"practice"`
			Unit      int    `json:"unit"`
			LevelInfo []struct {
				Level     int    `json:"level"`
				Name      string `json:"name"`
				Image     string `json:"image"`
				Threshold int    `json:"threshold"`
			} `json:"levelInfo"`
		} `json:"competitions"`
	}
	json.Unmarshal(w.Body.Bytes(), &lst)
	if len(lst.Competitions) != 1 || !lst.Competitions[0].Practice || lst.Competitions[0].Unit != 4 {
		t.Fatalf("listing: %+v", lst)
	}
	li := lst.Competitions[0].LevelInfo
	if len(li) != 2 || li[1].Name != "13.4.5 Configure Trunks" || li[0].Threshold != 100 || li[0].Image == "" {
		t.Fatalf("levelInfo: %+v", li)
	}

	// 3) syncimages writes both blocks once, tagged practice; repeating is a no-op
	sync := func() map[string]interface{} {
		req := httptest.NewRequest("POST", "/admin/syncimages?comp=p13-vlans", nil)
		req.Header.Set("X-Admin-Token", "a")
		w := httptest.NewRecorder()
		adminSyncImages(w, req)
		if w.Code != 200 {
			t.Fatalf("sync: %d %s", w.Code, w.Body.String())
		}
		var o map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &o)
		return o
	}
	if o := sync(); o["images_added"].(float64) != 2 {
		t.Fatalf("first sync: %v", o)
	}
	got, _ := os.ReadFile(conf)
	if strings.Count(string(got), "practice = true") != 2 || !strings.Contains(string(got), `"`+li[0].Image+`"`) {
		t.Fatalf("sarpedon.conf after sync:\n%s", got)
	}
	if o := sync(); o["images_added"].(float64) != 0 {
		t.Fatalf("second sync should add nothing: %v", o)
	}

	// 4) a normal (non-practice) competition gets an untagged block immediately
	body, ct = createForm(t, map[string]string{"name": "Real comp", "comp": "real"}, []string{"real.pka"})
	req = httptest.NewRequest("POST", "/admin/create", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("X-Admin-Token", "a")
	w = httptest.NewRecorder()
	adminCreate(w, req)
	json.Unmarshal(w.Body.Bytes(), &cr)
	if w.Code != 200 || cr["images_added"].(float64) != 1 {
		t.Fatalf("real create: %d %s", w.Code, w.Body.String())
	}
	got, _ = os.ReadFile(conf)
	if strings.Count(string(got), "practice = true") != 2 {
		t.Fatalf("non-practice block must not be tagged:\n%s", got)
	}

	// 5) admin token required
	req = httptest.NewRequest("POST", "/admin/syncimages", nil)
	w = httptest.NewRecorder()
	adminSyncImages(w, req)
	if w.Code != 401 {
		t.Fatalf("syncimages without token: %d", w.Code)
	}
}
