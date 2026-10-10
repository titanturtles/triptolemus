package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
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

// TestPracticeDeferredUpdateInsert: insert a new level ahead of a kept one with
// deferImages — the kept level keeps its image/key, nothing touches sarpedon.conf until
// syncimages, which then adds only the new (practice-tagged) block.
func TestPracticeDeferredUpdateInsert(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "sarpedon.conf")
	os.WriteFile(conf, []byte("[[team]]\nid = \"X\"\nalias = \"x\"\n"), 0644)
	confPath = filepath.Join(dir, "levels.json")
	cfg = Config{AdminToken: "a", SarpConf: conf, FilesDir: filepath.Join(dir, "levels")}
	post := func(h func(w http.ResponseWriter, r *http.Request), path string, fields map[string]string, files map[string]string) map[string]interface{} {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		for k, v := range fields {
			mw.WriteField(k, v)
		}
		for field, fn := range files {
			fw, _ := mw.CreateFormFile(field, fn)
			fw.Write([]byte("pka " + fn))
		}
		mw.Close()
		req := httptest.NewRequest("POST", path, &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("X-Admin-Token", "a")
		w := httptest.NewRecorder()
		h(w, req)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		var o map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &o)
		return o
	}
	post(adminCreate, "/admin/create", map[string]string{"name": "U4.M13. VLANs", "comp": "p13", "practice": "1", "unit": "4",
		"deferImages": "1", "levelname1": "13.3.12 VLAN Configuration"}, map[string]string{"level1": "13-3-12-vlan.pka"})
	post(adminSyncImages, "/admin/syncimages?comp=p13", nil, nil)
	before := snapshot().Competitions[0].Levels[0]
	base, _ := os.ReadFile(conf)

	// insert 13.1.4 as the new L1; keep the old level as L2 (renumbered, same image + key)
	o := post(adminUpdate, "/admin/update", map[string]string{"comp": "p13", "name": "U4.M13. VLANs", "practice": "1", "unit": "4",
		"deferImages": "1", "levelname1": "13.1.4 Who Hears the Broadcast", "keep2": before.Image, "levelname2": before.Name},
		map[string]string{"level1": "13-1-4-who-hears.pka"})
	if o["images_added"].(float64) != 0 || o["levels"].(float64) != 2 {
		t.Fatalf("deferred update: %v", o)
	}
	if got, _ := os.ReadFile(conf); string(got) != string(base) {
		t.Fatalf("deferred update touched sarpedon.conf")
	}
	lv := snapshot().Competitions[0].Levels
	if lv[1].Level != 2 || lv[1].Image != before.Image || lv[1].Password != before.Password || lv[0].Name != "13.1.4 Who Hears the Broadcast" {
		t.Fatalf("levels after insert: %+v", lv)
	}
	if o := post(adminSyncImages, "/admin/syncimages?comp=p13", nil, nil); o["images_added"].(float64) != 1 {
		t.Fatalf("sync after update should add only the new block: %v", o)
	}
	got, _ := os.ReadFile(conf)
	if strings.Count(string(got), "practice = true") != 2 || !strings.Contains(string(got), `"`+lv[0].Image+`"`) {
		t.Fatalf("sarpedon.conf after sync:\n%s", got)
	}
}

// TestUniqueImageNames: long similar file names truncate to the same 60-char image name
// ("… exploration part 1/2/3"); every level must still get its own image (sarpedon keys
// scoring by it), on create and when an update inserts a level.
func TestUniqueImageNames(t *testing.T) {
	taken := map[string]bool{}
	a := uniqueImage("p21-x-L8-21-7-3-multiarea-ospf-exploration-part-1-physical-m", taken)
	b := uniqueImage("p21-x-L8-21-7-3-multiarea-ospf-exploration-part-1-physical-m", taken)
	c := uniqueImage("p21-x-L8-21-7-3-multiarea-ospf-exploration-part-1-physical-m", taken)
	if a == b || b == c || a == c || len(b) > 60 || len(c) > 60 {
		t.Fatalf("uniqueImage: %q %q %q", a, b, c)
	}

	dir := t.TempDir()
	conf := filepath.Join(dir, "sarpedon.conf")
	os.WriteFile(conf, []byte(""), 0644)
	confPath = filepath.Join(dir, "levels.json")
	cfg = Config{AdminToken: "a", SarpConf: conf, FilesDir: filepath.Join(dir, "levels")}
	long := "21-7-3-multiarea-ospf-exploration-part-%d-physical-mode.pka"
	body, ct := createForm(t, map[string]string{"name": "OSPF", "comp": "p21-single-area-ospfv2-confi", "practice": "1", "deferImages": "1"},
		[]string{fmt.Sprintf(long, 3)})
	req := httptest.NewRequest("POST", "/admin/create", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("X-Admin-Token", "a")
	adminCreate(httptest.NewRecorder(), req)
	old := snapshot().Competitions[0].Levels[0]

	// insert Part 1 as L1 ahead of the kept Part 3 (which keeps its "L1" image name)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range map[string]string{"comp": "p21-single-area-ospfv2-confi", "name": "OSPF", "practice": "1",
		"deferImages": "1", "keep2": old.Image} {
		mw.WriteField(k, v)
	}
	fw, _ := mw.CreateFormFile("level1", fmt.Sprintf(long, 1))
	fw.Write([]byte("pka"))
	mw.Close()
	req = httptest.NewRequest("POST", "/admin/update", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-Admin-Token", "a")
	w := httptest.NewRecorder()
	adminUpdate(w, req)
	if w.Code != 200 {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}
	lv := snapshot().Competitions[0].Levels
	if len(lv) != 2 || lv[0].Image == lv[1].Image || lv[1].Image != old.Image || lv[1].Password != old.Password {
		t.Fatalf("levels share an image or the kept one changed: %+v", lv)
	}
}
