package main

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func latest(t *testing.T, q string) map[string]interface{} {
	req := httptest.NewRequest("GET", "/agent/latest"+q, nil)
	req.Header.Set("X-Class-Token", "t")
	w := httptest.NewRecorder()
	agentLatest(w, req)
	var out map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

func publish(t *testing.T, plat, ver string) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("platform", plat)
	mw.WriteField("version", ver)
	fw, _ := mw.CreateFormFile("binary", "x")
	fw.Write([]byte("binary-" + plat + "-" + ver))
	mw.Close()
	req := httptest.NewRequest("POST", "/admin/agentpublish", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-Admin-Token", "a")
	w := httptest.NewRecorder()
	adminAgentPublish(w, req)
	if w.Code != 200 {
		t.Fatalf("publish %s %s: %d %s", plat, ver, w.Code, w.Body.String())
	}
}

func TestPerPlatformVersions(t *testing.T) {
	dir := t.TempDir()
	cfg = Config{AgentDir: dir, ClassToken: "t", AdminToken: "a"}
	// today's production manifest: one shared version
	os.WriteFile(filepath.Join(dir, "agent.json"),
		[]byte(`{"version":"1.1.1","files":{"linux":"pt_agent_linux","windows":"pt_agent_windows.exe"}}`), 0644)
	got := latest(t, "")
	t.Logf("legacy manifest            -> %v", got)
	if got["version"] != "1.1.1" || len(got["platforms"].([]interface{})) != 1 {
		t.Fatal("legacy manifest: old clients should be offered linux 1.1.1 only (never windows)")
	}
	if w := latest(t, "?platform=windows"); w["version"] != "1.1.1" {
		t.Fatal("legacy manifest not read as windows at 1.1.1")
	}
	publish(t, "linux", "1.1.2") // the scenario that bit us
	got = latest(t, "")
	t.Logf("after linux 1.1.2          -> %v", got)
	if got["version"] != "1.1.2" || len(got["platforms"].([]interface{})) != 1 || got["platforms"].([]interface{})[0] != "linux" {
		t.Fatal("windows must not be offered 1.1.2")
	}
	w := latest(t, "?platform=windows")
	t.Logf("?platform=windows          -> %v", w)
	if w["version"] != "1.1.1" {
		t.Fatal("windows should still report 1.1.1")
	}
	publish(t, "windows", "1.1.3") // windows ahead of linux
	got = latest(t, "")
	t.Logf("after windows 1.1.3        -> %v", got)
	if got["version"] != "1.1.2" || len(got["platforms"].([]interface{})) != 1 || got["platforms"].([]interface{})[0] != "linux" {
		t.Fatal("old clients must never be offered windows, even when it is the newest build")
	}
	if w := latest(t, "?platform=windows"); w["version"] != "1.1.3" || len(w["platforms"].([]interface{})) != 1 {
		t.Fatal("1.1.3+ windows clients (which name their platform) should see windows 1.1.3")
	}
	if cmpVersion("1.1.10", "1.1.9") <= 0 || cmpVersion("", "1.0") >= 0 || cmpVersion("1.2", "1.2.0") != 0 {
		t.Fatal("cmpVersion ordering wrong")
	}
}
