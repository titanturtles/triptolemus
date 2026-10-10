package main

// Level completion messages: the text an activity shows once it is complete (Packet Tracer's
// "Overall Complete Feedback"), e.g. a password for the next round. PT only shows it under
// Check Results, and the agent moves straight on to the next level, so /status passes it
// along for every level the team has cleared.

import (
	"html"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ptDefaultComplete is Packet Tracer's stock completion text; not worth passing on.
const ptDefaultComplete = "Congratulations on completing this activity!"

var (
	completeFeedbackRe = regexp.MustCompile(`(?s)<OVERALL_COMPLETE_FEEDBACK[^>]*>(.*?)</OVERALL_COMPLETE_FEEDBACK>`)
	htmlHiddenRe       = regexp.MustCompile(`(?is)<head[^>]*>.*?</head>|<style[^>]*>.*?</style>`)
	htmlBreakRe        = regexp.MustCompile(`(?i)<br\s*/?>|</(div|p|li|h[1-6])>`)
	htmlTagRe          = regexp.MustCompile(`<[^>]*>`)
	spaceRunRe         = regexp.MustCompile(`[ \t\x{00a0}]+`)
)

// feedbackText turns the feedback element's content (XML-escaped Qt rich text) into plain
// text: one line per paragraph/line break, blank lines dropped.
func feedbackText(raw string) string {
	s := html.UnescapeString(raw) // XML escaping -> HTML
	s = htmlHiddenRe.ReplaceAllString(s, "")
	s = htmlBreakRe.ReplaceAllString(s, "\n")
	s = htmlTagRe.ReplaceAllString(s, "")
	s = html.UnescapeString(s) // HTML entities -> text
	var lines []string
	for _, ln := range strings.Split(s, "\n") {
		if ln = strings.TrimSpace(spaceRunRe.ReplaceAllString(ln, " ")); ln != "" {
			lines = append(lines, ln)
		}
	}
	return strings.Join(lines, "\n")
}

// readCompleteMessage decrypts a .pka with pka_tool and returns its completion message
// ("" for none or PT's default). ok is false when the file couldn't be read.
func readCompleteMessage(tool, pkaPath string) (text string, ok bool) {
	if tool == "" {
		return "", false
	}
	f, err := os.CreateTemp("", "levelmsg-*.xml")
	if err != nil {
		return "", false
	}
	tmp := f.Name()
	f.Close()
	defer os.Remove(tmp)
	if err := exec.Command(tool, pkaPath, tmp).Run(); err != nil {
		return "", false
	}
	data, err := os.ReadFile(tmp)
	if err != nil {
		return "", false
	}
	m := completeFeedbackRe.FindSubmatch(data)
	if m == nil {
		return "", true
	}
	text = feedbackText(string(m[1]))
	if strings.EqualFold(text, ptDefaultComplete) {
		return "", true
	}
	return text, true
}

type msgEntry struct {
	mod  time.Time
	size int64
	text string
}

var (
	msgMu    sync.Mutex
	msgCache = map[string]msgEntry{}
)

// completeMessage is readCompleteMessage cached per file until the file changes (a failed
// read isn't cached, so it is retried on the next request).
func completeMessage(tool, pkaPath string) string {
	st, err := os.Stat(pkaPath)
	if err != nil {
		return ""
	}
	msgMu.Lock()
	e, hit := msgCache[pkaPath]
	msgMu.Unlock()
	if hit && e.mod.Equal(st.ModTime()) && e.size == st.Size() {
		return e.text
	}
	text, ok := readCompleteMessage(tool, pkaPath)
	if ok {
		msgMu.Lock()
		msgCache[pkaPath] = msgEntry{st.ModTime(), st.Size(), text}
		msgMu.Unlock()
	}
	return text
}

// warmCompleteMessages reads every level's message once at startup, so the first /status
// after a restart doesn't wait on pka_tool.
func warmCompleteMessages(c Config) {
	total, with := 0, 0
	for _, cp := range c.Competitions {
		for _, l := range cp.Levels {
			total++
			if completeMessage(c.PkaTool, filepath.Join(c.FilesDir, cp.ID, l.File)) != "" {
				with++
			}
		}
	}
	log.Printf("level completion messages: %d of %d levels have one", with, total)
}
