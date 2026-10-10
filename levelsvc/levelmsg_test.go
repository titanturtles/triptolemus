package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFeedbackText(t *testing.T) {
	cases := []struct{ raw, want string }{
		// as saved by PT's Activity Wizard (team assignment level 1, password replaced)
		{`&lt;html contenteditable="true">&lt;head>&lt;/head>&lt;body>Congratulations on passing this level! Your password is "s3cret". Use it to extract level2.pka :D&lt;div>&lt;br>&lt;/div>&lt;div>&lt;br>&lt;div>&lt;br>&lt;/div>&lt;/div>&lt;/body>&lt;/html>`,
			`Congratulations on passing this level! Your password is "s3cret". Use it to extract level2.pka :D`},
		// literal angle brackets typed into the message are double-escaped
		{`&lt;html>&lt;body>The password is: &amp;lt;GET_TO_100%_FIRST&amp;gt;&lt;/body>&lt;/html>`,
			`The password is: <GET_TO_100%_FIRST>`},
		// Qt rich text with a style block, paragraphs and &nbsp;
		{`&lt;html>&lt;head>&lt;style type="text/css">p, li { white-space: pre-wrap; }&lt;/style>&lt;/head>&lt;body>&lt;p>Round 2 password:&amp;nbsp; &lt;b>blue-otter&lt;/b>&lt;/p>&lt;p>Good luck!&lt;/p>&lt;/body>&lt;/html>`,
			"Round 2 password: blue-otter\nGood luck!"},
		{``, ``},
	}
	for _, c := range cases {
		if got := feedbackText(c.raw); got != c.want {
			t.Errorf("feedbackText(%.40q…) = %q, want %q", c.raw, got, c.want)
		}
	}
}

// fakePkaTool writes a stand-in for pka_tool that "decrypts" a .pka by copying it (the test
// .pka files are plain XML) and counts its runs in <dir>/runs.
func fakePkaTool(t *testing.T, dir string) string {
	tool := filepath.Join(dir, "pka_tool")
	script := "#!/bin/sh\necho run >> " + filepath.Join(dir, "runs") + "\ncp \"$1\" \"$2\"\n"
	if err := os.WriteFile(tool, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	return tool
}

func activityXML(complete string) string {
	return `<PACKETTRACER5_ACTIVITY><ACTIVITY><OVERALL_INCOMPLETE_FEEDBACK translate="true">&lt;html>&lt;body>Keep going&lt;/body>&lt;/html></OVERALL_INCOMPLETE_FEEDBACK>
  <OVERALL_COMPLETE_FEEDBACK translate="true">&lt;html>&lt;head>&lt;/head>&lt;body>` + complete + `&lt;/body>&lt;/html></OVERALL_COMPLETE_FEEDBACK></ACTIVITY></PACKETTRACER5_ACTIVITY>`
}

func TestCompleteMessage(t *testing.T) {
	dir := t.TempDir()
	tool := fakePkaTool(t, dir)
	runs := func() int {
		b, _ := os.ReadFile(filepath.Join(dir, "runs"))
		return strings.Count(string(b), "run")
	}
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	l1 := write("l1.pka", activityXML(`Your password is "s3cret".`))
	if got := completeMessage(tool, l1); got != `Your password is "s3cret".` {
		t.Fatalf("level 1 message = %q", got)
	}
	completeMessage(tool, l1)
	if runs() != 1 {
		t.Fatalf("expected the cached message to be reused, pka_tool ran %d times", runs())
	}

	// a re-uploaded file is read again
	os.WriteFile(l1, []byte(activityXML(`New password: "t0p".`)), 0644)
	os.Chtimes(l1, time.Now().Add(time.Minute), time.Now().Add(time.Minute))
	if got := completeMessage(tool, l1); got != `New password: "t0p".` {
		t.Fatalf("message after re-upload = %q", got)
	}

	// PT's stock text and a missing element both mean "no message"
	if got := completeMessage(tool, write("l2.pka", activityXML("Congratulations on completing this activity!"))); got != "" {
		t.Errorf("PT default text should be skipped, got %q", got)
	}
	if got := completeMessage(tool, write("l3.pka", "<PACKETTRACER5_ACTIVITY/>")); got != "" {
		t.Errorf("no feedback element should give no message, got %q", got)
	}

	// a failed read isn't cached
	before := runs()
	bad := filepath.Join(dir, "bad.pka")
	os.Mkdir(bad, 0755) // cp of a directory fails, like pka_tool on a corrupt file
	completeMessage(tool, bad)
	completeMessage(tool, bad)
	if runs()-before != 2 {
		t.Errorf("a failed read should be retried, pka_tool ran %d times", runs()-before)
	}
	if got := completeMessage("", l1); got != `New password: "t0p".` {
		t.Errorf("cached message should survive a missing tool, got %q", got)
	}
}
