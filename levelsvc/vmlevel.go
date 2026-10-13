package main

// Windows and Linux practices. A competition's kind says what its levels are: a Cisco level
// is a Packet Tracer .pka; a Windows or Linux level is a JSON scenario that the agent applies
// inside the student's practice VM (a README for the student, a setup script that plants the
// vulnerabilities, and the checks that score them). Scoring and gating are the same for every
// kind: each level is a sarpedon image with its own key, cleared at its threshold.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// normKind maps a requested kind to the stored one ("" = Cisco, so existing competitions,
// which have no kind, stay Cisco). ok is false for an unknown kind.
func normKind(k string) (kind string, ok bool) {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case "", "cisco":
		return "", true
	case "windows":
		return "windows", true
	case "linux":
		return "linux", true
	}
	return "", false
}

// kindName is the kind as the agent sees it.
func kindName(kind string) string {
	if kind == "" {
		return "cisco"
	}
	return kind
}

// levelExt is the stored level file's extension for a competition kind.
func levelExt(kind string) string {
	if kind == "" {
		return ".pka"
	}
	return ".json"
}

// scenario is the part of a Windows/Linux level file the server reads; the agent reads the rest.
type scenario struct {
	OS              string            `json:"os"`
	Checks          []json.RawMessage `json:"checks"`
	CompleteMessage string            `json:"complete_message"`
}

// scenarioOS lists the operating systems a kind's scenarios may target (the Linux tab also
// takes FreeBSD).
var scenarioOS = map[string][]string{"windows": {"windows"}, "linux": {"linux", "freebsd"}}

// checkScenario rejects an upload that the agent couldn't run as a level of this kind.
func checkScenario(kind string, data []byte) error {
	var s scenario
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("not a scenario file (invalid JSON: %v)", err)
	}
	ok := false
	for _, o := range scenarioOS[kind] {
		ok = ok || s.OS == o
	}
	if !ok {
		return fmt.Errorf("the scenario is for %q, but this is a %s practice", s.OS, kind)
	}
	if len(s.Checks) == 0 {
		return errors.New("the scenario has no checks")
	}
	return nil
}

// agentKinds parses the kinds an agent can play (?kinds=cisco,windows,linux). Agents before
// 1.2.0 send none and only open .pka files, so they get Cisco competitions only.
func agentKinds(q string) map[string]bool {
	out := map[string]bool{"cisco": true}
	for _, k := range strings.Split(q, ",") {
		if k = strings.ToLower(strings.TrimSpace(k)); k != "" {
			out[k] = true
		}
	}
	return out
}

// vulnDef is one scored item of a VM scenario, for the scoreboard's admin per-vuln view.
type vulnDef struct {
	Message string `json:"message"`
	Points  int    `json:"points"`
}

// scenarioVulns lists a scenario's scored items (message + points) in order. A negative-point
// item is a penalty.
func scenarioVulns(data []byte) []vulnDef {
	var s struct {
		Checks []struct {
			Message string `json:"message"`
			Points  int    `json:"points"`
		} `json:"checks"`
	}
	if json.Unmarshal(data, &s) != nil {
		return nil
	}
	out := make([]vulnDef, 0, len(s.Checks))
	for _, c := range s.Checks {
		out = append(out, vulnDef{Message: c.Message, Points: c.Points})
	}
	return out
}
