package httpapi

import (
	"bytes"
	"testing"
)

func TestNodeActionsUseResponsiveCardToolbar(t *testing.T) {
	managedCSS, err := webFiles.ReadFile("web/managed.css")
	if err != nil {
		t.Fatal(err)
	}
	appScript, err := webFiles.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}

	for _, required := range []string{
		`"node-info node-status"`,
		`"node-actions node-actions"`,
		"grid-area: node-actions",
		"max-width: none",
		"@media (max-width: 760px)",
		"grid-template-columns: repeat(2, minmax(0, 1fr))",
	} {
		if !bytes.Contains(managedCSS, []byte(required)) {
			t.Fatalf("responsive node-action toolbar is missing %q", required)
		}
	}
	for _, required := range []string{
		"actions.setAttribute('role', 'group')",
		"actions.setAttribute('aria-label', `Actions for ${node.name}`)",
	} {
		if !bytes.Contains(appScript, []byte(required)) {
			t.Fatalf("node action group accessibility contract is missing %q", required)
		}
	}
}
