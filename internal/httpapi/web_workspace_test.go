package httpapi

import (
	"bytes"
	"strings"
	"testing"
)

func TestDashboardBackgroundRefreshPreservesWorkspaceInteraction(t *testing.T) {
	app, err := webFiles.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(app)
	start := strings.Index(source, "async function refreshFleetSnapshot()")
	end := strings.Index(source[start:], "async function refreshRuntimeTelemetry()")
	if start < 0 || end < 0 {
		t.Fatal("fleet refresh implementation is unavailable")
	}
	refresh := source[start : start+end]
	successTail := refresh[strings.Index(refresh, "scheduleFleetExpiry();"):]
	if strings.Count(successTail, "renderNetworksSafely();") != 1 ||
		!strings.Contains(successTail, "if (state.fleet) await refreshRuntimeTelemetry();\n  renderNetworksSafely();") {
		t.Fatal("successful fleet refresh must collect health and runtime telemetry before one workspace render")
	}
	for _, required := range []string{
		"captureNetworkUIState", "restoreNetworkUIState",
		"openDetails", "persistFocusKey", "setSelectionRange",
		"window.scrollTo(snapshot.scrollX, snapshot.scrollY)",
		`settings.dataset.persistKey = 'network-settings'`,
		`nodeManagement.dataset.persistKey = 'node-management'`,
		`alerts.dataset.persistKey = 'health-alerts'`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("background refresh interaction preservation is missing %q", required)
		}
	}
	if strings.Count(source, "location.reload()") != 1 || !strings.Contains(source, "$('#logout').addEventListener") {
		t.Fatal("the only full page reload must remain the explicit logout transition")
	}
}

func TestDashboardExposesFleetAndNetworkNodeSearchAndGlobalGroupManagement(t *testing.T) {
	app, err := webFiles.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	html, err := webFiles.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"renderNetworkDirectoryBody", "Search every node", "renderWorkspaceNodeSearch", "Search nodes in",
		"nodeSearchModel.filter", "nodeSearch.byNetwork",
		"openSecurityGroups", "refreshSecurityGroupsDocument", "membershipChanges",
		"/groups/${encodeURIComponent(group.name)}", "previous_certificate_blocklisted",
		"renderPolicySecurityGroupOptions", "create the security group",
	} {
		if !bytes.Contains(app, []byte(required)) {
			t.Fatalf("dashboard application is missing %q", required)
		}
	}
	for _, required := range []string{
		`id="security-groups-dialog"`, `id="create-security-group-form"`,
		`id="security-group-member-list"`, `id="save-security-group-members"`,
	} {
		if !bytes.Contains(html, []byte(required)) {
			t.Fatalf("dashboard markup is missing %q", required)
		}
	}
}
