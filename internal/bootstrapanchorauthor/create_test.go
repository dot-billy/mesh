package bootstrapanchorauthor

import "testing"

func TestCreateRejectsInvalidHandoffBeforeAnchor(t *testing.T) {
	if document, raw, err := Create([]byte("{}\n")); err == nil || document.Schema != "" || raw != nil {
		t.Fatalf("invalid handoff = %#v %q %v", document, raw, err)
	}
}
