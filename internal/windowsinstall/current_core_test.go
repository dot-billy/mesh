package windowsinstall

import (
	"fmt"
	"strings"
	"testing"
)

func testDescriptor(digit string, sequence uint64) CurrentDescriptor {
	return CurrentDescriptor{
		Schema:         CurrentDescriptorSchema,
		InstalledID:    "s" + leftPad20(sequence) + "-r" + strings.Repeat(digit, 16) + "-a" + strings.Repeat(digit, 16),
		ArtifactSHA256: strings.Repeat(digit, 64), PackageJSONSHA256: strings.Repeat(digit, 64),
		Architecture: "amd64", SecurityFloor: sequence,
	}
}

func leftPad20(value uint64) string {
	return fmt.Sprintf("%020d", value)
}

func TestCurrentDescriptorCanonicalRoundTrip(t *testing.T) {
	descriptor := testDescriptor("a", 1)
	raw, err := MarshalCurrentDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCurrentDescriptor(raw)
	if err != nil || !descriptorEqual(&parsed, &descriptor) {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
	for _, mutation := range [][]byte{
		append([]byte(" "), raw...),
		append(append([]byte(nil), raw...), '\n'),
		[]byte(strings.Replace(string(raw), `"schema":`, `"schema":"mesh-windows-current-release-v1","schema2":`, 1)),
	} {
		if _, err := ParseCurrentDescriptor(mutation); err == nil {
			t.Fatalf("noncanonical descriptor accepted: %q", mutation)
		}
	}
}

func TestCurrentDescriptorRejectsAuthorityDrift(t *testing.T) {
	tests := []func(*CurrentDescriptor){
		func(value *CurrentDescriptor) { value.Schema = "other" },
		func(value *CurrentDescriptor) { value.InstalledID = "release" },
		func(value *CurrentDescriptor) { value.ArtifactSHA256 = strings.Repeat("A", 64) },
		func(value *CurrentDescriptor) { value.PackageJSONSHA256 = "" },
		func(value *CurrentDescriptor) { value.Architecture = "386" },
		func(value *CurrentDescriptor) { value.SecurityFloor = 0 },
	}
	for index, mutate := range tests {
		value := testDescriptor("b", 2)
		mutate(&value)
		if err := value.Validate(); err == nil {
			t.Fatalf("mutation %d accepted", index)
		}
	}
}

type fakeCurrentSwitch struct {
	targets map[string]bool
	current *CurrentDescriptor
	temp    *CurrentDescriptor
	syncs   int
}

func (fake *fakeCurrentSwitch) InspectTarget(target CurrentDescriptor) error {
	if !fake.targets[target.InstalledID] {
		return stringsError("target unavailable")
	}
	return nil
}

func (fake *fakeCurrentSwitch) InspectCurrent() (*CurrentDescriptor, error) {
	return cloneDescriptor(fake.current), nil
}
func (fake *fakeCurrentSwitch) InspectTemporary(target CurrentDescriptor) (bool, error) {
	return descriptorEqual(fake.temp, &target), nil
}
func (fake *fakeCurrentSwitch) CreateTemporary(target CurrentDescriptor) error {
	copy := target
	fake.temp = &copy
	return nil
}
func (fake *fakeCurrentSwitch) RemoveTemporary() error { fake.temp = nil; return nil }
func (fake *fakeCurrentSwitch) SyncRoot() error        { fake.syncs++; return nil }
func (fake *fakeCurrentSwitch) ReplaceCurrent(target CurrentDescriptor) error {
	if !descriptorEqual(fake.temp, &target) {
		return stringsError("temporary drift")
	}
	fake.current = cloneDescriptor(fake.temp)
	fake.temp = nil
	return nil
}

type stringsError string

func (value stringsError) Error() string { return string(value) }

func cloneDescriptor(value *CurrentDescriptor) *CurrentDescriptor {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func TestSwitchCurrentReleaseInitialUpgradeRecoveryAndStalePrior(t *testing.T) {
	first, second, third := testDescriptor("c", 3), testDescriptor("d", 4), testDescriptor("e", 5)
	fake := &fakeCurrentSwitch{targets: map[string]bool{first.InstalledID: true, second.InstalledID: true, third.InstalledID: true}}
	if err := switchCurrentRelease(fake, nil, first); err != nil {
		t.Fatal(err)
	}
	if !descriptorEqual(fake.current, &first) || fake.temp != nil || fake.syncs != 2 {
		t.Fatalf("initial switch state=%#v temp=%#v syncs=%d", fake.current, fake.temp, fake.syncs)
	}
	// A crash after temporary publication is recovered by the same exact
	// expected-prior transaction.
	fake.temp = cloneDescriptor(&second)
	if err := switchCurrentRelease(fake, &first, second); err != nil {
		t.Fatal(err)
	}
	if !descriptorEqual(fake.current, &second) || fake.temp != nil {
		t.Fatalf("upgrade state=%#v temp=%#v", fake.current, fake.temp)
	}
	if err := switchCurrentRelease(fake, &first, third); err == nil || !strings.Contains(err.Error(), "expected prior") {
		t.Fatalf("stale prior error=%v", err)
	}
	// Idempotent replay proves the target and scavenges only its recognized
	// temporary descriptor.
	fake.temp = cloneDescriptor(&second)
	if err := switchCurrentRelease(fake, &first, second); err != nil {
		t.Fatal(err)
	}
	if fake.temp != nil {
		t.Fatal("recognized replay temporary survived")
	}
}
