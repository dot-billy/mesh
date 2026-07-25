package onlinerelease

import "testing"

func TestCanonicalBundleURL(t *testing.T) {
	accepted := []string{
		"https://releases.example/channels/stable/bundle.json",
		"https://releases.example:8443/channels/stable/bundle.json",
		"https://127.0.0.1:18443/channels/stable/bundle.json",
		"https://[2001:db8::1]:8443/channels/stable/bundle.json",
	}
	for _, value := range accepted {
		t.Run("accept "+value, func(t *testing.T) {
			if got, err := CanonicalBundleURL(value); err != nil || got != value {
				t.Fatalf("CanonicalBundleURL(%q) = %q, %v", value, got, err)
			}
		})
	}

	rejected := []string{
		"",
		" http://releases.example/bundle.json",
		"http://releases.example/bundle.json",
		"https://user@releases.example/bundle.json",
		"https://releases.example/bundle.json#x",
		"https://releases.example/bundle.json?token=x",
		"https://RELEASES.example/bundle.json",
		"https://releases.example:443/bundle.json",
		"https://releases.example",
		"https://releases.example/",
		"https://releases.example/a/../bundle.json",
		"https://releases.example//bundle.json",
		"https://releases.example/%62undle.json",
		"https://releases.example/bundle%2Ejson",
		"https://releases.example/channel's/bundle.json",
		"https://releases.example/bundle json",
		"https://releases.example:0/bundle.json",
		"https://releases.example:99999/bundle.json",
		"https://releases.example:/bundle.json",
		"https:opaque",
		"HTTPS://releases.example/bundle.json",
	}
	for _, value := range rejected {
		t.Run("reject "+value, func(t *testing.T) {
			if _, err := CanonicalBundleURL(value); err == nil {
				t.Fatalf("noncanonical URL accepted: %q", value)
			}
		})
	}
}
