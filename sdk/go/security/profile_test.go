package security

import "testing"

func TestPublicMultiTenantProfileRequiresEncryption(t *testing.T) {
	profile := PublicMultiTenantProfile()

	if !profile.E2EERequired {
		t.Fatal("expected E2EE to be required")
	}

	if !profile.StorageEncryptionRequired {
		t.Fatal("expected storage encryption to be required")
	}
}

func TestSegmentPrefixMatchesChild(t *testing.T) {
	if !SegmentPrefixMatches("tenant/a", "tenant/a/object.txt") {
		t.Fatal("expected child path to match")
	}
}

func TestSegmentPrefixRejectsConfusion(t *testing.T) {
	if SegmentPrefixMatches("tenant/a", "tenant/alpha") {
		t.Fatal("expected prefix confusion to be rejected")
	}
}

func TestProfileUsesProtocolDefaults(t *testing.T) {
	profile := PublicMultiTenantProfile()
	if profile.KeyWrappingSuite != "HPKE/X25519" {
		t.Fatalf("unexpected key wrapping suite: %s", profile.KeyWrappingSuite)
	}
}
