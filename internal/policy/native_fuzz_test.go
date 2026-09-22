package policy

import (
	"net/netip"
	"testing"
)

func FuzzExpandNativeIPBlockNeverPanics(f *testing.F) {
	f.Add("10.0.0.0/24", "10.0.0.0/26", "10.0.0.64/26")
	f.Add("198.51.100.0/30", "198.51.100.0/31", "")
	f.Add("192.0.2.1/32", "192.0.2.1/32", "192.0.2.1/32")
	f.Add("not-a-cidr", "also-not-a-cidr", "")

	f.Fuzz(func(t *testing.T, cidr, exceptA, exceptB string) {
		if len(cidr) > 128 || len(exceptA) > 128 || len(exceptB) > 128 {
			t.Skip()
		}
		excepts := make([]string, 0, 2)
		for _, value := range []string{exceptA, exceptB} {
			if value != "" {
				excepts = append(excepts, value)
			}
		}
		prefixes, err := ExpandNativeIPBlock(NativeIPBlock{CIDR: cidr, Except: excepts})
		if err != nil {
			return
		}
		base, err := netip.ParsePrefix(cidr)
		if err != nil || !base.Addr().Is4() {
			t.Fatalf("successful expansion has an invalid base %q: %v", cidr, err)
		}
		base = base.Masked()
		for index, prefix := range prefixes {
			if !prefix.Addr().Is4() || prefix.Bits() < base.Bits() || !base.Contains(prefix.Addr()) {
				t.Fatalf("expanded prefix %q escapes base %q", prefix, base)
			}
			if index > 0 {
				previous := prefixes[index-1]
				if previous.Bits() > prefix.Bits() || (previous.Bits() == prefix.Bits() && !previous.Addr().Less(prefix.Addr())) {
					t.Fatalf("expanded prefixes are not strictly sorted: %v", prefixes)
				}
				if previous.Contains(prefix.Addr()) || prefix.Contains(previous.Addr()) {
					t.Fatalf("expanded prefixes overlap: %v", prefixes)
				}
			}
		}
		for _, rawExcept := range excepts {
			except, parseErr := netip.ParsePrefix(rawExcept)
			if parseErr != nil {
				continue
			}
			except = except.Masked()
			for _, prefix := range prefixes {
				if prefix.Contains(except.Addr()) || except.Contains(prefix.Addr()) {
					t.Fatalf("expanded prefix %q overlaps exclusion %q", prefix, except)
				}
			}
		}
		if len(prefixes) > MaxIPBlockExpansion {
			t.Fatalf("expanded %d prefixes, cap is %d", len(prefixes), MaxIPBlockExpansion)
		}
	})
}
