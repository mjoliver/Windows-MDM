package mdm

import (
	"strings"
	"testing"
)

func TestGenerateLAPSCredentialsAndGroupXML(t *testing.T) {
	avoid := map[string]bool{"lzadm-0000": true}
	user, pwd, err := GenerateLAPSCredentials("lzadm", 22, avoid)
	if err != nil {
		t.Fatalf("GenerateLAPSCredentials: %v", err)
	}
	if len(user) > 20 || !strings.HasPrefix(user, "lzadm-") {
		t.Fatalf("unexpected username %q (len=%d)", user, len(user))
	}
	if len(pwd) != 22 {
		t.Fatalf("want password length 22, got %d", len(pwd))
	}
	hasUpper := strings.ContainsAny(pwd, lapsUpper)
	hasLower := strings.ContainsAny(pwd, lapsLower)
	hasDigit := strings.ContainsAny(pwd, lapsDigits)
	hasSym := strings.ContainsAny(pwd, lapsSymbols)
	if !hasUpper || !hasLower || !hasDigit || !hasSym {
		t.Fatalf("password %q missing complexity class (U=%v L=%v D=%v S=%v)", pwd, hasUpper, hasLower, hasDigit, hasSym)
	}

	xmlStr := BuildLAPSGroupConfigXML("lzadm-9c4e", []string{"lzadm-7f3a", "lzadm-1122", "lzadm-9c4e"})
	if !strings.Contains(xmlStr, `desc="S-1-5-32-544"`) ||
		!strings.Contains(xmlStr, `action="U"`) ||
		!strings.Contains(xmlStr, `<add member="lzadm-9c4e"></add>`) && !strings.Contains(xmlStr, `<add member="lzadm-9c4e"/>`) ||
		strings.Contains(xmlStr, `<remove member="lzadm-9c4e"`) ||
		!strings.Contains(xmlStr, `lzadm-7f3a`) {
		t.Fatalf("unexpected GroupConfiguration XML: %s", xmlStr)
	}
}
