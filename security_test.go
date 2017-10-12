package securitytxt

import (
	"testing"
)

func TestSecurity__read(t *testing.T) {
	s1, e1 := Read("https://securitytxt.org/")
	if e1 != nil {
		t.Fatal(e1)
	}
	if !s1.Acknowledgements.Empty() {
		t.Fatalf("s1.Acknowledgements was non-empty: %s", s1.Acknowledgements)
	}
	if !s1.Contact.Equal("https://twitter.com/EdOverflow") {
		t.Fatalf("s1.Contact was something else: %s", s1.Contact)
	}
	if !s1.Disclosure.Empty() {
		t.Fatalf("s1.Disclosure was non-empty: %s", s1.Disclosure)
	}
	if !s1.Encryption.Empty() {
		t.Fatalf("s1.Encryption was non-empty: %v", s1.Encryption)
	}

	// full addr
	s2, e2 := Read("https://securitytxt.org/security.txt")
	if e2 != nil {
		t.Fatal(e2)
	}
	if !s2.Acknowledgements.Empty() {
		t.Fatalf("s2.Acknowledgements was non-empty: %s", s2.Acknowledgements)
	}
	if !s2.Contact.Equal("https://twitter.com/EdOverflow") {
		t.Fatalf("s2.Contact was something else: %s", s2.Contact)
	}
	if !s2.Disclosure.Empty() {
		t.Fatalf("s2.Disclosure was non-empty: %s", s2.Disclosure)
	}
	if !s2.Encryption.Empty() {
		t.Fatalf("s2.Encryption was non-empty: %v", s2.Encryption)
	}
}

func TestSecurity__parse(t *testing.T) {
	sec, err := FromFile("testdata/security.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !sec.Acknowledgements.Equal("https://example.com/about/security") {
		t.Fatalf("sec.Acknowledgements was something else: %s", sec.Acknowledgements)
	}
	if !sec.Contact.Equal("security@example.com") {
		t.Fatalf("sec.Contact was something else: %s", sec.Contact)
	}
	if !sec.Disclosure.Equal("Full") {
		t.Fatalf("sec.Disclosure was something else: %s", sec.Disclosure)
	}
	if !sec.Encryption.Equal("https://example.com/security.gpg") {
		t.Fatalf("sec.Encryption was something else: %v", sec.Encryption)
	}
}
