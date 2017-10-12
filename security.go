package securitytxt

import (
	"bufio"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	fieldSeparator = ":"
	lineSeparator  = "\n"
	filename       = "security.txt"
)

type SecurityTxt struct {
	// Required fields
	Contact Contact

	// Optional fields
	Acknowledgements Acknowledgements
	Disclosure       Disclosure
	Encryption       Encryption
}

func Read(addr string) (*SecurityTxt, error) {
	addr, err := fixupAddr(addr)
	if err != nil {
		return nil, err
	}

	body, err := getBody(addr)
	if err != nil {
		return nil, err
	}
	return Parse(body)
}

func fixupAddr(addr string) (string, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return "", err
	}
	if !strings.HasSuffix(u.Path, filename) {
		u.Path = filename
	}
	return u.String(), nil
}

func FromFile(p string) (*SecurityTxt, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, err
	}
	s := bufio.NewScanner(f)
	return Parse(s)
}

func Parse(body *bufio.Scanner) (*SecurityTxt, error) {
	sec := SecurityTxt{}
	for body.Scan() {
		line := body.Text()

		// Split on first ':'
		parts := strings.SplitN(line, fieldSeparator, 2)
		var key, val string
		if len(parts) > 1 {
			key = strings.TrimSpace(parts[0])
			val = strings.TrimSpace(strings.Join(parts[1:], fieldSeparator))
		}

		// basic matcher
		switch strings.ToLower(key) {
		case "acknowledgements":
			if a := parseAcknowledgements(val); !a.Empty() {
				sec.Acknowledgements = a
			}
		case "contact":
			if c := parseContact(val); !c.Empty() {
				sec.Contact = c
			}
		case "disclosure":
			if d := parseDisclosure(val); !d.Empty() {
				sec.Disclosure = d
			}
		case "encryption":
			if e := parseEncryption(val); !e.Empty() {
				sec.Encryption = e
			}
		}
	}

	if err := body.Err(); err != nil {
		return nil, err
	}

	return &sec, nil
}

func getBody(addr string) (*bufio.Scanner, error) {
	client := setupHttpClient()
	resp, err := client.Get(addr)
	if err != nil {
		if resp.Body != nil {
			e2 := resp.Body.Close()
			if e2 != nil {
				return nil, e2
			}
		}
		return nil, err
	}

	s := bufio.NewScanner(resp.Body)
	s.Split(bufio.ScanLines)
	return s, nil
}

// TODO(adam): way more configs setup
// - lower max response size
// - timeouts/deadlines
// - force tls?
// - etc...
func setupHttpClient() *http.Client {
	return http.DefaultClient
}

// Records

type Acknowledgements string

func (a Acknowledgements) Empty() bool {
	return len(string(a)) == 0
}
func (a Acknowledgements) Equal(s string) bool {
	return strings.ToLower(string(a)) == strings.ToLower(s)
}
func parseAcknowledgements(val string) Acknowledgements {
	if strings.Contains(val, "http") {
		return Acknowledgements(val)
	}
	return Acknowledgements("")
}

type Contact string

func (c Contact) Empty() bool {
	return len(string(c)) == 0
}
func (c Contact) Equal(s string) bool {
	return strings.ToLower(string(c)) == strings.ToLower(s)
}
func parseContact(val string) Contact {
	// TODO(adam): real validation
	if strings.Contains(val, "@") {
		return Contact(val)
	}
	if strings.Contains(val, "http") {
		return Contact(val)
	}
	if len(val) == 7 || len(val) == 10 || strings.Contains(val, "-") {
		return Contact(val)
	}
	return Contact("")
}

type Disclosure string

func (d Disclosure) Empty() bool {
	return len(string(d)) == 0
}
func (d Disclosure) Equal(s string) bool {
	return strings.ToLower(string(d)) == strings.ToLower(s)
}
func parseDisclosure(val string) Disclosure {
	clean := strings.ToLower(val)
	switch clean {
	case "none":
		return Disclosure("none")
	case "partial":
		return Disclosure("partial")
	case "full":
		return Disclosure("full")
	}
	return Disclosure("")
}

type Encryption url.URL

func (e Encryption) Empty() bool {
	return e.Host == ""
}
func (e Encryption) Equal(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}

	// Don't compare Schema, Fragment or Query
	// Some sites/pages would still present the same content
	return e.Host == u.Host && e.Path == u.Path
}
func parseEncryption(val string) Encryption {
	u, err := url.Parse(val)
	if err != nil {
		return Encryption(url.URL{})
	}
	return Encryption(*u)
}
