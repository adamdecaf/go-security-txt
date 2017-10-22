package securitytxt

import (
	"bufio"
	"errors"
	"fmt"
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
	Encryption       Encryption

	// Private fields
	originalUrl *url.URL
}

func (s SecurityTxt) String() string {
	out := ""
	out += fmt.Sprintf("  Contact: %s\n", s.Contact)
	if !s.Acknowledgements.empty() {
		out += fmt.Sprintf("  Acknowledgements: %s\n", s.Acknowledgements)
	}
	if !s.Encryption.Empty() {
		out += fmt.Sprintf("  Encryption: %v", s.Encryption)
	}
	return out
}

func FromUrl(addr string) (*SecurityTxt, error) {
	u, err := fixupAddr(addr)
	if err != nil {
		return nil, err
	}

	body, err := getBody(u.String())
	if err != nil {
		return nil, err
	}

	sec, err := Parse(body)
	if sec != nil {
		sec.originalUrl = u
	}
	return sec, err
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
			ack, err := sec.checkAcknowledgements(val)
			if err != nil {
				return nil, err
			}
			sec.Acknowledgements = ack
		case "contact":
			c, err := sec.checkContact(val)
			if err != nil {
				return nil, err
			}
			if !c.Empty() {
				sec.Contact = c
			}
		case "encryption":
			e, err := sec.checkEncryption(val)
			if err != nil {
				return nil, err
			}
			if !e.Empty() {
				sec.Encryption = e
			}
		}
	}

	if err := body.Err(); err != nil {
		return nil, err
	}

	return &sec, nil
}

// Records

type Acknowledgements string

func (a Acknowledgements) empty() bool {
	return len(string(a)) == 0
}
func (a Acknowledgements) Equal(s string) bool {
	return strings.ToLower(string(a)) == strings.ToLower(s)
}
func (s SecurityTxt) checkAcknowledgements(val string) (Acknowledgements, error) {
	if !strings.Contains(val, "http") {
		return "", errors.New("acknowledgement needs to contain a link")
	}

	// Verify the ack link is on the same domain
	u, err := url.Parse(val)
	if err != nil {
		return "", err
	}
	if s.originalUrl != nil {
		if s.originalUrl.Hostname() != u.Hostname() {
			return "", errors.New("acknowledgement link is on a different url")
		}
	}

	// Check the site resolves
	client := setupHttpClient()
	resp, err := client.Get(u.String())
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("bad response status: %s", resp.Status)
	}

	return Acknowledgements(u.String()), nil
}

type Contact string

func (c Contact) Empty() bool {
	return len(string(c)) == 0
}
func (c Contact) Equal(s string) bool {
	return strings.ToLower(string(c)) == strings.ToLower(s)
}
func (s SecurityTxt) checkContact(val string) (Contact, error) {
	// TODO(adam): real validation
	if strings.Contains(val, "@") {
		return Contact(val), nil
	}
	if strings.Contains(val, "http") {
		return Contact(val), nil
	}
	if len(val) == 7 || len(val) == 10 || strings.Contains(val, "-") {
		return Contact(val), nil
	}
	return "", errors.New("invalid contact")
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
func (s SecurityTxt) checkEncryption(val string) (Encryption, error) {
	empty := Encryption(url.URL{})
	u, err := url.Parse(val)
	if err != nil {
		return empty, err
	}

	// Verify the link is over https
	if u.Scheme != "https" {
		return empty, errors.New("encryption email not over https")
	}

	// verify key is coming from the same hostname
	if s.originalUrl != nil {
		if s.originalUrl.Hostname() != u.Hostname() {
			return empty, errors.New("encryption isn't on the same hostname")
		}
	}

	// Check response status
	client := setupHttpClient()
	resp, err := client.Get(u.String())
	if err != nil {
		return empty, err
	}
	if resp.StatusCode != 200 {
		return empty, fmt.Errorf("bad response status: %s", resp.Status)
	}

	return Encryption(*u), nil
}
