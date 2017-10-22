package securitytxt

import (
	"bufio"
	"net/http"
	"net/url"
	"strings"
)

func fixupAddr(addr string) (*url.URL, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(u.Path, filename) {
		u.Path = filename
	}
	return u, nil
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
// https://github.com/adamdecaf/go-security-txt/issues/1
func setupHttpClient() *http.Client {
	return http.DefaultClient
}
