package securitytxt

import (
	"bufio"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	overallTimeout = time.Second * 30
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
		if resp != nil && resp.Body != nil {
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

func setupHttpClient() *http.Client {
	c := &http.Client{}
	c.Timeout = overallTimeout

	// don't follow redirects
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// From the docs, src/net/http/client.go
		//
		// As a special case, if CheckRedirect returns ErrUseLastResponse,
		// then the most recent response is returned with its body
		// unclosed, along with a nil error.
		return http.ErrUseLastResponse
	}

	return c
}
