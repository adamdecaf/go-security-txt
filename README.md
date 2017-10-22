## go-security-txt

A golang parser and cli tool for [security.txt](https://securitytxt.org/)

### Usage

If you want to use this as a library:

```go
package main

import (
    sectext "github.com/adamdecaf/go-security-txt"
)

func main() {
    addr := "https://securitytxt.org"
    sec, err := sectext.FromUrl(addr)
    if err != nil {
			fmt.Println(err)
    }
    fmt.Println(sec.Contact)
}
```

### Cli

You can use the cli like:

```
$ security-txt -address https://securitytxt.org
security.txt for https://securitytxt.org
  Contact: https://twitter.com/EdOverflow
```
