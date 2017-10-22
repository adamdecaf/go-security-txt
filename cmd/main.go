package main

import (
	"flag"
	"fmt"
	"os"

	sectext "github.com/adamdecaf/go-security-txt"
)

var (
	fs = flag.NewFlagSet("flag", flag.ExitOnError)

	address = fs.String("address", "", "The address to check for a security.txt file")
	version = fs.Bool("version", false, "Show the version")
)

const (
	Version = "0.1.0"
)

func main() {
	fs.Parse(os.Args[1:])

	if address != nil && *address != "" {
		sec, err := sectext.Read(*address)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		output(*address, *sec)
		os.Exit(0)
	}

	if version != nil && *version {
		fmt.Printf("security-txt: %s\n", Version)
		os.Exit(0)
	}

	fs.PrintDefaults()
	os.Exit(1)
}

func output(addr string, sec sectext.SecurityTxt) {
	fmt.Printf("security.txt for %s\n", addr)
	fmt.Printf("  Contact: %s\n", sec.Contact)
	if !sec.Acknowledgements.Empty() {
		fmt.Printf("  Acknowledgements: %s\n", sec.Acknowledgements)
	}
	if !sec.Encryption.Empty() {
		fmt.Printf("  Encryption: %s", sec.Encryption)
	}
}
