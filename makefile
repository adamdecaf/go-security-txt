.PHONY: build

linux: linux_amd64
linux_amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o bin/security-txt-linux-amd64 github.com/adamdecaf/go-security-txt/cmd

osx: osx_amd64
osx_amd64:
	GOOS=darwin GOARCH=amd64 go build -o bin/security-txt-osx-amd64 github.com/adamdecaf/go-security-txt/cmd

win: win_32 win_64
win_32:
	CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -o bin/security-txt-386.exe github.com/adamdecaf/go-security-txt/cmd
win_64:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/security-txt-amd64.exe github.com/adamdecaf/go-security-txt/cmd

dist: check linux osx win
	@chmod +x bin/*

build: check
	go build -o bin/security-txt github.com/adamdecaf/go-security-txt/cmd
	@chmod +x bin/*

check:
	go vet ./...
	go fmt ./...

test:
	go test ./...
