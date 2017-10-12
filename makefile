.PHONY: build

build: check
	@chmod +x bin/*

dev: check
	go build -o bin/security-txt github.com/adamdecaf/go-security-txt/cmd
	@chmod +x bin/*

check:
	go vet ./...
	go fmt ./...

test:
	go test ./...
