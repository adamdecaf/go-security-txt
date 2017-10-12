.PHONY: build

build:
	go build -o bin/security-txt github.com/adamdecaf/go-security-txt/cmd
	@chmod +x bin/*
