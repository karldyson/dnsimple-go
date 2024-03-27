all: linux darwin_intel darwin_apple

linux:
	GOOS=linux GOARCH=amd64 /usr/local/go/bin/go build -o build/linux/amd64/dnsimple-ds dnsimple-ds.go common.go

darwin_intel:
	GOOS=darwin GOARCH=amd64 /usr/local/go/bin/go build -o build/darwin/amd64/dnsimple-ds dnsimple-ds.go common.go

darwin_apple:
	GOOS=darwin GOARCH=arm64 /usr/local/go/bin/go build -o build/darwin/arm64/dnsimple-ds dnsimple-ds.go common.go

