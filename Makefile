VERSION = $(shell git describe)

all: linux darwin_intel darwin_apple

linux:
	GOOS=linux GOARCH=amd64 /usr/local/go/bin/go build -o build/linux/amd64/dnsimple-cds -buildvcs=true -ldflags "-X main.versionString=$(VERSION)" dnsimple-cds.go common.go
	GOOS=linux GOARCH=amd64 /usr/local/go/bin/go build -o build/linux/amd64/dnsimple-ds -buildvcs=true -ldflags "-X main.versionString=$(VERSION)" dnsimple-ds.go common.go
	GOOS=linux GOARCH=amd64 /usr/local/go/bin/go build -o build/linux/amd64/dnsimple-ns -buildvcs=true -ldflags "-X main.versionString=$(VERSION)" dnsimple-ns.go common.go
	GOOS=linux GOARCH=amd64 /usr/local/go/bin/go build -o build/linux/amd64/dnsimple-domain -buildvcs=true -ldflags "-X main.versionString=$(VERSION)" dnsimple-domain.go common.go
	GOOS=linux GOARCH=amd64 /usr/local/go/bin/go build -o build/linux/amd64/dnsimple-contact -buildvcs=true -ldflags "-X main.versionString=$(VERSION)" dnsimple-contact.go common.go

darwin_intel:
	GOOS=darwin GOARCH=amd64 /usr/local/go/bin/go build -o build/darwin/amd64/dnsimple-cds -buildvcs=true -ldflags "-X main.versionString=$(VERSION)" dnsimple-cds.go common.go
	GOOS=darwin GOARCH=amd64 /usr/local/go/bin/go build -o build/darwin/amd64/dnsimple-ds -buildvcs=true -ldflags "-X main.versionString=$(VERSION)" dnsimple-ds.go common.go
	GOOS=darwin GOARCH=amd64 /usr/local/go/bin/go build -o build/darwin/amd64/dnsimple-ns -buildvcs=true -ldflags "-X main.versionString=$(VERSION)" dnsimple-ns.go common.go
	GOOS=darwin GOARCH=amd64 /usr/local/go/bin/go build -o build/darwin/amd64/dnsimple-domain -buildvcs=true -ldflags "-X main.versionString=$(VERSION)" dnsimple-domain.go common.go
	GOOS=darwin GOARCH=amd64 /usr/local/go/bin/go build -o build/darwin/amd64/dnsimple-contact -buildvcs=true -ldflags "-X main.versionString=$(VERSION)" dnsimple-contact.go common.go

darwin_apple:
	GOOS=darwin GOARCH=arm64 /usr/local/go/bin/go build -o build/darwin/arm64/dnsimple-cds -buildvcs=true -ldflags "-X main.versionString=$(VERSION)" dnsimple-cds.go common.go
	GOOS=darwin GOARCH=arm64 /usr/local/go/bin/go build -o build/darwin/arm64/dnsimple-ds -buildvcs=true -ldflags "-X main.versionString=$(VERSION)" dnsimple-ds.go common.go
	GOOS=darwin GOARCH=arm64 /usr/local/go/bin/go build -o build/darwin/arm64/dnsimple-ns -buildvcs=true -ldflags "-X main.versionString=$(VERSION)" dnsimple-ns.go common.go
	GOOS=darwin GOARCH=arm64 /usr/local/go/bin/go build -o build/darwin/arm64/dnsimple-domain -buildvcs=true -ldflags "-X main.versionString=$(VERSION)" dnsimple-domain.go common.go
	GOOS=darwin GOARCH=arm64 /usr/local/go/bin/go build -o build/darwin/arm64/dnsimple-contact -buildvcs=true -ldflags "-X main.versionString=$(VERSION)" dnsimple-contact.go common.go

