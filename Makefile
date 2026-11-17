build:
	go build -v -trimpath -ldflags='-w -s -buildid=' -tags "with_quic" ./cmd/sing-trusttunnel

fmt:
	@golangci-lint fmt

fmt_install:
	$(MAKE) lint_install

lint:
	GOOS=linux golangci-lint run ./...
	GOOS=android GOARCH=arm64 golangci-lint run ./...
	GOOS=windows golangci-lint run ./...
	GOOS=darwin golangci-lint run ./...
	GOOS=freebsd golangci-lint run ./...

lint_install:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

test:
	go test -v -tags "with_quic" ./...
