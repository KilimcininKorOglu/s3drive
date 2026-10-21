BIN := bin/s3drive
VERSION ?= 0.1.0
LDFLAGS := -s -w -X s3drive/internal/config.Version=$(VERSION)

.PHONY: all build run dev test vet fmt tidy docker clean

all: build

build:
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN) ./cmd/s3drive

run: build
	./$(BIN)

dev:
	go run ./cmd/s3drive

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal web/embed.go

tidy:
	go mod tidy

docker:
	docker build --build-arg VERSION=$(VERSION) -t s3drive:$(VERSION) -t s3drive:latest .

clean:
	rm -rf bin
