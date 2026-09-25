BINARY := ids
BIN_DIR := bin
PKG := ./cmd/$(BINARY)

.PHONY: build test lint run clean

build:
	go build -o $(BIN_DIR)/$(BINARY) $(PKG)

test:
	go test ./...

lint:
	go vet ./...
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "staticcheck not installed; skipping (go install honnef.co/go/tools/cmd/staticcheck@latest)"; \
	fi

# Placeholder: cmd/ids is wired up in the integration step.
run: build
	./$(BIN_DIR)/$(BINARY) $(ARGS)

clean:
	rm -rf $(BIN_DIR)
