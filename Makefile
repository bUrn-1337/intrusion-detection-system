BIN_DIR := bin

.PHONY: build setcap test scenarios fuzz lint run clean

build:
	go build -o $(BIN_DIR)/ids ./cmd/ids
	go build -o $(BIN_DIR)/capturedump ./cmd/capturedump

# Grants raw-socket capabilities for live capture. Rebuilding strips them,
# so run this again after every build. setcap needs the capability text
# before each file.
CAPS := cap_net_raw,cap_net_admin=eip

setcap:
	sudo setcap $(CAPS) $(BIN_DIR)/ids $(CAPS) $(BIN_DIR)/capturedump

test:
	go test ./...

# Runs every testdata/scenarios/* through the ids pipeline (docs/SCENARIOS.md).
scenarios:
	go test -count=1 -run '^TestScenarios$$' ./cmd/ids/

# make fuzz FUZZTIME=2m, make fuzz FUZZ=FuzzStream
FUZZ ?= FuzzPipeline
FUZZTIME ?= 30s
fuzz:
	go test -run '^$$' -fuzz '^$(FUZZ)$$' -fuzztime $(FUZZTIME) ./cmd/ids/

lint:
	go vet ./...
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "staticcheck not installed; skipping (go install honnef.co/go/tools/cmd/staticcheck@latest)"; \
	fi

# make run ARGS="-i eth0"   (does not rebuild, so capabilities are kept)
run:
	./$(BIN_DIR)/ids run $(ARGS)

clean:
	rm -rf $(BIN_DIR)
