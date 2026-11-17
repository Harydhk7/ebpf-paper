ROOT := $(CURDIR)
DAEMON_DIR := $(ROOT)/daemon
SDK_DIR := $(ROOT)/sdk/python

.PHONY: all bpf daemon sdk paper test test-deps clean

all: bpf daemon sdk

bpf:
	@if command -v bpftool >/dev/null 2>&1 && test -r /sys/kernel/btf/vmlinux; then \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(ROOT)/bpf/vmlinux.h; \
	fi
	cd $(DAEMON_DIR) && go generate

daemon: bpf
	cd $(DAEMON_DIR) && go build -o $(ROOT)/intentguardd .

sdk:
	python3 -m pip wheel --no-deps --wheel-dir $(SDK_DIR)/dist $(SDK_DIR)

paper:
	mkdir -p papers/build
	cd papers && pdflatex -interaction=nonstopmode -halt-on-error -output-directory=build ieee.tex

test-deps:
	python3 -m pip install 'pytest>=8'

test: test-deps
	python3 -m pytest -q

clean:
	rm -f $(ROOT)/intentguardd
	rm -rf $(SDK_DIR)/build $(SDK_DIR)/dist $(SDK_DIR)/intentguard.egg-info
