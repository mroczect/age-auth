.PHONY: all build release check test lint fmt clippy clean run install ci

MEMBERS = age_auth libage_authenticator libage_crypto libage_otp libage_auth_handler
SNAPCAT = snapcat
SNAPCAT_OPTS =

all: build

build:
	cargo build

release:
	cargo build --release

check:
	cargo check --workspace

test:
	cargo test --workspace

test-verbose:
	cargo test --workspace -- --nocapture

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

lint: fmt clippy

clean:
	cargo clean

run:
	cargo run

install:
	cargo install --path .

uninstall:
	cargo uninstall jsscli

ci: fmt-check clippy test

rebuild:
	make release && make install

snap:
	mkdir -p dev
	@for dir in $(MEMBERS); do \
		if [ -d "$$dir" ]; then \
			echo "📸 $$dir"; \
			$(SNAPCAT) $$dir -f markdown $(SNAPCAT_OPTS) -o dev/$$dir.src.snapcat.md; \
		fi; \
		if [ -d "$$dir/tests" ]; then \
			echo "📸 $$dir/tests"; \
			$(SNAPCAT) $$dir/tests -f markdown $(SNAPCAT_OPTS) -o dev/$$dir.tests.snapcat.md; \
		fi; \
	done
	@echo "Menggabungkan semua snapshot ke dev/root.md"
	cat dev/*.snapcat.md > dev/root.md
	@echo "Selesai. Lihat dev/root.md"
