lint:
	cargo clippy --all --all-targets --all-features -- -Dwarnings
	cargo fmt --all -- --check

test:
	cargo tarpaulin --all --all-features --all-targets -o Lcov --output-dir ./coverage

.PHONY: lint test