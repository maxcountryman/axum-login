postgres_url = postgres://postgres:postgres@localhost:5432
mysql_url = mysql://root@localhost:3306/public
sqlite_url = sqlite://memory

integration_tests_postgres:
	DATABASE_URL=${postgres_url} cargo test --manifest-path "axum-login-tests/Cargo.toml" --features postgres

integration_tests_mysql:
	DATABASE_URL=${mysql_url} cargo test --manifest-path "axum-login-tests/Cargo.toml" --features mysql

integration_tests_sqlite:
	DATABASE_URL=${sqlite_url} cargo test --manifest-path "axum-login-tests/Cargo.toml" --features sqlite


lint:
	cargo clippy --all --all-targets --all-features -- -Dwarnings
	cd examples/; cargo clippy --all --all-targets --all-features -- -Dwarnings
	cargo fmt --all -- --check
	cd examples/; cargo fmt --all -- --check

test:
	cd ./axum-login; cargo tarpaulin --all --all-features -o Lcov --output-dir ./coverage

test_integration:
	$(MAKE) integration_tests_sqlite
	$(MAKE) integration_tests_postgres
	$(MAKE) integration_tests_mysql


.PHONY: lint test test_integration