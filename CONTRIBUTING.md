## Contribute code to axum-login

### Local setup

1. Install Rust using [rustup], which allows you to easily switch between Rust versions
2. Install Docker and Docker Compose
3. Setup databases for integration tests by running `docker-compose up -d`

[rustup]: https://rustup.rs/

### Running tests locally

1. Run `make test` to run the tests
2. Run `make integration_tests` to run database stores integration tests

### Code style
1. Run `make lint` to have Clippy and Rust FMT check your code