# Build stage
FROM rust:1.85-slim AS builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src
COPY examples ./examples

# Build the application in release mode
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies if needed
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy the binary from builder
COPY --from=builder /app/target/release/netflow_generator /usr/local/bin/netflow_generator

# Copy examples
COPY examples /examples

# Set the working directory
WORKDIR /app

# Default command runs the generator in default mode
ENTRYPOINT ["/usr/local/bin/netflow_generator"]
CMD []
