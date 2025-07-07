# --- Stage 1: Build the Go binary ---
FROM golang:1.24.1 AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum separately to leverage caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the Go binary
RUN env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o itgateway main.go

# --- Stage 2: Create final image with SSH server ---
FROM linuxserver/openssh-server

# Copy the built binary from the builder stage
COPY --from=builder /app/itgateway /usr/local/bin/itgateway

# Copy your custom entrypoint script
COPY entrypoint.sh /custom-entrypoint.sh
RUN chmod +x /custom-entrypoint.sh

# Set custom entrypoint (ensure script is in the right path)
ENTRYPOINT ["/custom-entrypoint.sh"]
