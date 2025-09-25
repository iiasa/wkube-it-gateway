# --- Stage 1: Build the Go binary ---
FROM golang:1.24.1 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o itgateway gateway.go

# --- Stage 2: Final image with SSH server ---
FROM linuxserver/openssh-server

# Copy the Go binary
COPY --from=builder /app/itgateway /usr/local/bin/itgateway

# Add s6 service for itgateway
RUN mkdir -p /etc/services.d/itgateway
COPY scripts/run-itgateway.sh /etc/services.d/itgateway/run
RUN chmod +x /etc/services.d/itgateway/run

# (Optional) Add cont-init.d script if you need to patch sshd_config dynamically
COPY scripts/10-sshd-config.sh /etc/cont-init.d/10-sshd-config
RUN chmod +x /etc/cont-init.d/10-sshd-config
