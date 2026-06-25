# --- Stage 1: Build the React Frontend ---
FROM node:20-alpine AS web-builder
WORKDIR /app/web
COPY web/package*.json ./
RUN npm install
COPY web/ ./
RUN npm run build

# --- Stage 2: Build the Go Backend ---
FROM golang:1.26-alpine AS go-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Copy the compiled React assets from Stage 1 into internal/server/web_dist
COPY --from=web-builder /app/web/dist ./internal/server/web_dist
# Compile the binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o latchz ./cmd/latchz

# --- Stage 3: Final Minimal Image ---
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -u 10001 -h /app latchz
WORKDIR /app
COPY --from=go-builder --chown=latchz:latchz /app/latchz .

# Run as a non-root user.
USER latchz

# Expose port (Cloud Run defaults to 8080)
EXPOSE 8080

# Run the app
CMD ["./latchz", "serve"]
