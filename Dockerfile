FROM golang:1.24.1-alpine AS build

WORKDIR /src

# Copy go.mod and go.sum to cache dependencies
COPY go.mod go.sum ./

# Download all dependencies. Caching is leveraged to speed up builds.
RUN go mod download

# Copy the source code into the container
COPY . ./

# Build the Go application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o sshm ./cmd/sshm

FROM nicolaka/netshoot

# ~400k - compared to 4.3M (2.9 stripped)
COPY --from=build /src/sshm /ko-app/sshm
ENTRYPOINT ["/ko-app/sshm"]
