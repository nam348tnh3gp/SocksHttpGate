FROM golang:1.23-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/dot-server .

FROM alpine:3.22
RUN apk add --no-cache ca-certificates && adduser -D -H -u 10001 app
WORKDIR /app
COPY --from=build /out/dot-server /usr/local/bin/dot-server
USER 10001:10001

EXPOSE 853/tcp
ENTRYPOINT ["/usr/local/bin/dot-server"]
