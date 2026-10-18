FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/odoh-proxy ./Proxy
FROM alpine:3.21
RUN adduser -D -H -u 10001 app
COPY --from=build /out/odoh-proxy /usr/local/bin/odoh-proxy
USER 10001
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/odoh-proxy"]
