FROM golang:1.24-bookworm AS build
WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -o /out/valden-server ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/valden-server /app/valden-server
COPY migrations /app/migrations

ENV LISTEN_ADDR=:8080
EXPOSE 8080
ENTRYPOINT ["/app/valden-server"]
