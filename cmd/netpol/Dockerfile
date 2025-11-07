FROM docker.io/library/golang:1.25.4 AS builder
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /netpol

FROM gcr.io/distroless/static-debian12
COPY --from=builder /netpol /netpol
ENTRYPOINT ["/netpol"]
