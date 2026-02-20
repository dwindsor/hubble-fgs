FROM docker.io/library/golang:1.26.0@sha256:c83e68f3ebb6943a2904fa66348867d108119890a2c6a2e6f07b38d0eb6c25c5 AS builder
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /netpol

FROM gcr.io/distroless/static-debian12
COPY --from=builder /netpol /netpol
ENTRYPOINT ["/netpol"]
