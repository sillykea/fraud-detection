FROM golang:1.26-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /fraud ./cmd/fraud \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /simulate ./cmd/simulate

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /fraud /fraud
COPY --from=build /simulate /simulate
EXPOSE 8090
USER nonroot
ENTRYPOINT ["/fraud"]
