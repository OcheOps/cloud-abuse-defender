# Image for the offline `cad` analyser. It needs no network access and no
# cloud credentials: mount the files to analyse.
#
#   docker build -t cad .
#   docker run --rm -v "$PWD:/data:ro" cad detect -file /data/trail.json.gz
#
# cad-watch is not included: it shells out to the AWS CLI, which this image
# deliberately does not contain. Run cad-watch from a host that has it.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/cad ./cmd/cad

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/cad /usr/local/bin/cad
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/cad"]
CMD ["help"]
