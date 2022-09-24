ARG GO_VERSION=1.17

FROM golang:${GO_VERSION}-alpine as build

RUN apk --no-cache add make
WORKDIR /src
COPY go.mod go.sum /src/
RUN go mod download
COPY . /src/
RUN make build

FROM gcr.io/distroless/base:debug AS debug
COPY --from=build /src/bin/in-toto /bin/in-toto
ENTRYPOINT [ "/bin/in-toto" ]

FROM gcr.io/distroless/base
COPY --from=build /src/bin/in-toto /bin/in-toto
ENTRYPOINT [ "/bin/in-toto" ]
