FROM alpine:3.11.5

RUN apk add --no-cache --update gcc musl-dev g++ bison flex make ccache git linux-headers \
    build-base alpine-sdk ncurses ncurses-dev ncurses-libs ncurses-static

RUN mkdir -p /build/output

WORKDIR /build
COPY . .

RUN make clean