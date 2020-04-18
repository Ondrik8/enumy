# Enumy

Enumy is a Linux post exploitation vulnerability scanner that aims to automate as much of the intial post exploitation recon during a CTF or a pentest. Enumy has a nice interface built with ncurses if you have an SSH connection, or a standard text based interface for dumb shells.

![Example](./docs/svg/example.svg)

## Installation

You can download the final binary from the release x86 or x64 tab. _Statically linked to musl_

## Usage

Transfer the final enumyy binary to the target machine

## Compilation

To compile during devlopment, make is all that is required.

```shell
make
```

To remove the glibc dependency and compile with musl do the following.

```shell
./build.sh
cd output
```
