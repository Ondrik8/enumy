# Enumy

Enumy is a Linux post exploitation vulnerability scanner that aims to automate as much of the intial post exploitation recon during a CTF or a pentest. Enumy has a nice interface built with ncurses if you have an SSH connection, or a standard text based interface for dumb shells. With an emphisise on portablility and speed.

![Example](./docs/svg/example.svg)

## Installation

You can download the final binary from the release x86 or x64 tab. _Statically linked to musl_

- [latest release](https://github.com/luke-goddard/enumy/releases)

## Usage

Transfer the final enumy binary to the target machine

```
$ ./enumy64 -h

 ▄█▀─▄▄▄▄▄▄▄─▀█▄  _____
 ▀█████████████▀ |   __|___ _ _ _____ _ _
     █▄███▄█     |   __|   | | |     | | |
      █████      |_____|_|_|___|_|_|_|_  |
      █▀█▀█                          |___|

------------------------------------------

Enumy - Used to enumerate the target environment and look for common
security vulnerabilities and hostspots

 -o <loc>     Save results to location
 -i <loc>     Ignore files in this directory (usefull for network shares)
 -w <loc>     Only walk files in this directory (usefull for devlopment)
 -t <num>     Threads (default 4)
 -f           Run full scans
 -n           Enabled ncurses
 -h           Show help
 ```

## Compilation

To compile during devlopment, make libcap and the ncurses libary is all that is required.

```shell
make
```

To remove the glibc dependency and statically link all libaries/compile with musl do the following. _Note to do this you will have to have docker installed to create the apline build environment._

```shells
./build.sh 64bit
./build.sh 32bit
./build.sh all
cd output
```

## Scans That've Been Implemented

- SUID/GUID scans
- File capabilities
- Interesting files scan
- Coredump scan
- Breakout binary scan

## Optimization

Changing the default number of threads is pretty pointless __unless__  you're running a full scan. A full scan will do a lot more IO so threads greatly increase scan times. For a full scan on my system it took the following times.

- 1 Thread  -> `system 50% cpu 3:16.38 total`
- 2 Thread  -> `system 86% cpu 1:33.95 total`
- 4 Thread  -> `system 165% cpu 47.753 total`
- 8 Threads -> `system 366% cpu 29.768 total`
- 12 Thread -> `system 467% cpu 29.815 total`
