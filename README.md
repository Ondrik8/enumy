# Enumy

![Example](./docs/svg/example.svg)

Enumy is portable executable that you drop on target Linux machine during a pentest or CTF in the post exploitation phase. Running enumy will enumerate the box for common security vulnerabilities. Enumy has a Htop like Ncurses interface or a standard interface for dumb reverse shells.  

## Installation

You can download the final binary from the release x86 or x64 tab. _Statically linked to musl_
Transfer the final enumy binary to the target machine

- [latest release](https://github.com/luke-goddard/enumy/releases)

```shell
./enumy
```

## Who Should Use Enumy?

- Pentester can run on a target machine raisable issues for their reports.
- CTF players can use it identify things that they might have missed.
- People who are curious to know how many isues enumy finds on their local machine? 

## Options

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

To compile during _devlopment_, make libcap and the ncurses libary is all that is required.

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

Below is the ever growing list of scans that have been implemented.

### Quck Scan

- SUID/GUID scans
- File capabilities
- Interesting files scan
- Coredump scan
- Breakout binary scan

### Full Scan

- This is a superset of quick scan
- Elf shared libary injection

## Scan Times

Changing the default number of threads is pretty pointless __unless__  you're running a full scan. A full scan will do a lot more IO so more threads greatly decrease scan times. These are the scan times with a i7-8700k and 2 million files scanned.

### Quick Scan Times

- 2 Thread  -> `system 70%  cpu 54.093 total`
- 2 Thread  -> `system 121% cpu 26.122 total`
- 4 Thread  -> `system 289% cpu 15.657 total`
- 8 Threads -> `system 468% cpu 15.863 total`
- 12 Thread -> `system 420% cpu 20.548 total`

### Full Scan Times 

- 1 Thread  -> `system 50%  cpu 3:16.38 total`
- 2 Thread  -> `system 86%  cpu 1:33.95 total`
- 4 Thread  -> `system 165% cpu 47.753 total`
- 8 Threads -> `system 366% cpu 29.768 total`
- 12 Thread -> `system 467% cpu 29.815 total`
