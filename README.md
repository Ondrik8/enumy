# Enumy

Enumy is a Linux post exploitation vulnerability scanner that aims to automate as much of the intial post exploitation recon during a CTF or a pentest. Enumy has a nice interface built with ncurses if you have an SSH connection, or a standard text based interface for dumb shells.

![Example](./docs/svg/example.svg)

## Installation

You can download the final binary from the release x86 or x64 tab. _Statically linked to musl_

## Usage

Transfer the final enumy binary to the target machine

## Compilation

To compile during devlopment, make libcap and the ncurses libary is all that is required.

```shell
make
```

To remove the glibc dependency and statically link all libaries/compile with musl do the following. _Note to do this you will have to have docker installed to create the apline build environment._

```shell
./build.sh 64bit
./build.sh 32bit
./build.sh all
cd output
```

## Scans That've Been Implemented

- SUID/GUID scans
- File capabilities


Note: this capability is overloaded; see Notes to kernel developers, below.

- Perform a range of system administration operations including: quotactl(2), mount(2), umount(2), pivot_root(2), swapon(2), swapoff(2), sethostname(2), and setdomainname(2);
- perform privileged syslog(2) operations (since Linux 2.6.37, CAP_SYSLOG should be used to permit such operations);
- perform VM86_REQUEST_IRQ vm86(2) command;
- perform IPC_SET and IPC_RMID operations on arbitrary System V IPC objects;
- override RLIMIT_NPROC resource limit;
- perform operations on trusted and security Extended Attributes (see xattr(7));
- use lookup_dcookie(2);
- use ioprio_set(2) to assign IOPRIO_CLASS_RT and (before Linux 2.6.25) IOPRIO_CLASS_IDLE I/O scheduling classes;
- forge PID when passing socket credentials via UNIX domain sockets;
- exceed /proc/sys/fs/file-max, the system-wide limit on the number of open files, in system calls that open files (e.g., accept(2), execve(2), open(2), pipe(2));
- employ CLONE_* flags that create new namespaces with clone(2) and unshare(2) (but, since Linux 3.8, creating user namespaces does not require any capability);
- call perf_event_open(2);
- access privileged perf event information;
- call setns(2) (requires CAP_SYS_ADMIN in the target namespace);
- call fanotify_init(2);
- call bpf(2);
- perform privileged KEYCTL_CHOWN and KEYCTL_SETPERM keyctl(2) operations;
- perform madvise(2) MADV_HWPOISON operation;
- employ the TIOCSTI ioctl(2) to insert characters into the input queue of a terminal other than the caller's controlling terminal;
- employ the obsolete nfsservctl(2) system call;
- employ the obsolete bdflush(2) system call;
- perform various privileged block-device ioctl(2) operations;
- perform various privileged filesystem ioctl(2) operations;
- perform privileged ioctl(2) operations on the /dev/random device (see random(4));
- install a seccomp(2) filter without first having to set the no_new_privs thread attribute;
- modify allow/deny rules for device control groups;
- employ the ptrace(2) PTRACE_SECCOMP_GET_FILTER operation to dump tracee's seccomp filters;
- employ the ptrace(2) PTRACE_SETOPTIONS operation to suspend the tracee's seccomp protections (i.e., the PTRACE_O_SUSPEND_SECCOMP flag);
- perform administrative operations on many device drivers.
- Modify autogroup nice values by writing to /proc/[pid]/autogroup (see sched(7)).