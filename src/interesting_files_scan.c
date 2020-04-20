/*
    The job of this file is to try and identify files that could be 
    of intrest to an attacker without showing too many false positives
    Examples of these files are backupfiles, private keys, certificates,
    writable config files and coredump files. 
*/

#include "main.h"
#include "results.h"
#include "utils.h"
#include "fs.h"

int intresting_files_scan(File_Info *fi, All_Results *ar, Args *cmdline);
static int extension_checker(File_Info *fi, All_Results *ar, Args *cmdline);
static int file_name_checker(File_Info *fi, All_Results *ar, Args *cmdline);

// Kicks of other scans
int intresting_files_scan(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int findings = 0;

    findings += extension_checker(fi, ar, cmdline);
    findings += file_name_checker(fi, ar, cmdline);
    findings += parent_dir_checker(fi, ar, cmdline);
}

// Kicks off scans that require the file extensions to clasify the file
static int extension_checker(File_Info *fi, All_Results *ar, Args *cmdline)
{
    switch (fi->extension[0])
    {
    case 'a':
        // .aes
        break;
    case 'b':
        // .bak
        // .backup
        // .bk
        break;
    case 'c':
        // .cer
        // .chk https://en.wikipedia.org/wiki/CHKDSK
        // .crack
        // .crk
        // .conf
        // .config
        // .crt
        break;
    case 'd':
        // .data
        // .dat
        // .debug
        // .der
        // .des
        // .dump
        // .coredump
        // .core
        break;
    case 'g':
        // .gxk
        break;
    case 'h':
        // .hdmp
        break;
    case 'i':
        // .ida
        break;
    case 'j':
        // .jks
        break;
    case 'k':
        // .key
        break;
    case 'm':
        // .mbr
        // .mmf
        // .msd
        // .map
        // .mysql
        break;
    case 'o':
        // .old
        // .afx
        break;
    case 'p':
        // .ple
        // .pwl
        // .pot
        // .password
        // .private
        // .pk
        // .pgp
        break;
    case 'r':
        // .rzk
        // .rzx
        break;
    case 's':
        // .secret
        // .sec
        // .sig
        // .sql
        // .sqlite
        break;
    case 'v':
        // .vpn
        // .openvpn
        break;
    }
}

// Kick of scans that require the file name to classify the file
static int file_name_checker(File_Info *fi, All_Results *ar, Args *cmdline)
{
}

// Kick of the scans that require the  parent directory to identify the file
static int parent_dir_checker(File_Info *fi, All_Results *ar, Args *cmdline)
{
}