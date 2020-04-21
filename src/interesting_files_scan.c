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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#define ENTROPY_SIZE 5000

int intresting_files_scan(File_Info *fi, All_Results *ar, Args *cmdline);
static int extension_checker(File_Info *fi, All_Results *ar, Args *cmdline);
static int file_name_checker(File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_for_encryption_key(File_Info *fi, All_Results *ar, Args *cmdline);
static double caclulate_file_entropy(char *file_location);

// Kicks of other scans
int intresting_files_scan(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int findings = 0;

    findings += extension_checker(fi, ar, cmdline);
    // findings += file_name_checker(fi, ar, cmdline);
    // findings += parent_dir_checker(fi, ar, cmdline);
}

// Kicks off scans that require the file extensions to clasify the file
static int extension_checker(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int findings = 0;

    switch (fi->extension[0])
    {
    case 'a':
        if (strcmp(fi->extension, "aes") == 0)
            findings = (check_for_encryption_key(fi, ar, cmdline) == true) ? findings++ : findings;
        break;
    case 'c':
        break;
    case 'd':
        // .coredump
        // .core
        if (strcmp(fi->extension, "des") == 0)
            findings = (check_for_encryption_key(fi, ar, cmdline) == true) ? findings++ : findings;
        if (strcmp(fi->extension, "der") == 0)
            findings = (check_for_encryption_key(fi, ar, cmdline) == true) ? findings++ : findings;
        break;
    case 'g':
        // .gxk
        break;
    case 'h':
        // .hdmp
        break;
    case 'i':
        // .ida
        if (strcmp(fi->extension, "ida") == 0)
            findings = (check_for_encryption_key(fi, ar, cmdline) == true) ? findings++ : findings;
        break;
    case 'j':
        // .jks
        break;
    case 'k':
        // .key
        if (strcmp(fi->extension, "key") == 0)
            findings = (check_for_encryption_key(fi, ar, cmdline) == true) ? findings++ : findings;
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
        if (strcmp(fi->extension, "password") == 0)
            findings = (check_for_encryption_key(fi, ar, cmdline) == true) ? findings++ : findings;
        if (strcmp(fi->extension, "private") == 0)
            findings = (check_for_encryption_key(fi, ar, cmdline) == true) ? findings++ : findings;
        if (strcmp(fi->extension, "pk") == 0)
            findings = (check_for_encryption_key(fi, ar, cmdline) == true) ? findings++ : findings;
        if (strcmp(fi->extension, "pgp") == 0)
            findings = (check_for_encryption_key(fi, ar, cmdline) == true) ? findings++ : findings;
        break;
    case 'r':
        if (strcmp(fi->extension, "rsa") == 0)
            findings = (check_for_encryption_key(fi, ar, cmdline) == true) ? findings++ : findings;
        break;
    case 's':
        // .secret
        // .sec
        // .sig
        // .sql
        // .sqlite
        if (strcmp(fi->extension, "secret") == 0)
            findings = (check_for_encryption_key(fi, ar, cmdline) == true) ? findings++ : findings;
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

// If the file has the string private key etc inside of it or the file has low entropy
// then we will report this ass being true
static bool check_for_encryption_key(File_Info *fi, All_Results *ar, Args *cmdline)
{
    float entropy;
    int id;

    if (strstr(fi->location, "/test/") || strstr(fi->location, "/tests/") || strstr(fi->location, "/testing/"))
    {
        return false;
    }

    if (strstr(fi->location, "integration") && strstr(fi->location, "test"))
    {
        return false;
    }
    if (fi->stat->st_size > 100000 || fi->stat->st_size < 100)
    {
        // Data probably too big to be a key
        return false;
    }

    if (access(fi->location, R_OK) != 0)
    {
    // Log issuse as info
    NONREADABLE:
        id = 43;
        char *name = "None readable potentianal encryption key";
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        add_new_result_info(new_result, ar, cmdline);
        return true;
    }

    entropy = caclulate_file_entropy(fi->location);
    if (entropy > 7.0 || entropy == -1)
    {
        // Not sure if we care about reporting encrypted data
        return false;
    }

    if (getuid() == 0 && fi->stat->st_uid == 0)
    {
        goto NONREADABLE;
    }

    id = 45;
    char *name = "Heuristic identified file as private key";
    Result *new_result = create_new_issue();
    set_id_and_desc(id, new_result);
    set_issue_location(fi->location, new_result);
    set_issue_name(name, new_result);
    add_new_result_high(new_result, ar, cmdline);
    return true;
}

// This function is used to try and determine if a file such as x.rsa is the key
// or the file is encrypted data. Key's should have low entropy and good encryption
// should be indistingushable from random data. Note that this only works if the key encoded
static double caclulate_file_entropy(char *file_location)
{
    char str[ENTROPY_SIZE];
    unsigned char current_pos;
    unsigned int len, *hist, histlen, i;
    FILE *f;
    int wherechar[256];
    double H;
    H = 0;

    f = fopen(file_location, "r");
    for (len = 0; !feof(f) && len < ENTROPY_SIZE; len++)
        str[len] = (unsigned char)fgetc(f);

    fclose(f);
    str[--len] = '\0';

    hist = (int *)calloc(len, sizeof(int));
    if (hist == NULL)
    {
        return -1;
    }

    // Create histogram
    histlen = 0;
    for (i = 0; i < 256; i++)
        wherechar[i] = 0;

    for (i = 0; i < len; i++)
    {
        current_pos = str[i];
        if (wherechar[(int)current_pos] == 0)
        {
            wherechar[current_pos] = histlen;
            histlen++;
        }
        hist[wherechar[(unsigned char)str[i]]]++;
    }

    // Calculate entropy
    for (i = 0; i < histlen; i++)
    {
        H -= (double)hist[i] / len * log2((double)hist[i] / len);
    }

    if (hist != NULL)
    {
        free(hist);
    }
    return H;
}