/*
    The job of this file is to try and identify files that could be 
    of intrest to an attacker without showing too many false positives
    Examples of these files are backupfiles, private keys, certificates,
    writable config files and coredump files. 
*/

#define _GNU_SOURCE

#include "main.h"
#include "results.h"
#include "utils.h"
#include "fs.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
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
static int check_for_writable_shared_object(File_Info *fi, All_Results *ar, Args *cmdline);
static double caclulate_file_entropy(char *file_location);
static int search_conf_for_pass(File_Info *fi, All_Results *ar, Args *cmdline);
static int search_line(unsigned char *line_start, unsigned char *line_end);

// Kicks of other scans
int intresting_files_scan(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int findings = 0;

    findings += extension_checker(fi, ar, cmdline);
    findings += file_name_checker(fi, ar, cmdline);
    // findings += parent_dir_checker(fi, ar, cmdline);
    return findings;
}

// Kicks off scans that require the file extensions to clasify the file
static int extension_checker(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int findings = 0;

    switch (fi->extension[0])
    {
    case 'a':
        if (strcmp(fi->extension, "aes") == 0)
            findings += (check_for_encryption_key(fi, ar, cmdline) == true) ? 1 : 0;
        break;
    case 'c':
        if (strcmp(fi->extension, "config") == 0)
            findings += search_conf_for_pass(fi, ar, cmdline);
        if (strcmp(fi->extension, "conf") == 0)
            findings += search_conf_for_pass(fi, ar, cmdline);
        break;
    case 'd':
        if (strcmp(fi->extension, "des") == 0)
            findings += (check_for_encryption_key(fi, ar, cmdline) == true) ? 1 : 0;
        break;
    case 'g':
        // .gxk
        break;
    case 'h':
        // .hdmp
        break;
    case 'j':
        // .jks
        break;
    case 'k':
        // .key
        if (strcmp(fi->extension, "key") == 0)
            findings += (check_for_encryption_key(fi, ar, cmdline) == true) ? 1 : 0;
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
            findings += (check_for_encryption_key(fi, ar, cmdline) == true) ? 1 : 0;
        if (strcmp(fi->extension, "passwords") == 0)
            findings += (check_for_encryption_key(fi, ar, cmdline) == true) ? 1 : 0;
        if (strcmp(fi->extension, "private") == 0)
            findings += (check_for_encryption_key(fi, ar, cmdline) == true) ? 1 : 0;
        if (strcmp(fi->extension, "pk") == 0)
            findings += (check_for_encryption_key(fi, ar, cmdline) == true) ? 1 : 0;
        break;
    case 'r':
        if (strcmp(fi->extension, "rsa") == 0)
            findings += (check_for_encryption_key(fi, ar, cmdline) == true) ? 1 : 0;
        break;
    case 's':
        // .secret
        // .sec
        // .sig
        // .sql
        // .sqlite
        if (strcmp(fi->extension, "secret") == 0)
            findings += (check_for_encryption_key(fi, ar, cmdline) == true) ? 1 : 0;
        if (strcmp(fi->extension, "so") == 0)
            findings += check_for_writable_shared_object(fi, ar, cmdline);
        break;
    case 'v':
        // .vpn
        // .openvpn
        break;
    }
    return findings;
}

// Kick of scans that require the file name to classify the file
static int file_name_checker(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int findings = 0;
    if (strcasestr(fi->name, "id_rsa") != NULL && strcmp(fi->extension, "pub") != 0)
    {
        if (check_for_encryption_key(fi, ar, cmdline))
        {
            findings++;
        }
    }
    if (strcasestr(fi->name, "id_dsa") != NULL && strcmp(fi->extension, "pub") != 0)
    {
        if (check_for_encryption_key(fi, ar, cmdline))
        {
            findings++;
        }
    }
    return findings;
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
        id = 46;
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
    double entropy = 0;

    f = fopen(file_location, "r");
    for (len = 0; !feof(f) && len < ENTROPY_SIZE; len++)
        str[len] = (unsigned char)fgetc(f);

    fclose(f);
    str[--len] = '\0';

    hist = (unsigned int *)calloc(len, sizeof(int));
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
        entropy -= (double)hist[i] / len * log2((double)hist[i] / len);
    }

    if (hist != NULL)
    {
        free(hist);
    }
    return entropy;
}

// Maps the entired file into memory
static int search_conf_for_pass(File_Info *fi, All_Results *ar, Args *cmdline)
{

    int fd;
    int findings = 0;
    unsigned char *f_data, *f_data_end;
    unsigned char *line_begin, *line_end;

    if (fi->stat->st_size == 0 || (fd = open(fi->location, O_RDONLY) == -1))
    {
        return findings;
    }

    f_data = mmap(0, fi->stat->st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (f_data == MAP_FAILED)
    {
        close(fd);
        return findings;
    }

    f_data_end = f_data + fi->stat->st_size;
    line_begin = line_end = f_data;

    while (true)
    {
        // Itterate until we find a new line or EOF
        while ((line_end < f_data_end) && ((*line_end != '\n') || (*line_end != '\r') || (*line_end != 0x0a)))
        {
            if (line_end - line_begin >= 3)
            {
                if (
                    ((unsigned char)*line_end == 0xe2) &&
                    ((unsigned char)*line_end - 1 == 0x90) &&
                    ((unsigned char)*line_end - 2 == 0xa4))
                {
                    break; // utf8 new line
                }
            }
            line_end++;
        }
        if (search_line(line_begin, line_end))
        {
            int id = 47;
            char *name = "Config could contain passwords";
            Result *new_result = create_new_issue();
            set_id_and_desc(id, new_result);
            set_issue_location(fi->location, new_result);
            set_issue_name(name, new_result);
            add_new_result_info(new_result, ar, cmdline);
            findings++;
            break;
        }
        if (line_end == f_data_end)
        {
            break;
        }
        else
        {
            line_end++;
            line_begin = line_end;
        }
    }

    close(fd);
    munmap((void *)f_data, fi->stat->st_size);
    return findings;
}

static int search_line(unsigned char *line_start, unsigned char *line_end)
{
    unsigned char *buffer = malloc((2 + (line_end - line_start)) * sizeof(unsigned char));
    int loc = 0;
    int findings = 0;
    bool in_whitespace = true;
    bool first_non_white = false;
    bool equals_found = false;

    if (buffer == NULL)
    {
        return 0;
    }
    for (unsigned char *i = line_start; i <= line_end; i++)
    {
        if (in_whitespace && (*i == ' ' || *i == '\t'))
        {
            first_non_white = true;
        }
        else
        {
            if (first_non_white && *i == '#')
            {
                // line is commented
                free(buffer);
                return findings;
            }
            first_non_white = false;
            in_whitespace = false;
            if (*i == '=')
            {
                equals_found = true;
            }
        }
        buffer[loc] = *i;
        loc++;
    }
    buffer[loc++] = '\0';

    if (equals_found && strcasestr((char *)buffer, "password=") != NULL)
    {
        findings++;
    }
    if (equals_found && strcasestr((char *)buffer, "private_key=") != NULL)
    {
        findings++;
    }
    if (equals_found && strcasestr((char *)buffer, "private-key=") != NULL)
    {
        findings++;
    }
    if (equals_found && strcasestr((char *)buffer, "PrivateKey=") != NULL)
    {
        findings++;
    }
    if (equals_found && strcasestr((char *)buffer, "Private_Key=") != NULL)
    {
        findings++;
    }
    if (equals_found && strcasestr((char *)buffer, "password ") != NULL)
    {
        findings++;
    }
    if (equals_found && strcasestr((char *)buffer, "private_key ") != NULL)
    {
        findings++;
    }
    if (equals_found && strcasestr((char *)buffer, "private-key ") != NULL)
    {
        findings++;
    }
    if (equals_found && strcasestr((char *)buffer, "PrivateKey ") != NULL)
    {
        findings++;
    }
    if (equals_found && strcasestr((char *)buffer, "Private_Key ") != NULL)
    {
        findings++;
    }

    free(buffer);
    return findings;
}

static int check_for_writable_shared_object(File_Info *fi, All_Results *ar, Args *cmdline)
{
    if (has_global_write(fi))
    {
        char *name = "World writable shared object found";
        Result *new_result = create_new_issue();
        set_id_and_desc(48, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return 1;
    }
    return 0;
}