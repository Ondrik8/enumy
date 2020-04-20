/* 
    This file is used to populate an array of files in the system 
    each file stored in the array will have permissions etc. We can
    use this to find SUID binaries and writeable config files etc
*/

#include "fs.h"
#include "utils.h"
#include "results.h"
#include "scan.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>

static void get_file_extension(char *buf, char *f_name);
static void scan_file_for_issues(char *file_location, char *file_name, All_Results *all_results, Args *cmdline);

void walk_file_system(char *entry_location, All_Results *all_results, Args *cmdline)
{
    DIR *dir;
    struct dirent *entry;
    char file_location[MAX_FILE_SIZE];

    dir = opendir(entry_location);

    if (dir == NULL)
    {
        return;
    }

    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
        {

            if (entry->d_type & DT_REG)
            {
                strcpy(file_location, entry_location);
                strcat(file_location, entry->d_name);
                scan_file_for_issues(file_location, entry->d_name, all_results, cmdline);
            }
            if (entry->d_type & DT_DIR)
            {
                strcpy(file_location, entry_location);
                strcat(file_location, entry->d_name);
                strcat(file_location, "/");
                walk_file_system(file_location, all_results, cmdline);
            }
        }
    }
    closedir(dir);
}

static void scan_file_for_issues(char *file_location, char *file_name, All_Results *all_results, Args *cmdline)
{
    struct File_Info *new_file = (File_Info *)malloc(sizeof(File_Info));
    struct stat *stat_buf = malloc(sizeof(struct stat));
    int findings = 0;

    if ((new_file == NULL) || (stat_buf == NULL))
    {
        out_of_memory_err();
    }

    strcpy(new_file->location, file_location);
    strcpy(new_file->name, file_name);
    get_file_extension(new_file->extension, file_location);

    if (lstat(file_location, stat_buf) == 0)
    {
        new_file->stat = stat_buf;
    }
    else
    {
        return;
    }

    findings += suid_bit_scan(new_file, all_results, cmdline);
    findings += guid_bit_scan(new_file, all_results, cmdline);
    findings += capabilities_scan(new_file, all_results, cmdline);

    if (findings > 1)
    {
        printf("\n");
    }
}

static void get_file_extension(char *buf, char *f_name)
{
    int size = strlen(f_name);
    int i = 0;
    char current;

    if (size > MAX_FILE_SIZE)
    {
        return;
    }

    for (int x = size; x >= 0; x--)
    {
        current = f_name[x];
        if (current == '.' && x != 0 && size - x < MAX_EXTENSION_SIZE)
        {
            for (int y = x + 1; y <= size; y++)
            {
                buf[i] = f_name[y];
                i++;
            }
            return;
        }
    }
    buf[0] = '\0';
}

bool has_global_read(File_Info *f)
{
    return f->stat->st_mode & S_IROTH;
}

bool has_global_write(File_Info *f)
{
    return f->stat->st_mode & S_IWOTH;
}

bool has_global_execute(File_Info *f)
{
    return f->stat->st_mode & S_IXOTH;
}

bool has_group_execute(File_Info *f)
{
    return f->stat->st_mode & S_IXGRP;
}

bool has_group_write(File_Info *f)
{
    return f->stat->st_mode & S_IWGRP;
}

bool has_suid(File_Info *f)
{
    return f->stat->st_mode & S_ISUID;
}

bool has_guid(File_Info *f)
{
    return f->stat->st_mode & S_ISGID;
}

bool has_extension(File_Info *f, char *extension)
{
    return strcmp(f->extension, extension);
}

bool has_executable(File_Info *f)
{
    return (has_group_execute(f) || has_global_execute(f));
}