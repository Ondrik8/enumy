/* 
    This file is used to populate an array of files in the system 
    each file stored in the array will have permissions etc. We can
    use this to find SUID binaries and writeable config files etc
*/

#include "file_system.h"
#include "utils.h"
#include "results.h"
#include "scan.h"
#include "thpool.h"
#include "debug.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <ctype.h>

pthread_mutex_t FILES_SCANNED_MUTEX;
int FILES_SCANNED = 0;

typedef struct Thread_Pool_Args
{
    char file_location[MAXSIZE];
    char file_name[MAXSIZE];
    All_Results *all_results;
    Args *cmdline;
} Thread_Pool_Args;

static void get_file_extension(char *buf, char *f_name);
static void scan_file_for_issues(Thread_Pool_Args *thread_pool_args);
static void add_file_to_thread_pool(char *file_location, char *file_name, All_Results *all_results, Args *cmdline);

int get_number_of_files_scanned()
{
    return FILES_SCANNED;
}

void walk_file_system(char *entry_location, All_Results *all_results, Args *cmdline)
{
    DIR *dir;
    struct dirent *entry;
    char file_location[MAXSIZE];

    file_location[0] = '\0';

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
                strncpy(file_location, entry_location, MAXSIZE - 1);
                strcat(file_location, entry->d_name);
                add_file_to_thread_pool(file_location, entry->d_name, all_results, cmdline);
            }
            if (entry->d_type & DT_DIR)
            {
                strncpy(file_location, entry_location, MAXSIZE - 1);
                strcat(file_location, entry->d_name);
                if (strcmp(cmdline->ignore_scan_dir, file_location) == 0)
                {
                    continue;
                }
                if (strcmp("/proc", file_location) == 0)
                {
                    continue;
                }
                strcat(file_location, "/");
                if (strcmp(cmdline->ignore_scan_dir, file_location) == 0)
                {
                    continue;
                }
                walk_file_system(file_location, all_results, cmdline);
            }
        }
    }
    closedir(dir);
}

static void add_file_to_thread_pool(char *file_location, char *file_name, All_Results *all_results, Args *cmdline)
{
    Thread_Pool_Args *args = malloc(sizeof(Thread_Pool_Args));

    if (args == NULL)
    {
        out_of_memory_err();
    }

    strncpy(args->file_location, file_location, MAXSIZE - 1);
    strncpy(args->file_name, file_name, MAXSIZE - 1);
    args->all_results = all_results;
    args->cmdline = cmdline;

    while (thpool_jobqueue_length(cmdline->fs_threadpool) > cmdline->fs_threads * 2)
    {
        usleep(20);
    }

    thpool_add_work(cmdline->fs_threadpool, (void *)scan_file_for_issues, (void *)args);
}

static void scan_file_for_issues(Thread_Pool_Args *thread_pool_args)
{
    struct File_Info *new_file = (File_Info *)malloc(sizeof(File_Info));
    struct stat *stat_buf = malloc(sizeof(struct stat));
    int findings = 0;

    if (stat_buf == NULL)
    {
        free(thread_pool_args);
        out_of_memory_err();
    }
    if (new_file == NULL)
    {
        free(thread_pool_args);
        out_of_memory_err();
    }

    strncpy(new_file->location, thread_pool_args->file_location, sizeof(new_file->location) - 1);
    strncpy(new_file->name, thread_pool_args->file_name, sizeof(new_file->location) - 1);
    get_file_extension(new_file->extension, thread_pool_args->file_location);

    if (lstat(thread_pool_args->file_location, stat_buf) == 0)
    {
        new_file->stat = stat_buf;
    }
    else
    {
        DEBUG_PRINT("lstat failed to get information for -> %s\n", new_file->location);
        free(stat_buf);
        free(new_file);
        free(thread_pool_args);
        return;
    }

    // Ignore symlinks as following them to special files will break scans
    if (S_ISLNK(stat_buf->st_mode))
    {
        free(stat_buf);
        free(new_file);
        free(thread_pool_args);
        return;
    }

    // printf("Scanning file -> %s\n", thread_pool_args->file_location);
    findings += suid_bit_scan(new_file, thread_pool_args->all_results, thread_pool_args->cmdline);
    findings += guid_bit_scan(new_file, thread_pool_args->all_results, thread_pool_args->cmdline);
    findings += capabilities_scan(new_file, thread_pool_args->all_results, thread_pool_args->cmdline);
    findings += intresting_files_scan(new_file, thread_pool_args->all_results, thread_pool_args->cmdline);
    findings += core_dump_scan(new_file, thread_pool_args->all_results, thread_pool_args->cmdline);
    findings += rpath_scan(new_file, thread_pool_args->all_results, thread_pool_args->cmdline);

    free(stat_buf);
    free(new_file);
    free(thread_pool_args);

    pthread_mutex_lock(&FILES_SCANNED_MUTEX);
    FILES_SCANNED++;
    pthread_mutex_unlock(&FILES_SCANNED_MUTEX);
}

// Get the file extension the "." is not saved and an extension
// abc.tar.gz would return .gz not .tar.gz
// The extensions is saved in lowercase
static void get_file_extension(char *buf, char *f_name)
{
    int size = strlen(f_name);
    int i = 0;
    char current;

    if (size > MAX_FILE_SIZE - 1)
    {
        DEBUG_PRINT("Found a file with an extension bigger than buffer size -> %s\n", f_name);
        return;
    }

    for (int x = size; x >= 0; x--)
    {
        current = f_name[x];
        if (current == '.' && x != 0 && size - x < MAX_EXTENSION_SIZE)
        {
            for (int y = x + 1; y <= size; y++)
            {
                buf[i] = (char)tolower(f_name[y]);
                i++;
            }
            buf[i] = '\0';
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

bool can_read(File_Info *fi)
{
    return access(fi->location, R_OK) == 0;
}