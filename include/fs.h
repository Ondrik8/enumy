#pragma once

#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <unistd.h>

#include "results.h"

#define MAX_FILE_SIZE 1024
#define MAX_EXTENSION_SIZE 16

typedef struct File_Info
{
    char location[MAX_FILE_SIZE];
    char name[MAX_FILE_SIZE];
    char extension[MAX_EXTENSION_SIZE];
    struct stat *stat;
} File_Info;

void walk_file_system(char *entry_location, All_Results *all_results, Args *cmdline);

bool has_global_write(File_Info *f);
bool has_global_read(File_Info *f);
bool has_global_execute(File_Info *f);
bool has_group_write(File_Info *f);
bool has_group_execute(File_Info *f);
bool has_executable(File_Info *f);
bool has_suid(File_Info *f);
bool has_guid(File_Info *f);
bool has_extension(File_Info *f, char *extension);
bool can_read(File_Info *fi);

int get_number_of_files_scanned();