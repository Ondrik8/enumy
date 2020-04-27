/*
    This scan will parse elf file and then look in the .dynamic section of the binary 
    for the following tags.

    DT_RPATH    String table offset to library search path (deprecated)
    DT_RUNPATH  String table offset to library search path
    DT_NEEDED   String table offset to name of a needed library

    the run paths (DT_RPATH and DT_RUNPATH) are used to find libaries needed similar to 
    the $PATH variable for finding executables. The precedence is the following: 

    1. DT_RPATH
    2. LD_LIBRARY_PATH
    3. DT_RUNPATH 

    If the file is determined to be an elf file we first find out what shared libaries 
    are required by itterating through the .dynamic section looking for the DT_NEEDED 
    tag. This points to the names of the shared libaries required to execute. Next we
    search for the shared libary if we find it's missing or a search location with higher
    precedence is does not contain the shared libary and this location is writable then
    we will report this as an issue. 

    This scan is slow because we have to parse millions of files so it's only enabled in 
    the full scan option

    Note DT_RPATH and DT_RUNPATH can be tokenized with semicolons e.g
    DT_RUNPATH:-> $ORIGIN/../../lib

    The $ORIGIN value means replace with the binaries current directory 
*/

#include "file_system.h"
#include "main.h"
#include "results.h"
#include "scan.h"
#include "elf_parsing.h"

#include <stdio.h>
#include <err.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>

typedef struct Lib_Info
{
    Tag_Array *dt_needed;  // All the shared libaries files names
    Tag_Array *dt_rpath;   // High precedence
    Tag_Array *dt_runpath; // Low precedence
} Lib_Info;

int rpath_scan(File_Info *fi, All_Results *ar, Args *cmdline);
static int test_missing_shared_libaries(Lib_Info *lib_info);
static int test_injectable_shared_libaries(Lib_Info *lib_info);
static Lib_Info *get_lib_info(Elf_File *elf);
static void free_lib_info(Lib_Info *lib_info);

int rpath_scan(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int findings = 0;

    if (cmdline->enabled_full_scans != true)
    {
        return findings;
    }

    int arch = has_elf_magic_bytes(fi);
    if (
        (arch == 0) ||
        (arch == 1 && sizeof(char *) != 4) ||
        (arch == 2 && sizeof(char *) != 8))
    {
        return findings;
    }

    Elf_File *elf = parse_elf(fi);
    if (elf == NULL)
    {
        return findings;
    }

    elf_parse_dynamic_sections(elf);

    Lib_Info *lib_info = get_lib_info(elf);

    findings += test_injectable_shared_libaries(lib_info);
    findings += test_missing_shared_libaries(lib_info);

    close_elf(elf, fi);
    free_lib_info(lib_info);

    return findings;
}

static Lib_Info *get_lib_info(Elf_File *elf)
{
    Lib_Info *lib_info = malloc(sizeof(Lib_Info));

    lib_info->dt_needed = search_dynamic_for_value(elf, DT_NEEDED);
    lib_info->dt_rpath = search_dynamic_for_value(elf, DT_RPATH);
    lib_info->dt_runpath = search_dynamic_for_value(elf, DT_RUNPATH);

    return lib_info;
}

static void free_lib_info(Lib_Info *lib_info)
{
    free(lib_info);
}

static int test_missing_shared_libaries(Lib_Info *lib_info)
{
    int findings = 0;

    if (lib_info->dt_needed == NULL)
    {
        // Does not need any shared libs
        return findings;
    }

    // printf("DT_NEEDED:");
    // for (int i = 0; i < lib_info->dt_needed[0].size; i++)
    // {
    //     printf("-> %s", lib_info->dt_needed[i].tag_value);
    // }

    // if (lib_info->dt_runpath != NULL)
    // {
    //     printf("\n");
    //     printf("DT_RUNPATH:");
    //     for (int i = 0; i < lib_info->dt_runpath[0].size; i++)
    //     {
    //         printf("-> %s", lib_info->dt_runpath[i].tag_value);
    //     }
    // }
    // if (lib_info->dt_rpath != NULL)
    // {
    //     printf("\n");
    //     printf("DT_RPATH:");
    //     for (int i = 0; i < lib_info->dt_rpath[0].size; i++)
    //     {
    //         printf("-> %s", lib_info->dt_rpath[i].tag_value);
    //     }
    // }
    // printf("\n");
    // printf("---------------------------------------------------\n");
    return findings;
}

static int test_injectable_shared_libaries(Lib_Info *lib_info)
{
    int findings = 0;
    return findings;
}