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

#define _GNU_SOURCE

#include "file_system.h"
#include "main.h"
#include "results.h"
#include "scan.h"
#include "elf_parsing.h"
#include "debug.h"
#include "utils.h"
#include "vector.h"

#include <stdio.h>
#include <err.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct Lib_Info
{
    Tag_Array *dt_needed;  // All the shared libaries files names
    Tag_Array *dt_rpath;   // High precedence
    Tag_Array *dt_runpath; // Low precedence
} Lib_Info;

int rpath_scan(File_Info *fi, All_Results *ar, Args *cmdline);
static int test_missing_shared_libaries(Lib_Info *lib_info, File_Info *fi, All_Results *ar, Args *cmdline);
static int test_injectable_shared_libaries(Lib_Info *lib_info);
static Lib_Info *get_lib_info(Elf_File *elf);
static void free_lib_info(Lib_Info *lib_info);
static bool search_dyn_path(char *search_for, Tag_Array *tag, char *origin);

/**
 * Given a file this function will determine if the file is an elf
 * if the file is an elf and can be parsed then we try and find the shared
 * objects dependendcies. We pass these dependenceies to other scans
 * @param fi The current files information 
 * @param ar The struct containing all of enumy's findings 
 * @param cmdline The struct containing runtime arguments 
 */
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
        DEBUG_PRINT("Failed to parse elf at location -> %s\n", fi->location);
        return findings;
    }

    elf_parse_dynamic_sections(elf);

    Lib_Info *lib_info = get_lib_info(elf);

    findings += test_injectable_shared_libaries(lib_info);
    findings += test_missing_shared_libaries(lib_info, fi, ar, cmdline);

    close_elf(elf, fi);
    free_lib_info(lib_info);

    return findings;
}

/**
 * Takes an Elf_File and then searches the dynamic section for 3 tags, DT_NEEDED
 * DT_RPATH and DT_RUNPATH. Creates a struct containing the results
 * @param elf pointer to an Elf_File that has allready been parsed
 * @return a pointer to results
 */
static Lib_Info *get_lib_info(Elf_File *elf)
{
    Lib_Info *lib_info = malloc(sizeof(Lib_Info));

    if (lib_info == NULL)
    {
        out_of_memory_err();
    }

    lib_info->dt_needed = search_dynamic_for_value(elf, DT_NEEDED);
    lib_info->dt_rpath = search_dynamic_for_value(elf, DT_RPATH);
    lib_info->dt_runpath = search_dynamic_for_value(elf, DT_RUNPATH);

    return lib_info;
}

static void free_lib_info(Lib_Info *lib_info)
{
    free(lib_info);
}

/**
 * Itterates through the required shared objects for an ELF File then tries to find them on the system. 
 * First the RPATH is searchedd
 * Second the standard files inside /usr/lib etc are searched 
 * Third the RUNPATH is searched 
 * @param lib_info struct containg vectors containing all of the shared object information parsed from .dynamic 
 * @param fi struct containing the elf files information
 * @param ar Linked list containg all issues found on the system
 * @param cmdline struct containing runtime arguments 
 * @return retuns the number of missing shared objects for the given elf file 
 */
static int test_missing_shared_libaries(Lib_Info *lib_info, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int findings = 0;
    int copy_loc;
    bool found = false;
    char search_loc[MAXSIZE];
    char current;
    char *origin;

    if (lib_info->dt_needed == NULL)
    {
        // Does not need any shared libs
        return findings;
    }

    for (int i = 0; i < lib_info->dt_needed[0].size; i++)
    {
        if (strcasestr(lib_info->dt_needed[0].tag_value, ".so") == NULL)
        {
            DEBUG_PRINT("Probably failed to parse DT_NEEDED at location %s with value -> '%s'\n", fi->location, lib_info->dt_needed[i].tag_value);
            continue;
        }

        origin = get_dir_name(fi->location);

        // check rpath
        if (search_dyn_path(lib_info->dt_needed[i].tag_value, lib_info->dt_rpath, origin))
        {
            free(origin);
            continue;
        }

        // Check normal shared objects in /usr/lib etc
        if (test_if_standard_shared_object(cmdline->valid_shared_libs, lib_info->dt_needed[i].tag_value))
        {
            free(origin);
            continue;
        }

        // check run_path
        if (search_dyn_path(lib_info->dt_needed[i].tag_value, lib_info->dt_runpath, origin))
        {
            free(origin);
            continue;
        }

        int id = 233;
        char name[MAXSIZE];
        Result *new_result = create_new_issue();
        snprintf(name, MAXSIZE, "Missing shared libary %s", lib_info->dt_needed[i].tag_value);
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        add_new_result_info(new_result, ar, cmdline);

        free(origin);
    }

    return findings;
}

/**
 * Itterates through the RPATH or RUNPATH tag array, searching for the value
 * will replace $ORIGIN with the full path to the base name of the executable
 * The tag array can contain multiple tag_values
 * @param search_for the shared object required by the executable
 * @param Tag_Array the parsed data from .dym section of the binary
 * @param origin what $ORIGIN will me replaced with (see man elf rpath)
 * @return true if shared object has been found
 */
static bool search_dyn_path(char *search_for, Tag_Array *tag, char *origin)
{
    char search_location[MAXSIZE];
    char *current_rpath;
    char current_character;
    int buf_copy_loc;

    if (tag == NULL)
    {
        return false;
    }

    // Itterate through each path tag found in binary
    for (int i = 0; i < tag[0].size; i++)
    {

        current_rpath = tag[i].tag_value;
        buf_copy_loc = 0;

        // Itterate through each character in a tag (tokenized with ":")
        for (int y = 0; y < strlen(current_rpath); i++)
        {
            current_character = current_rpath[y];
            if (current_character == ':')
            {
                search_location[buf_copy_loc + 1] == '\0';
                buf_copy_loc = 0;

                if (f())
                {
                    return true;
                }
            }
        }

        search_location[buf_copy_loc + 1] == '\0';
        if (f())
        {
            return true;
        }
    }
    return false;
}

static bool search_shared_lib_in_dir(char *lib_name, char *location, char *origin)
{
}

/**
 * strrep (String Replace). Replaces 'search' with 'replace' in 'base' and returns the new string.
 * You need to free the returned string in your code after using strrep.
 * @param base The string with the text.
 * @param search The text to find.
 * @param replace The replacement text.
 * @return The text updated wit the replacement.
 */
char *replace_origin(const char *base, const char *search, const char *replace)
{
    char *string;
    char *ptr;
    char *strrep;

    string = (char *)malloc(strlen(base) + 1);
    sprintf(string, "%s", base);
    if (!*search)
        return string;
    ptr = strtokk(string, search);
    strrep = malloc(strlen(ptr) + 1);
    memset(strrep, 0, strlen(ptr));
    while (ptr)
    {
        strrep = appendstr(strrep, ptr);
        ptr = strtokk(NULL, search);
        if (ptr)
            strrep = appendstr(strrep, replace);
    }
    free(string);
    return strrep;
}

static int test_injectable_shared_libaries(Lib_Info *lib_info)
{
    int findings = 0;
    return findings;
}