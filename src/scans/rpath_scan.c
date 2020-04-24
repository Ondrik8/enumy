/*
    This scan will parse elf file and then look in the .dynamic section of the binary 
    for the following tags.

    DT_RPATH    String table offset to library search path (deprecated)
    DT_RUNPATH  String table offset to library search path
    DT_NEEDED   String table offset to name of a needed library

    the run paths (DT_RPATH and DT_RUNPATH) are used to find libaries needed similar to 
    the $PATH variable for finding executables. The precedence is the following: 

    1. DR_RPATH
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
*/

#include "fs.h"
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

int rpath_scan(File_Info *fi, All_Results *ar, Args *cmdline);
static int test_missing_shared_libaries(Elf_File *elf);
static int test_injectable_shared_libaries(Elf_File *elf);

int rpath_scan(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int findings = 0;

    if (cmdline->enabled_full_scans != true)
    {
        return findings;
    }

    if (strcasestr(fi->name, "core") != NULL)
    {
        return findings;
    }
}

static int test_missing_shared_libaries(Elf_File *elf)
{
}

static int test_injectable_shared_libaries(Elf_File *elf)
{
}