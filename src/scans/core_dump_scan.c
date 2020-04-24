/* 
    This file is meant to try and find core dump files
*/

#define _GNU_SOURCE

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

int core_dump_scan(File_Info *fi, All_Results *ar, Args *cmdline);

int core_dump_scan(File_Info *fi, All_Results *ar, Args *cmdline)
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

    // Test if the elf file is a core dump
    if ((unsigned short)elf->header->e_type == (unsigned short)ET_CORE)
    {
        findings++;

        if (has_global_read(fi))
        {
            char *name = "Found a world readable core dump file";
            Result *new_result = create_new_issue();
            set_id_and_desc(43, new_result);
            set_issue_location(fi->location, new_result);
            set_issue_name(name, new_result);
            add_new_result_high(new_result, ar, cmdline);
        }
        if (fi->stat->st_uid != 0)
        {
            char *name = "Found a core dump, owner is not root";
            Result *new_result = create_new_issue();
            set_id_and_desc(44, new_result);
            set_issue_location(fi->location, new_result);
            set_issue_name(name, new_result);
            add_new_result_low(new_result, ar, cmdline);
        }
        if (can_read(fi))
        {
            char *name = "Found a readable core dump file";
            Result *new_result = create_new_issue();
            set_id_and_desc(44, new_result);
            set_issue_location(fi->location, new_result);
            set_issue_name(name, new_result);
            add_new_result_high(new_result, ar, cmdline);
        }
    }

    return findings;
}
