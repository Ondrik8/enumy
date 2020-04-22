/* 
    This file is meant to try and find core dump files
*/

#define _GNU_SOURCE

#include "fs.h"
#include "main.h"
#include "results.h"
#include "scan.h"

#include <stdio.h>
#include <err.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>

#define ARM 0
#define X64 1
#define X86 2

#ifdef __amd64
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Sym Elf_Sym;
const int ARCH = X64;
#endif

#ifdef __i386
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Shdr Elf_Shdr;
typedef Elf32_Sym Elf_Sym;
const int ARCH = X86;
#endif

#ifdef __ARM
const int ARCH = ARM;
#endif

typedef struct ElfFile
{
    const void *address;
    Elf_Ehdr *header;
} ElfFile;

typedef struct ELF_FILE
{
    const void *address;

} ELF_FILE;

int core_dump_scan(File_Info *fi, All_Results *ar, Args *cmdline);
static bool parse_elf_headers(File_Info *fi);
static inline Elf_Ehdr *get_elf_header(const void *map_start);
static bool test_magic_number(File_Info *fi);

int core_dump_scan(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int findings = 0;

    if (strcasestr(fi->name, "core") == NULL || ARCH == ARM)
    {
        return findings;
    }

    if (test_magic_number(fi) == false)
    {
        return findings;
    }

    if (parse_elf_headers(fi))
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

static bool parse_elf_headers(File_Info *fi)
{
    int fd;
    bool ret;
    ElfFile *file = NULL;

    if (fi->stat->st_size == 0)
    {
        return false;
    }
    fd = open(fi->location, O_RDONLY);
    if (fd < 0)
    {
        return false;
    }

    file = malloc(sizeof(ElfFile));
    if (file == NULL)
    {
        close(fd);
        return false;
    }

    file->address = mmap(NULL, fi->stat->st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file->address == MAP_FAILED)
    {
        close(fd);
        free(file);
        return false;
    }
    if (file->address == NULL)
    {
        free(file);
        close(fd);
        return false;
    }
    file->header = get_elf_header(file->address);

    if ((unsigned short)file->header->e_type == (unsigned short)ET_CORE)
    {
        munmap((void *)file->address, fi->stat->st_size);
        free(file);
        close(fd);
        return true;
    }
    munmap((void *)file->address, fi->stat->st_size);
    free(file);
    close(fd);
    return false;
}

static inline Elf_Ehdr *get_elf_header(const void *map_start)
{
    return (Elf_Ehdr *)map_start;
}

static bool test_magic_number(File_Info *fi)
{
    const int magic_size = 4;

    unsigned char values[4] = {0x00, 0x00, 0x00, 0x00};
    unsigned char little_endian[4] = {0x45, 0x7f, 0x46, 0x4c};
    unsigned char big_endian[4] = {0x7f, 0x45, 0x4c, 0x46};

    FILE *fp;
    int i;
    bool little_found, big_found;

    little_found = big_found = true;

    fp = fopen(fi->location, "rb");
    if (fp == NULL)
    {
        return false;
    }

    fread(values, 1, magic_size, fp);
    fclose(fp);

    // Little egg
    for (int i = 0; i < magic_size; i++)
    {
        if (little_endian[i] != values[i])
        {
            little_found = false;
            break;
        }
    }
    // Big egg
    for (int i = 0; i < magic_size; i++)
    {
        if (big_endian[i] != values[i])
        {
            big_found = false;
            break;
        }
    }
    return (little_found || big_found);
}