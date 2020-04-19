/* 
    This file is used to populate an array of files in the system 
    each file stored in the array will have permissions etc. We can
    use this to find SUID binaries and writeable config files etc
*/

#include "fs.h"
#include "utils.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>

#define CHUNK_SIZE 1

static void add_new_file(Total_Files *total_files, char *file_location);
static void get_file_extension(char *buf, char *f_name);

// Creates the structure for holding system file data
Total_Files *init_total_files()
{
    struct Total_Files *total_files_ptr = malloc(sizeof(Total_Files));
    if (total_files_ptr == NULL)
    {
        out_of_memory_err();
    }

    total_files_ptr->file_array = malloc(CHUNK_SIZE * sizeof(*total_files_ptr->file_array));
    if (total_files_ptr->file_array == NULL)
    {
        out_of_memory_err();
    }

    total_files_ptr->tot_files = 0;
    total_files_ptr->size = CHUNK_SIZE;
    return total_files_ptr;
}

void walk_file_system(char *entry_location, Total_Files *total_files)
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
                add_new_file(total_files, file_location);
            }
            if (entry->d_type & DT_DIR)
            {
                strcpy(file_location, entry_location);
                strcat(file_location, entry->d_name);
                strcat(file_location, "/");
                walk_file_system(file_location, total_files);
            }
        }
    }
    closedir(dir);
}

static void add_new_file(Total_Files *total_files, char *file_location)
{
    struct File_Info *new_file = (File_Info *)malloc(sizeof(File_Info));
    struct stat *stat_buf = malloc(sizeof(struct stat));

    if ((new_file == NULL) || (stat_buf == NULL))
    {
        out_of_memory_err();
    }

    strcpy(new_file->location, file_location);
    get_file_extension(new_file->extension, file_location);

    if (stat(file_location, stat_buf) == 0)
    {
        new_file->stat = stat_buf;
    }

    if (total_files->size == total_files->tot_files)
    {
        total_files->size *= 2;
        total_files->file_array = (struct File_Info **)realloc(total_files->file_array, total_files->size * sizeof(File_Info));

        if (total_files->file_array == NULL)
        {
            out_of_memory_err();
        }
    }
    total_files->file_array[total_files->tot_files] = new_file;
    total_files->tot_files++;
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

void print_all_file_info(Total_Files *total_files)
{
    for (int x = 0; x < total_files->tot_files; x++)
    {
        printf("%s\n", total_files->file_array[x]->location);
    }
}

bool has_global_write(File_Info *f)
{
    return f->stat->st_mode & S_IWOTH;
}

bool has_global_read(File_Info *f)
{
    return f->stat->st_mode & S_IROTH;
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