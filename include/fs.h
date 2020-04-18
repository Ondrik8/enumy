#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <unistd.h>

#define MAX_FILE_SIZE 1024
#define MAX_EXTENSION_SIZE 16

typedef struct File_Info
{
    char location[MAX_FILE_SIZE];
    char extension[MAX_EXTENSION_SIZE];
    struct stat *stat;
} File_Info;

typedef struct Total_Files
{
    struct File_Info **file_array;
    int tot_files;
    int size;
} Total_Files;

void walk_file_system(char *entry_location, Total_Files *total_files);
Total_Files *init_total_files();
void print_all_file_info(Total_Files *total_files);