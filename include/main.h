#pragma once

#include <stdbool.h>

#define MAXSIZE 2048

typedef struct Args
{
    char save_location[MAXSIZE + 1];
    char ignore_scan_dir[MAXSIZE + 1];
    bool enabled_all_scans;
    bool enabled_quick_scans;
    bool enabled_ncurses;
} Args;