#pragma once

#include <stdbool.h>

typedef struct Args
{
    char save_location[1024];
    bool enabled_all_scans;
    bool enabled_quick_scans;
    bool enabled_ncurses;
} Args;