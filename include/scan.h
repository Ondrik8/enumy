#pragma once

#include "results.h"
#include "gui.h"
#include "fs.h"
#include "main.h"

extern char *KNOW_GOOD_SUID[];

void start_scan(Ncurses_Layout *layout, All_Results *results, Args *args);

int suid_bit_scan(File_Info *fi, All_Results *ar, Args *cmdline);
int guid_bit_scan(File_Info *fi, All_Results *ar, Args *cmdline);
int capabilities_scan(File_Info *fi, All_Results *ar, Args *cmdline);
int intresting_files_scan(File_Info *fi, All_Results *ar, Args *cmdline);
int core_dump_scan(File_Info *fi, All_Results *ar, Args *cmdline);