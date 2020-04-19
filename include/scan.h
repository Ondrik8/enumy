#pragma once

#include "results.h"
#include "gui.h"
#include "fs.h"
#include "main.h"

extern char *KNOW_GOOD_SUID[];

void start_scan(Ncurses_Layout *layout, All_Results *results, Args args);

bool suid_bit_scan(File_Info *fi, All_Results *ar, Args *cmdline);
bool guid_bit_scan(File_Info *fi, All_Results *ar, Args *cmdline);