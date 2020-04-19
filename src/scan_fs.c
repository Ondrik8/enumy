/*
    This file performs scans relating to permissions such as finding 
    writeable config files and SUID binaries
*/

#include "results.h"
#include "fs.h"

void find_suid_binaries(All_Results *all_results, Total_Files *total_files);
void find_guid_binaries(All_Results *all_results, Total_Files *total_files);
void find_world_writeable_files(All_Results *all_results, Total_Files *total_files);
void find_world_writeable_config_files(All_Results *all_results, Total_Files *total_files);
void find_world_writable_shared_objects(All_Results *all_Results, Total_Files *total_files);
void find_world_writable_protected_files(All_Results *all_Results, Total_Files *total_files);