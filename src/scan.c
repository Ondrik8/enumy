#include "results.h"
#include "main.h"
#include "gui.h"
#include "fs.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

void start_scan(Ncurses_Layout *layout, All_Results *all_results, Args args)
{
    bool ncurses_enabled = args.enabled_ncurses;
    Total_Files *total_files = init_total_files();
    if (total_files == NULL)
    {
        out_of_memory_err();
    }
    walk_file_system("/etc/", total_files);
    print_all_file_info(total_files);
}

// void add_info(All_Results *all_results)
// {
//     Result *new_issue = create_new_issue();

//     set_id(110, new_issue);
//     set_issue_description("EXAMPLE issue", new_issue);
//     set_issue_location("/tmp/TEST", new_issue);
//     set_issue_name("EXAMPLE", new_issue);
//     add_new_result_info(new_issue, all_results);
// }