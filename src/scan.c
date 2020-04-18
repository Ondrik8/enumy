#include "results.h"
#include "main.h"
#include "gui.h"

#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

void add_high(All_Results *all_results)
{
    Result *new_issue = create_new_issue();
    Result *new_issue2 = create_new_issue();

    set_id(10, new_issue);
    set_issue_description("example issue", new_issue);
    set_issue_location("/tmp/test", new_issue);
    set_issue_name("Example", new_issue);

    set_id(20, new_issue2);
    set_issue_description("example issue", new_issue2);
    set_issue_location("/tmp/tsinasdfest", new_issue2);
    set_issue_name("Exampleasdfa", new_issue2);

    add_new_result_high(new_issue, all_results);
    add_new_result_high(new_issue2, all_results);
}

void add_medium(All_Results *all_results)
{
    Result *new_issue = create_new_issue();

    set_id(110, new_issue);
    set_issue_description("EXAMPLE issue", new_issue);
    set_issue_location("/tmp/TEST", new_issue);
    set_issue_name("EXAMPLE", new_issue);

    add_new_result_medium(new_issue, all_results);
}

void add_low(All_Results *all_results)
{
    Result *new_issue = create_new_issue();

    set_id(110, new_issue);
    set_issue_description("EXAMPLE issue", new_issue);
    set_issue_location("/tmp/TEST", new_issue);
    set_issue_name("EXAMPLE", new_issue);

    add_new_result_low(new_issue, all_results);
}

void add_info(All_Results *all_results)
{
    Result *new_issue = create_new_issue();

    set_id(110, new_issue);
    set_issue_description("EXAMPLE issue", new_issue);
    set_issue_location("/tmp/TEST", new_issue);
    set_issue_name("EXAMPLE", new_issue);

    add_new_result_info(new_issue, all_results);
}

void start_scan(Ncurses_Layout *layout, All_Results *all_results, Args args)
{
    bool ncurses_enabled = args.enabled_ncurses;

    if (!ncurses_enabled)
    {
        puts("Starting scan");
    }
    add_low(all_results);
    sleep(1);
    add_high(all_results);
    sleep(1);
    add_high(all_results);
    add_medium(all_results);
    sleep(1);
    add_high(all_results);
    add_medium(all_results);
    sleep(1);
    add_medium(all_results);
    sleep(1);
    add_low(all_results);
    if (!ncurses_enabled)
    {
        print_all_results(all_results);
    }
}