#pragma once

#include "main.h"

#include <stdbool.h>

#define HIGH 3
#define MEDIUM 2
#define LOW 1
#define INFO 0
#define NO_REFRESH -1

#define MAXSIZE 512

#define FIRST_ID -1
#define INCOMPLETE_ID -1

typedef struct Result
{
    int issue_id;
    char issue_name[MAXSIZE];
    char description[MAXSIZE];
    char location[MAXSIZE];
    char other_info[MAXSIZE];
    struct Result *previous, *next;
} Result;

typedef struct All_Results
{
    Result *high;
    Result *high_end_node;

    Result *medium;
    Result *medium_end_node;

    Result *low;
    Result *low_end_node;

    Result *info;
    Result *info_end_node;

    int gui_requires_refresh;
} All_Results;

All_Results *initilize_total_results();

Result *create_new_issue();
void set_id(int issue_id, Result *result_node);
void set_id_and_desc(int issue_id, Result *result_node);
void set_issue_name(char *issue_name, Result *result_node);
void set_issue_description(char *issue_description, Result *result_node);
void set_issue_location(char *issue_location, Result *result_node);
void set_other_info(char *issue_location, Result *result_nodee);

bool add_new_result_high(Result *new_result, All_Results *result, Args *cmdline);
bool add_new_result_medium(Result *new_result, All_Results *result, Args *cmdline);
bool add_new_result_low(Result *new_result, All_Results *result, Args *cmdline);
bool add_new_result_info(Result *new_result, All_Results *result, Args *cmdline);

void print_all_results(All_Results *all_results);
void print_high_results(All_Results *all_results);
void print_medium_results(All_Results *all_results);
void print_low_results(All_Results *all_results);
void print_info_results(All_Results *all_results);

int get_results_total(All_Results *result);
int get_tot_high(All_Results *result);
int get_tot_medium(All_Results *result);
int get_tot_low(All_Results *result);
int get_tot_info(All_Results *result);