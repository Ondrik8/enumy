/*
    This file holds all of the functions relating to storing, appending 
    and retriving results found from scans. There are four categories for 
    results high, medium, low, info 

    High    ->  Critical issues that should be exploitable during a CTF
    
    Medium  ->  Issues that could be could be exploitable or require certain 
                conditions to be met to be exploitable 

    Low     ->  Stuff you would report as a finding, but probably is not that 
                useful durning a pentest 

    Info    ->  Stuff that is not an issue but could be useful during a pentest
                for example, current user, groups, running processes etc 
    
    These results are stored in the All_Results struct, this struct contains a 
    pointer to the head of the linked list for each category
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "results.h"
#include "utils.h"
#include "main.h"

#define URL "https://exploitwriteup.com/enumy-results/#"

All_Results *initilize_total_results();
Result *create_new_issue();

void set_id(int issue_id, Result *result_node);
void set_issue_name(char *issue_name, Result *result_node);
void set_issue_description(char *issue_description, Result *result_node);
void set_issue_location(char *issue_location, Result *result_nodee);

void print_all_results(All_Results *all_results);
void print_high_results(All_Results *all_results);
void print_medium_results(All_Results *all_results);
void print_low_results(All_Results *all_results);
void print_info_results(All_Results *all_results);

bool add_new_result_high(Result *new_result, All_Results *result, Args *cmdline);
bool add_new_result_medium(Result *new_result, All_Results *result, Args *cmdline);
bool add_new_result_low(Result *new_result, All_Results *result, Args *cmdline);
bool add_new_result_info(Result *new_result, All_Results *result, Args *cmdline);

static void log_issue_to_screen(Result *new_result);
static void print_result_set(Result *result_cat);
static bool is_complete(Result *new_result);
static void add_new_issue(Result *new_result, All_Results *all_results, int category);

static int count_linked_list_length(Result *first_result);

// Creates the All_Results struct, should only be called once
All_Results *initilize_total_results()
{
    struct All_Results *all_results = (struct All_Results *)malloc(sizeof(struct All_Results));

    all_results->high = (struct Result *)malloc(sizeof(struct Result));
    all_results->medium = (struct Result *)malloc(sizeof(struct Result));
    all_results->low = (struct Result *)malloc(sizeof(struct Result));
    all_results->info = (struct Result *)malloc(sizeof(struct Result));

    if (
        (all_results->high == NULL) ||
        (all_results->medium == NULL) ||
        (all_results->low == NULL) ||
        (all_results->info == NULL))
    {
        out_of_memory_err();
    }

    all_results->high_end_node = all_results->high;
    all_results->medium_end_node = all_results->medium;
    all_results->low_end_node = all_results->low;
    all_results->info_end_node = all_results->info;

    all_results->gui_requires_refresh = NO_REFRESH;

    all_results->high->issue_id = FIRST_ID;
    all_results->medium->issue_id = FIRST_ID;
    all_results->low->issue_id = FIRST_ID;
    all_results->info->issue_id = FIRST_ID;

    return all_results;
}

// Creates a base issue with default values
Result *create_new_issue()
{
    struct Result *new_result = (struct Result *)malloc(sizeof(struct Result));

    if (new_result == NULL)
    {
        out_of_memory_err();
    }

    /* set the issues to invalid values so we can test if a new issue is commplete */
    new_result->issue_id = INCOMPLETE_ID;
    new_result->issue_name[0] = '\0';
    new_result->description[0] = '\0';
    new_result->location[0] = '\0';
    new_result->next = NULL;
    new_result->previous = NULL;

    return new_result;
}

// Set id for the base issue
void set_id(int issue_id, Result *result_node)
{
    result_node->issue_id = issue_id;
}

// Set id for the base issue and the description as a
// link to the issue writeup on my website with the id being the
// ancore point to the link
void set_id_and_desc(int issue_id, Result *result_node)
{
    int length = snprintf(NULL, 0, "%d", issue_id);
    char *str = malloc(length + 1);
    if (str == NULL)
    {
        out_of_memory_err();
    }
    snprintf(str, length + 1, "%d", issue_id);

    result_node->issue_id = issue_id;
    strcpy(result_node->description, URL);
    strcat(result_node->description, str);
    free(str);
}

// Set issue name for the base issue
void set_issue_name(char *issue_name, Result *result_node)
{
    strncpy(result_node->issue_name, issue_name, sizeof(result_node->issue_name));
}

// Set issue description for the base issue
void set_issue_description(char *issue_description, Result *result_node)
{
    strncpy(result_node->description, issue_description, sizeof(result_node->description));
}

// Set issue location for the base issue
void set_issue_location(char *issue_location, Result *result_node)
{
    strncpy(result_node->location, issue_location, sizeof(result_node->location));
}

// Prints all the results in non ncurse mode
void print_all_results(All_Results *all_results)
{
    print_high_results(all_results);
    print_medium_results(all_results);
    print_low_results(all_results);
    print_info_results(all_results);
}

// Prints the high results in non ncurse mode
void print_high_results(All_Results *all_results)
{
    puts("HIGH:");
    print_result_set(all_results->high);
    puts("");
}

// Prints the medium results in non ncurse mode
void print_medium_results(All_Results *all_results)
{
    puts("MEDIUM:");
    print_result_set(all_results->medium);
    puts("");
}

// Prints the low results in non ncurse mode
void print_low_results(All_Results *all_results)
{
    puts("LOW:");
    print_result_set(all_results->low);
    puts("");
}

// Prints the info results in non ncurse mode
void print_info_results(All_Results *all_results)
{
    puts("INFO:");
    print_result_set(all_results->info);
    puts("");
}

// Adds a new fully completed issue to the High linked list
bool add_new_result_high(Result *new_result, All_Results *all_results, Args *cmdline)
{
    if (!is_complete(new_result))
        return false;

    add_new_issue(new_result, all_results, HIGH);

    all_results->high_end_node = new_result;
    all_results->gui_requires_refresh = HIGH;

    if (!cmdline->enabled_ncurses)
    {
        log_issue_to_screen(new_result);
    }

    return true;
}

// Adds a new fully completed issue to the Medium linked list
bool add_new_result_medium(Result *new_result, All_Results *all_results, Args *cmdline)
{
    if (!is_complete(new_result))
        return false;

    add_new_issue(new_result, all_results, MEDIUM);

    all_results->medium_end_node = new_result;
    all_results->gui_requires_refresh = MEDIUM;

    if (!cmdline->enabled_ncurses)
    {
        log_issue_to_screen(new_result);
    }

    return true;
}

// Adds a new fully completed issue to the Low linked list
bool add_new_result_low(Result *new_result, All_Results *all_results, Args *cmdline)
{
    if (!is_complete(new_result))
        return false;

    add_new_issue(new_result, all_results, LOW);

    all_results->low_end_node = new_result;
    all_results->gui_requires_refresh = LOW;

    if (!cmdline->enabled_ncurses)
    {
        log_issue_to_screen(new_result);
    }

    return true;
}

// Adds a new fully completed issue to the Info linked list
bool add_new_result_info(Result *new_result, All_Results *all_results, Args *cmdline)
{
    if (!is_complete(new_result))
        return false;

    add_new_issue(new_result, all_results, INFO);

    all_results->info_end_node = new_result;
    all_results->gui_requires_refresh = INFO;

    if (!cmdline->enabled_ncurses)
    {
        log_issue_to_screen(new_result);
    }

    return true;
}

// Tests to make sure that issue stuct is completed
// has side effect of printing incomplete structs
static bool is_complete(Result *new_result)
{
    if (
        (new_result->issue_id != INCOMPLETE_ID) &&
        (new_result->issue_name[0] != '\0') &&
        (new_result->description[0] != '\0') &&
        (new_result->location[0] != '\0'))
    {
        return true;
    }

    log_issue_to_screen(new_result);
    return false;
}

/* Only called if programmer forgot to set all values 
of the struct before adding to linked list */
static void log_issue_to_screen(Result *new_result)
{
    printf("Programming error:");
    printf("issue_id: %i\n", new_result->issue_id);
    printf("issue_name: %s\n", new_result->issue_name);
    printf("description: %s\n", new_result->description);
    printf("location: %s\n", new_result->location);
}

static void print_result_set(Result *result_cat)
{
    struct Result *res_ptr = result_cat;

    printf("%-10s%-30s%-60s%60s\n", "Issue_ID", "Name", "Description", "Location");
    while (res_ptr != NULL)
    {
        if (res_ptr->issue_id == FIRST_ID)
        {
            printf("%-10s%-30s%-60s%60s\n", "None", "None", "None", "None");
            break;
        }
        printf("%-10i%-30s%-60s%60s\n", res_ptr->issue_id, res_ptr->issue_name, res_ptr->description, res_ptr->location);
        res_ptr = res_ptr->next;
    }
}

// Finds the correct linked list, if the first element in the link list is the dummy issue
// then swap it with the new result. Updates the saved end nodes.
static void add_new_issue(Result *new_result, All_Results *all_results, int category)
{
    struct Result *old_head;
    switch (category)
    {
    case HIGH:
        old_head = all_results->high_end_node;
        all_results->high_end_node = new_result;
        if (all_results->high->issue_id == FIRST_ID)
        {
            all_results->high = new_result;
        }

        all_results->high_end_node->previous = old_head;
        old_head->next = new_result;
        break;

    case MEDIUM:
        old_head = all_results->medium_end_node;
        all_results->medium_end_node = new_result;

        if (all_results->medium->issue_id == FIRST_ID)
        {
            all_results->medium = new_result;
        }

        all_results->medium_end_node->previous = old_head;
        old_head->next = new_result;
        break;

    case LOW:
        old_head = all_results->low_end_node;
        all_results->low_end_node = new_result;

        if (all_results->low->issue_id == FIRST_ID)
        {
            all_results->low = new_result;
        }

        all_results->low_end_node->previous = old_head;
        old_head->next = new_result;
        break;

    case INFO:
        old_head = all_results->info_end_node;
        all_results->info_end_node = new_result;
        if (all_results->info->issue_id == FIRST_ID)
        {
            all_results->info = new_result;
        }
        all_results->info_end_node->previous = old_head;
        old_head->next = new_result;
        break;

    default:
        puts("Programming error, category was not found");
        printf("Category -> %i\n", category);
    }
}

int get_results_total(All_Results *result)
{
    return (
        get_tot_high(result) +
        get_tot_medium(result) +
        get_tot_low(result) +
        get_tot_info(result));
}

int get_tot_high(All_Results *result)
{
    struct Result *head_ptr = result->high;
    return count_linked_list_length(head_ptr);
}

int get_tot_medium(All_Results *result)
{
    struct Result *head_ptr = result->medium;
    return count_linked_list_length(head_ptr);
}

int get_tot_low(All_Results *result)
{
    struct Result *head_ptr = result->low;
    return count_linked_list_length(head_ptr);
}

int get_tot_info(All_Results *result)
{
    struct Result *head_ptr = result->info;
    return count_linked_list_length(head_ptr);
}

static int count_linked_list_length(Result *first_result)
{
    int tot = 0;
    struct Result *next_item = first_result;

    while ((next_item) && (next_item->issue_id != FIRST_ID))
    {
        tot++;
        next_item = next_item->next;
    }
    return tot;
}