/*
    This is the entry point for the program it's job is to parse command line 
    output and spawn the relevant threads. 
*/
#include <getopt.h>
#include <locale.h>
#include <unistd.h>
#include <ncurses.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>

#include "main.h"
#include "gui.h"
#include "scan.h"
#include "results.h"

#define KEY_J 106
#define KEY_K 107
#define KEY_SHOW_HIGH 104
#define KEY_SHOW_MEDIUM 109
#define KEY_SHOW_LOW 108
#define KEY_SHOW_INFO 105
#define KEY_DEL_CURRENT 100
#define KEY_DEL_ALL_ID 68
#define KEY_QUIT 113

typedef struct UserInputThreadArgs
{
    Ncurses_Layout *layout;
    All_Results *all_results;
} UserInputThreadArgs;

void sigint_handler(int sig)
{
    if (sig == SIGINT)
    {
        endwin();
        exit(0);
    }
}

void banner()
{
    puts(" ▄█▀─▄▄▄▄▄▄▄─▀█▄  _____  				 ");
    puts(" ▀█████████████▀ |   __|___ _ _ _____ _ _ ");
    puts("     █▄███▄█     |   __|   | | |     | | |");
    puts("      █████      |_____|_|_|___|_|_|_|_  |");
    puts("      █▀█▀█                          |___|");
}

void help()
{
    puts("");
    puts("------------------------------------------");
    puts("");
    puts("Enumy - Used to enumerate the target");
    puts("the target environment and look for common");
    puts("security vulnerabilities and hostspots");
    puts("");
    puts(" -o <loc>     Save results to location");
    puts(" -q           Run quick scans");
    puts(" -n           Enabled ncurses");
    puts(" -h           Show help");
}

void *handle_user_input(void *user_input_args)
{
    UserInputThreadArgs *args = (UserInputThreadArgs *)user_input_args;
    All_Results *all_results = args->all_results;
    Ncurses_Layout *layout = args->layout;
    char input;

    while ((input = getch()) != KEY_QUIT)
    {
        switch (input)
        {
        case KEY_J:
            layout->cursor_position++;
            break;

        case KEY_K:
            layout->cursor_position--;
            break;

        case KEY_SHOW_HIGH:
            layout->current_category = HIGH;
            update_table(all_results, layout);
            update_bars(all_results, layout);
            break;

        case KEY_SHOW_MEDIUM:
            layout->current_category = MEDIUM;
            update_table(all_results, layout);
            update_bars(all_results, layout);
            break;

        case KEY_SHOW_LOW:
            layout->current_category = LOW;
            update_table(all_results, layout);
            update_bars(all_results, layout);
            break;

        case KEY_SHOW_INFO:
            layout->current_category = INFO;
            update_table(all_results, layout);
            update_bars(all_results, layout);
            break;
        }
    }
    kill(getpid(), SIGINT);
    return NULL;
}

int main(int argc, char *argv[])
{
    int opt;

    struct Args *args = (struct Args *)malloc(sizeof(struct Args));
    args->save_location[0] = '\0';
    args->enabled_all_scans = true;
    args->enabled_quick_scans = false;
    args->enabled_ncurses = false;

    struct Ncurses_Layout nlayout = {
        .logo = NULL,
        .bars = NULL,
        .main = NULL,
        .id = NULL};

    All_Results *all_results = initilize_total_results();

    struct UserInputThreadArgs user_input_thread_args = {
        .layout = &nlayout,
        .all_results = all_results};

    signal(SIGINT, sigint_handler);

    while ((opt = getopt(argc, argv, "qhno:")) != -1)
    {
        switch (opt)
        {
        case 'h': // help
            banner();
            help();
            break;

        case 'q':
            args->enabled_quick_scans = true;
            args->enabled_all_scans = false;

        case 'o':
            break;

        case 'n':
            args->enabled_ncurses = true;
            break;

        default:
            banner();
            help();
            break;
        }
    }

    if (args->enabled_ncurses == true)
    {
        char *_;
        pthread_t user_input_thread;
        init_ncurses_layout(&nlayout, all_results);
        pthread_create(&user_input_thread, NULL, &handle_user_input, &user_input_thread_args);
        args->enabled_ncurses = true;
        start_scan(&nlayout, all_results, args);
        pthread_join(user_input_thread, (void **)&_);
        endwin();
        return 0;
    }
    else
    {
        puts("");
        banner();
        puts("\nStarting scan");
        start_scan(&nlayout, all_results, args);
    }
    return 0;
}
