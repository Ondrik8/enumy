/*
    This files job is to kick of all the scans
*/

#include "results.h"
#include "main.h"
#include "gui.h"
#include "file_system.h"
#include "utils.h"
#include "vector.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <thpool.h>
#include <stdbool.h>

typedef struct Walk_Args
{
    char *walk_path;
    All_Results *all_results;
    Args *cmdline;
} Walk_Args;

static void *create_walk_thread(void *args);

static void *create_walk_thread(void *args)
{
    Walk_Args *arguments = (Walk_Args *)args;
    All_Results *all_results = arguments->all_results;
    char *walk_path = arguments->walk_path;
    Args *cmdline = arguments->cmdline;

    cmdline->fs_threadpool = thpool_init(cmdline->fs_threads);

    walk_file_system(walk_path, all_results, cmdline);
    thpool_destroy(cmdline->fs_threadpool);
    return NULL;
}

void start_scan(Ncurses_Layout *layout, All_Results *all_results, Args *args)
{
    pthread_t walk_thread;
    char *_;

    struct Walk_Args walk_args = {
        .walk_path = args->walk_dir,
        .all_results = all_results,
        .cmdline = args};

    args->valid_shared_libs = find_shared_libs();

    if (layout->current_category == 0x2342)
    {
        puts("I'm just here to make the compiler warning go away");
    }

    if (!args->enabled_ncurses)
    {
        printf("Walking file system at location -> %s\n", args->walk_dir);
    }

    // Walk the file system in the background while we perform other scans
    pthread_create(&walk_thread, NULL, create_walk_thread, &walk_args);
    pthread_join(walk_thread, (void **)&_);
    printf("Total files scanned -> %i\n", get_number_of_files_scanned());
    free_total_results(all_results);
    free_shared_libs(args->valid_shared_libs);
}