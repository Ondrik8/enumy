#include "results.h"
#include "fs.h"
#include "main.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/capability.h>
#include <unistd.h>
#include <stdlib.h>

static bool check_audit_control(cap_t caps_for_file);
static bool check_cap(cap_t caps_for_file, cap_value_t search);

int capabilities_scan(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int findings = 0;
    cap_t cap;

    int fd = open(fi->location, O_RDONLY);
    if (fd == -1)
    {
        return findings;
    }

    cap = cap_get_fd(fd);

    if (check_audit_control(cap))
    {
        findings++;
    }

    cap_free(cap);
    return findings;
}

static bool check_audit_control(cap_t caps_for_file)
{
    check_cap(caps_for_file, CAP_AUDIT_CONTROL);
}

static bool check_cap(cap_t caps_for_file, cap_value_t search)
{
    cap_t cap_p;               // Current files capabilities
    cap_value_t cap;           // Capability we're looking for
    cap_flag_t flag;           // values for this type are CAP_EFFECTIVE, CAP_INHERITABLE or CAP_PERMITTED
    cap_flag_value_t *value_p; // valid values for this type are CAP_CLEAR (0) or CAP_SET (1)
    // cap_get_flag()
}
