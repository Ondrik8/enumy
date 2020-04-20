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
#include <errno.h>

static bool check_audit_control(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_audit_read(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_audit_write(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_block_suspend(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_chown(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_dac_bypass(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_dac_read_search(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_fowner(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_clear_set_id(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_ipc_lock(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static bool check_ipc_owner(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline);
static int check_cap(cap_t caps_for_file, cap_value_t search);
static void print_cap(char *fname, cap_t cap);
static void set_other_info_to_cap_flag(cap_flag_t flag, Result *new_result);

int capabilities_scan(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int findings = 0;
    cap_t cap;

    if (!has_executable(fi))
    {
        return findings;
    }
    // printf("Attempting to open file at location %s\n", fi->location);
    int fd = open(fi->location, O_RDONLY);
    if (fd == -1)
    {
        // printf("Failed to open file at location %s\n", fi->location);
        return findings;
    }

    cap = cap_get_fd(fd);
    if (cap == NULL)
    {
        close(fd);
        return findings;
    }

    findings = (check_audit_control(cap, fi, ar, cmdline) == true) ? findings++ : findings;
    findings = (check_audit_read(cap, fi, ar, cmdline) == true) ? findings++ : findings;
    findings = (check_audit_write(cap, fi, ar, cmdline) == true) ? findings++ : findings;
    findings = (check_block_suspend(cap, fi, ar, cmdline) == true) ? findings++ : findings;
    findings = (check_chown(cap, fi, ar, cmdline) == true) ? findings++ : findings;
    findings = (check_dac_bypass(cap, fi, ar, cmdline) == true) ? findings++ : findings;
    findings = (check_dac_read_search(cap, fi, ar, cmdline) == true) ? findings++ : findings;
    findings = (check_fowner(cap, fi, ar, cmdline) == true) ? findings++ : findings;
    findings = (check_clear_set_id(cap, fi, ar, cmdline) == true) ? findings++ : findings;
    findings = (check_ipc_lock(cap, fi, ar, cmdline) == true) ? findings++ : findings;
    findings = (check_ipc_owner(cap, fi, ar, cmdline) == true) ? findings++ : findings;

    cap_free(cap);
    close(fd);
    return findings;
}

//CAP_AUDIT_CONTROL (since Linux 2.6.11)
//Enable and disable kernel auditing change auditing filter rules; retrieve auditing status and filtering rules.
static bool check_audit_control(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 7;
    char *name = "CAP_AUDIT_CONTROL capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_AUDIT_CONTROL);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_medium(new_result, ar, cmdline);
        return true;
    }
    return true;
}

//CAP_AUDIT_READ(since Linux 3.16)
//Allow reading the audit log via a multicast netlink socket.
static bool check_audit_read(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 8;
    char *name = "CAP_AUDIT_READ capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_AUDIT_READ);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_medium(new_result, ar, cmdline);
        return true;
    }
    return true;
}

// CAP_AUDIT_WRITE(since Linux 2.6.11)
// Write records to kernel auditing log.
static bool check_audit_write(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 9;
    char *name = "CAP_AUDIT_WRITE capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_AUDIT_WRITE);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_medium(new_result, ar, cmdline);
        return true;
    }
    return true;
}

// CAP_BLOCK_SUSPEND(since Linux 3.5)
// Employ features that can block system suspend(epoll(7)
// EPOLLWAKEUP, /proc/sys/wake_lock).
static bool check_block_suspend(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 10;
    char *name = "CAP_BLOCK_SUSPEND capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_BLOCK_SUSPEND);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_medium(new_result, ar, cmdline);
        return true;
    }
    return true;
}

// CAP_CHOWN
// Make arbitrary changes to file UIDs and GID
static bool check_chown(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 11;
    char *name = "CAP_CHOWN capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_CHOWN);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return true;
    }
    return true;
}

// CAP_DAC_OVERRIDE
// Bypass file read, write, and execute permission checks.
static bool check_dac_bypass(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 12;
    char *name = "CAP_DAC_OVERRIDE capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_DAC_OVERRIDE);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return true;
    }
    return true;
}

// CAP_DAC_READ_SEARCH
// *Bypass file read permission checks and directory read and
//     execute permission checks;
// *invoke open_by_handle_at(2);
// *use the linkat(2) AT_EMPTY_PATH flag to create a link to a file refred at fd
static bool check_dac_read_search(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 13;
    char *name = "CAP_DAC_READ_SEARCH capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_DAC_READ_SEARCH);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return true;
    }
    return true;
}

// CAP_FOWNER
// Bypass permissions checks on operations that requrire UID
// Set inodes and ACLS
// Ignore sticky bits
static bool check_fowner(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 14;
    char *name = "CAP_FOWNER capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_FOWNER);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return true;
    }
    return true;
}

// CAP_FSETID
// Do not clear SUID/GUID bits on modified files
static bool check_clear_set_id(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 15;
    char *name = "CAP_FSETID capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_FSETID);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_high(new_result, ar, cmdline);
        return true;
    }
    return true;
}

// CAP_IPC_LOCK
// Lock memory
static bool check_ipc_lock(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 16;
    char *name = "CAP_IPC_LOCK capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_IPC_LOCK);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_medium(new_result, ar, cmdline);
        return true;
    }
    return true;
}

// CAP_IPC_OWNER
// Bypass permission checks for operations on System V IPC objects
static bool check_ipc_owner(cap_t caps_for_file, File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 17;
    char *name = "CAP_IPC_OWNER capablities enabled on file";
    int cap_value = check_cap(caps_for_file, CAP_IPC_OWNER);
    if (cap_value)
    {
        Result *new_result = create_new_issue();
        set_id_and_desc(id, new_result);
        set_issue_location(fi->location, new_result);
        set_issue_name(name, new_result);
        set_other_info_to_cap_flag(cap_value, new_result);
        add_new_result_medium(new_result, ar, cmdline);
        return true;
    }
    return true;
}

// This function checks the capabilities for a file. The capabilities are either
// Effective ->     The effective set contains the capabilities that are currently active
// Inheritable ->   The permitted set contains the capabilities that the process has the right to use.
// Permited ->      The inheritable set contains the capabilities that can be inherited by children to the process
static int check_cap(cap_t caps_for_file, cap_value_t search)
{
    cap_value_t cap;                      // Capability we're looking for
    cap_flag_t flag;                      // values for this type are CAP_EFFECTIVE, CAP_INHERITABLE or CAP_PERMITTED
    cap_flag_value_t value_p = CAP_CLEAR; // valid values for this type are CAP_CLEAR (0) or CAP_SET (1)

    flag = CAP_PERMITTED;
    cap_get_flag(caps_for_file, search, flag, &value_p);
    if (value_p == CAP_SET)
    {
        return CAP_PERMITTED;
    }
    flag = CAP_INHERITABLE;
    cap_get_flag(caps_for_file, search, flag, &value_p);
    if (value_p == CAP_SET)
    {
        return CAP_INHERITABLE;
    }
    flag = CAP_EFFECTIVE;
    cap_get_flag(caps_for_file, search, flag, &value_p);
    if (value_p == CAP_SET)
    {
        return CAP_EFFECTIVE;
    }
    return 0;
}

// Just sets the issues other info value to the string representation of the flag
static void set_other_info_to_cap_flag(cap_flag_t flag, Result *new_result)
{
    if (flag == CAP_PERMITTED)
    {
        set_other_info("Capabilities flag set to -> CAP_PERMITTED", new_result);
    }
    else if (flag == CAP_INHERITABLE)
    {
        set_other_info("Capabilities flag set to -> CAP_INHERITIABLE", new_result);
    }
    else if (flag == CAP_EFFECTIVE)
    {
        set_other_info("Capabilities flag set to -> CAP_EFFECTIVE", new_result);
    }
}