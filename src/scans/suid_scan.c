/* 
    This file contains all the scans that can be run on a given file found 
    when walking the file systems. Most of theses scans relate to insecure 
    permissions

    The permission of proceses that is executing a GUID or SUID binary is 
    elevated or de-elevated at run time based of the owner or group attached 
    to the file. This means that they're a great target to try and exploit. 
    SUID/GUID binaries are not insecure, but an insecuritys can be exploited 
    resulting in higher impact vulnerability
*/

#include "results.h"
#include "file_system.h"
#include "scan.h"
#include "main.h"

#include <stdio.h>
#include <string.h>

char *KNOW_GOOD_SUID[] = {

    "sudo",
    "ping",
    "mount",
    "umount",
    "fusermount3",
    "chfn",
    "expiry",
    "change",
    "unix_chkpwd",
    "su",
    "newgrp",
    "passwd",
    "pkexec",
    "ksu",
    "nvidia-modprobe",
    "gpasswd",
    "mount.cifs",
    "chsh",
    "suexec",
    "sg",
    "vmware-mount",
    "vmware-vmx-debug",
    "vmware-vvmx-stats",
    "snap-confine",
    "mail-dotlock",
    "ssh-keysign",
    "polkit-agent-helper-1",
    "chrome-sandbox",
    "pam_extrausers_chkpwd",
    "chage",
    "ssh-agent",
    "wall",
    "vmware-authd",
    "fusermount",
    "locate",
    "write",
    "vmware-vmx-stats",
    "Xorg.wrap",
    "VBoxNetDHCP",
    "VBoxNetNAT",
    "VBoxSDL",
    "VBoxHeadless",
    "VBoxNetAdpCtl",
    "vmware-vmx",
    "VirtualBoxVM",

};

int suid_bit_scan(File_Info *fi, All_Results *ar, Args *cmdline);
int guid_bit_scan(File_Info *fi, All_Results *ar, Args *cmdline);

static bool has_normal_suid_name(File_Info *fi);
static bool has_suid_and_global_write(File_Info *fi, All_Results *ar, Args *cmdline);
static bool has_suid_and_group_write(File_Info *fi, All_Results *ar, Args *cmdline);
static bool has_guid_and_global_write(File_Info *fi, All_Results *ar, Args *cmdline);
static bool has_guid_and_group_write(File_Info *fi, All_Results *ar, Args *cmdline);

int suid_bit_scan(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int findings = 0;
    int id = 1;
    char *name = "Abnormal SUID enabled executable found";

    if (
        !has_suid(fi) ||
        !has_global_execute(fi) ||
        (has_normal_suid_name(fi) && !has_global_write(fi)))
    {
        return findings;
    }

    findings++;

    Result *new_result = create_new_issue();
    set_id_and_desc(id, new_result);
    set_issue_location(fi->location, new_result);
    set_issue_name(name, new_result);
    add_new_result_medium(new_result, ar, cmdline);

    if (has_suid_and_global_write(fi, ar, cmdline))
    {
        findings++;
    }

    if (has_suid_and_group_write(fi, ar, cmdline))
    {
        findings++;
    }
    findings += break_out_binary_scan(fi, ar, cmdline);
    return findings;
}

int guid_bit_scan(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int findings = 0;
    int id = 4;
    char *name = "Abnormal GUID enabled executable found";

    if (
        !has_guid(fi) ||
        !has_global_execute(fi) ||
        (has_normal_suid_name(fi) && !has_global_write(fi)))
    {
        return findings;
    }

    findings++;

    Result *new_result = create_new_issue();
    set_id_and_desc(id, new_result);
    set_issue_location(fi->location, new_result);
    set_issue_name(name, new_result);
    add_new_result_medium(new_result, ar, cmdline);

    if (has_guid_and_global_write(fi, ar, cmdline))
    {
        findings++;
    }

    if (has_guid_and_group_write(fi, ar, cmdline))
    {
        findings++;
    }
    return findings;
}

static bool has_normal_suid_name(File_Info *fi)
{
    int size = sizeof KNOW_GOOD_SUID / sizeof KNOW_GOOD_SUID[0];
    for (int x = 0; x < size; x++)
    {
        if (strcmp(fi->name, KNOW_GOOD_SUID[x]) == 0)
        {
            return true;
        }
    }
    return false;
}

static bool has_suid_and_global_write(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 2;
    char *name = "SUID enabled executable with global write access";

    if (!has_global_write(fi))
    {
        return false;
    }

    Result *new_result = create_new_issue();
    set_id(id, new_result);
    set_id_and_desc(id, new_result);
    set_issue_location(fi->location, new_result);
    set_issue_name(name, new_result);
    add_new_result_high(new_result, ar, cmdline);

    return true;
}

static bool has_suid_and_group_write(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 3;
    char *name = "SUID enabled executable with group write access";

    if (!has_group_write(fi))
    {
        return false;
    }

    Result *new_result = create_new_issue();
    set_id(id, new_result);
    set_id_and_desc(id, new_result);
    set_issue_location(fi->location, new_result);
    set_issue_name(name, new_result);
    add_new_result_high(new_result, ar, cmdline);

    return true;
}

static bool has_guid_and_global_write(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 5;
    char *name = "GUID enabled executable with global write access";

    if (!has_global_write(fi))
    {
        return false;
    }

    Result *new_result = create_new_issue();
    set_id(id, new_result);
    set_id_and_desc(id, new_result);
    set_issue_location(fi->location, new_result);
    set_issue_name(name, new_result);
    add_new_result_high(new_result, ar, cmdline);

    return true;
}

static bool has_guid_and_group_write(File_Info *fi, All_Results *ar, Args *cmdline)
{
    int id = 6;
    char *name = "GUID enabled executable with group write access";

    if (!has_group_write(fi))
    {
        return false;
    }

    Result *new_result = create_new_issue();
    set_id(id, new_result);
    set_id_and_desc(id, new_result);
    set_issue_location(fi->location, new_result);
    set_issue_name(name, new_result);
    add_new_result_high(new_result, ar, cmdline);

    return true;
}