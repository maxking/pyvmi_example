#! /usr/bin/env python

import os
import sys
import pyvmi
from collections import namedtuple

MEM_PATH = "/dev/mem"
DEFAULT_DEBUGFS_PATH = "/sys/kernel/debug"
PROCESS_DIR = "states"
CRED_UID_OFFSET = 0x4
CRED_GID_OFFSET = 0x8
LINUX_CRED_OFFSET = 0x588
LINUX_PARENT_OFFSET = 0x3f0;
top_debugfs_dir = os.path.join(DEFAULT_DEBUGFS_PATH, PROCESS_DIR)

Process = namedtuple('Process', 'pid uid gid ppid')

def debugfs_get_processes():
    """
    Get the process list from debugfs. By default, the debugfs is located at
    /sys/kernel/debug and we add all the processes inside `states` directory.
    Each directory inside states represents a process and within them there are
    files that represent the uid, gid, and different capabilities of that
    process.
    """

    processes = os.listdir(top_debugfs_dir)
    processes = [Process(pid=int(x),
                         uid=debugfs_get_uid(int(x)),
                         gid=debugfs_get_gid(int(x)),
                         ppid=debugfs_get_ppid(int(x)))
                 for x in processes]
    return processes

def debugfs_get_uid(pid):
    """
    Return the processes's uid from the debugfs.
    """
    proc_uid_path = os.path.join(top_debugfs_dir, str(pid), "uid")
    with open(proc_uid_path) as f:
        uid = debugfs_get_file_content(f)

    return int(uid)

def debugfs_get_gid(pid):
    """
    Return the processes's gid from the debugfs.
    """
    proc_gid_path = os.path.join(top_debugfs_dir, str(pid), "gid")
    with open(proc_gid_path) as f:
        gid = debugfs_get_file_content(f)

    return int(gid)

def debugfs_get_ppid(pid):
    """
    Return the parent proceses's pid from debugfs.
    """
    proc_ppid_path = os.path.join(top_debugfs_dir, str(pid), "ppid")
    with open(proc_ppid_path) as f:
        ppid = debugfs_get_file_content(f)

    return int(ppid)

def debugfs_get_file_content(fd):
    """
    Assuming the file contains a single value in the first line, return the
    complete first line of the file.
    """
    return fd.readlines()[0]


def pyvmi_get_processes(vmi):
    """
    Walk through the process list of the VM and return the list of all processes.
    """
    tasks_offset = vmi.get_offset("linux_tasks")
    # name_offset = vmi.get_offset("linux_name") - tasks_offset
    pid_offset = vmi.get_offset("linux_pid") - tasks_offset
    cred_offset = LINUX_CRED_OFFSET - tasks_offset
    parent_offset = LINUX_PARENT_OFFSET - tasks_offset
    list_head = vmi.translate_ksym2v("init_task")
    next_process = vmi.read_addr_va(list_head + tasks_offset, 0)
    list_head = next_process

    processes = []
    while True:
        pid = vmi.read_32_va(next_process + pid_offset, 0)
        cred = vmi.read_64_va(next_process + cred_offset, 0)
        uid = vmi.read_32_va(cred + CRED_UID_OFFSET, 0)
        gid = vmi.read_32_va(cred + CRED_GID_OFFSET, 0)

        parent = vmi.read_64_va(next_process + parent_offset, 0)

        ppid = vmi.read_32_va(parent + pid_offset, 0)
        next_process = vmi.read_addr_va(next_process, 0)

        # Check if the pid is not a garbage value of MAXINT
        if (pid < 1<<16):
            processes.append(Process(pid=pid, uid=uid, gid=gid, ppid=ppid))
        if (list_head == next_process):
            break

    return processes

def check_privilege_escalation(proc_pyvmi, proc_debugfs, attr_verify):
    for each in attr_verify:
        if each == "ppid":
            check_ppid_escalation(proc_pyvmi, proc_debugfs)
            continue
        check_generic_escalation(proc_pyvmi, proc_debugfs, each)

def check_ppid_escalation(proc_pyvmi, proc_debugfs):
    if proc_debugfs.ppid > 0:
        if proc_pyvmi.ppid > 0:
            print("Parent Changed from {0} to {0} ".format(proc_debugfs.ppid,
                                                           proc_pyvmi.ppid))

def check_generic_escalation(proc_pyvmi, proc_debugfs, attr):
    proc_debugfs_attr = getattr(proc_debugfs, attr)
    proc_pyvmi_attr = getattr(proc_pyvmi, attr)

    if proc_debugfs_attr == 0:
        assert getattr(proc_pyvmi, attr) >= 0, "Something looks suspicious\n" \
            "Escalated {2} privileges \n" \
            "PyVMI: {0} ... DebugsFS: {1}".format(
                proc_pyvmi, proc_debugfs, attr)
    elif proc_debugfs_attr > 0:
        assert proc_debugfs_attr == proc_pyvmi_attr ,"Something looks suspicious\n" \
            "Escalated {2} privileges \n" \
            "PyVMI: {0} ... DebugsFS: {1}".format(
                proc_pyvmi, proc_debugfs, attr)

def main(argv):
    print("The pid for this process is: {}".format(os.getpid()))
    try:
        vmi = pyvmi.init(MEM_PATH, "complete")
    except ValueError:
        print("Please check your VMI config for {}".format(MEM_PATH))
        exit(1)

    procs_pyvmi = dict({x.pid:x for x in pyvmi_get_processes(vmi)})
    procs_debugfs = dict({(x.pid, x) for x in debugfs_get_processes()})

    attr_verify = ["uid", "gid", "ppid"]
    for pid, proc_pyvmi in procs_pyvmi.iteritems():
        if pid in procs_debugfs:
            proc_debugfs = procs_debugfs[pid]
            if not proc_debugfs == proc_pyvmi:
                try:
                    check_privilege_escalation(proc_pyvmi,
                                               proc_debugfs, attr_verify)
                except AssertionError as e:
                    print(str(e))




if __name__ == "__main__":
    main(sys.argv)
