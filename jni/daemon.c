//===------------------------------------------------------------------------------------------===//
//
//                        The MANIAC Dynamic Binary Instrumentation Engine
//
//===------------------------------------------------------------------------------------------===//
//
// Copyright (C) 2018 Libre.io Developers
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
//
//===------------------------------------------------------------------------------------------===//
//
// daemon.c: the process-watchdog
//
//===------------------------------------------------------------------------------------------===//

#include <dirent.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__LP64__)
#define ZYGOTE_PROCNAME "zygote64"
#else
#define ZYGOTE_PROCNAME "zygote"
#endif

#if defined(__aarch64__)
#define ARCH "arm64-v8a"
#elif defined(__arm__)
#define ARCH "armeabi-v7a"
#elif defined(__x86_64__)
#define ARCH "x86_64"
#elif defined(__i386__)
#define ARCH "x86"
#endif

#define MODULES "/data/data/io.libre.maniac/private/mods/"
#define UTILS "/data/data/io.libre.maniac/private/utils/"
#define RUNTIME UTILS "/" ARCH "/maniacrun"

#define SBUF 32
#define MBUF 128
#define LBUF 512

pid_t _getpid(char* pname)
{
    DIR* dp = opendir("/proc");

    if (!dp) {
        closedir(dp);
        return 0;
    }

    pid_t pid_entry = -1;
    struct dirent* dirp = NULL;

    while (pid_entry == -1 && (dirp = readdir(dp))) {
        int id = atoi(dirp->d_name);

        if (id <= 0)
            continue;

        char cmd_path[SBUF];
        snprintf(cmd_path, SBUF, "/proc/%s/cmdline", dirp->d_name);

        char* cmd_line = NULL;
        FILE* cmd_file = fopen(cmd_path, "r");
        size_t cmd_len;

        if (getline(&cmd_line, &cmd_len, cmd_file) == -1) {
            free(cmd_line);
            continue;
        }

        int cmp_res = strcmp(cmd_line, pname);

        free(cmd_line);

        if (cmp_res == 0) {
            pid_entry = id;
            break;
        }
    }

    closedir(dp);

    return pid_entry;
}

void _getpname(pid_t pid, char* pname)
{
    char cmd_path[SBUF];
    snprintf(cmd_path, SBUF, "/proc/%d/cmdline", pid);

    char* cmd_line = NULL;
    FILE* cmd_file = fopen(cmd_path, "r");
    size_t cmd_len;

    getline(&cmd_line, &cmd_len, cmd_file);

    strncpy(pname, cmd_line, SBUF);

    free(cmd_line);
}

int main(void)
{
    pid_t zygote_pid = _getpid(ZYGOTE_PROCNAME);

    if (ptrace(PTRACE_SEIZE, zygote_pid, NULL, NULL) == -1)
        exit(-1);

    if (waitpid(zygote_pid, NULL, WUNTRACED) != zygote_pid)
        exit(-1);

    if (ptrace(PTRACE_SETOPTIONS, zygote_pid, 1, PTRACE_O_TRACECLONE) == -1)
        exit(-1);

    if (ptrace(PTRACE_CONT, zygote_pid, NULL, NULL) == -1)
        exit(-1);

    pid_t app_pid = 0;
    int32_t status = 0;

POLL:
    // wait until zygote raises an event
    if (waitpid(zygote_pid, &status, __WALL) != zygote_pid)
        exit(-1);

    // filter out spurious events
    if ((status >> 8) != (SIGTRAP | PTRACE_EVENT_CLONE << 8)) {
        if (ptrace(PTRACE_CONT, zygote_pid, NULL, NULL) == -1)
            exit(-1);

        goto POLL;
    }

    // retrieve the PID of the cloned process
    if (ptrace(PTRACE_GETEVENTMSG, zygote_pid, NULL, &app_pid) == -1)
        exit(-1);

    // retrieve the process name from /proc
    char pname[SBUF];
    _getpname(app_pid, pname);

    // check if the corresponding module directory exists
    char dirname[MBUF] = MODULES;
    strncat(dirname, pname, MBUF);

    DIR* dir = opendir(dirname);

    // no module found -- detach from the process
    if (!dir) {
        ptrace(PTRACE_DETACH, app_pid, NULL, NULL);
        goto POLL;
    }

    // module found -- proceed
    closedir(dir);

    // wait until the process is ready to be injected
    if (ptrace(PTRACE_CONT, zygote_pid, NULL, NULL) == -1)
        exit(-1);

    // heuristic; wait until the first syscall
    if (ptrace(PTRACE_SYSCALL, app_pid, NULL, NULL) == -1)
        exit(-1);

    if (waitpid(app_pid, NULL, __WALL) != app_pid)
        exit(-1);

    // invoke the runtime
    ptrace(PTRACE_DETACH, app_pid, NULL, NULL);
    chmod(RUNTIME, 0700);

    pid_t pid = fork();

    if (pid == -1)
        goto POLL;

    if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    } else {
        execl(RUNTIME, pname, NULL);
        _exit(-1);
    }

    goto POLL;
}
