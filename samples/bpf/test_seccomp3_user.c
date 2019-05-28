// SPDX-License-Identifier: GPL-2.0
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/bpf.h>
#include <unistd.h>
#include "libbpf.h"
#include "bpf_load.h"
#include <linux/bpf.h>
#include <sys/prctl.h>
#include <strings.h>
#include <errno.h>
#include <linux/unistd.h>
#include <linux/seccomp.h>
#include <linux/fcntl.h>

#define MAX_LEN	128

int main(int argc, char **argv)
{
        char filename[256];


        snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

        if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
                return 1;
        }

        /* set new_new_privs so non-privileged users can attach filters */
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
                perror("prctl(NO_NEW_PRIVS)");
                return 1;
        }

        if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                    SECCOMP_FILTER_FLAG_EXTENDED, &prog_fd)) {
                perror("seccomp");
                return 1;
        }

	char key_open[MAX_LEN];
        int value_open;

        value_open = O_RDWR;
        memset(key_open, 0, MAX_LEN);
        strcpy(key_open, "/dev/null");
        bpf_map_update_elem(map_fd[0], key_open, &value_open, BPF_ANY);

        value_open = O_RDONLY;
        memset(key_open, 0, MAX_LEN);
        strcpy(key_open, "/dev/urandom");
        bpf_map_update_elem(map_fd[0], key_open, &value_open, BPF_ANY);

        syscall(__NR_open, "/dev/null", O_RDONLY);
        assert(errno == 0);

        syscall(__NR_open, "/dev/urandom", O_WRONLY);
        assert(errno == EPERM);

	printf("open syscall successfully filtered\n");

        return 0;
}

