// SPDX-License-Identifier: GPL-2.0
#include <uapi/linux/seccomp.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"
#include <uapi/linux/unistd.h>
#include <uapi/linux/errno.h>
#include <uapi/linux/audit.h>
#include <linux/string.h>
#include <linux/fcntl.h>

#define MAX_LEN	128

struct bpf_map_def SEC("maps") strings_open = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = MAX_LEN,
        .value_size = sizeof(int),
        .max_entries = 128,
};

SEC("seccomp")
int bpf_prog1(struct seccomp_data *ctx)
{
	int flags;
        char *file_path;
        void *result;
        int perm;
        char pathname[MAX_LEN];

	if (ctx->nr != __NR_open)
		return SECCOMP_RET_ALLOW;

        flags = ctx->args[1];
        file_path = (char *) ctx->args[0];

        memset(pathname, 0, MAX_LEN);
        bpf_probe_read_str(pathname, sizeof(pathname), file_path);

        result = bpf_map_lookup_elem(&strings_open, pathname);
        if (result != NULL) {
                perm = *((int *) result);
                if (perm == O_RDWR || perm == flags)
                        return SECCOMP_RET_ALLOW;
        }

	return SECCOMP_RET_ERRNO | EPERM;
}

char _license[] SEC("license") = "GPL";
