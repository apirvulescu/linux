// SPDX-License-Identifier: GPL-2.0
#include <uapi/linux/seccomp.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"
#include <uapi/linux/unistd.h>
#include <uapi/linux/errno.h>
#include <uapi/linux/audit.h>
#include <linux/string.h>
#include <linux/fcntl.h>

SEC("seccomp")
int bpf_prog1(struct seccomp_data *ctx)
{
	if (ctx->nr != __NR_read)
        	return SECCOMP_RET_ALLOW;
        
        if (ctx->args[0] == 101)
        	return SECCOMP_RET_ALLOW;

	return SECCOMP_RET_ERRNO | EPERM;
}

char _license[] SEC("license") = "GPL";
