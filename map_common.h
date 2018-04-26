
#ifndef _SAMPLES_BPF_XDP_TX_IPTNL_COMMON_H
#define _SAMPLES_BPF_XDP_TX_IPTNL_COMMON_H

#include <linux/types.h>

#define EXIT_OK                 0
#define EXIT_FAIL               1
#define EXIT_FAIL_OPTION        2
#define EXIT_FAIL_XDP           3
#define EXIT_FAIL_MAP           20
#define EXIT_FAIL_MAP_KEY       21
#define EXIT_FAIL_MAP_FILE      22
#define EXIT_FAIL_MAP_FS        23
#define EXIT_FAIL_IP            30
#define EXIT_FAIL_PORT          31
#define EXIT_FAIL_BPF           40
#define EXIT_FAIL_BPF_ELF       41
#define EXIT_FAIL_BPF_RELOCATE  42

#define MAX_IPTNL_ENTRIES 256U

#define ACTION_ADD      (1<<0)
#define ACTION_DEL      (1<<1)

static int verbose = 1;

static const char *file_testmap = "/sys/fs/bpf/testmap";

struct vip {
	union {
		__u32 v6[4];
		__u32 v4;
	} daddr;
	__u16 family;
};

#endif
