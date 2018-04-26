/* Copyright (c) 2016 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
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

static int verbose = 0;

//#define DEBUG true 
#define DEBUG false 

static const char *file_rxcnt = "/sys/fs/bpf/rxcnt";
static const char *file_vip2tnl   = "/sys/fs/bpf/vip2tnl";
static const char *file_service   = "/sys/fs/bpf/service";
static const char *file_linklist   = "/sys/fs/bpf/linklist";
static const char *file_worker   = "/sys/fs/bpf/worker";
static const char *file_lbcache   = "/sys/fs/bpf/lbcache";

struct vip {
	union {
		__u32 v6[4];
		__u32 v4;
	} daddr;
	__u16 dport;
	__u16 family;
	__u8 protocol;
};

struct iptnl_info {
	union {
		__u32 v6[4];
		__u32 v4;
	} saddr;
	union {
		__u32 v6[4];
		__u32 v4;
	} daddr;
	__u16 family;
	__u8 dmac[6];
};

struct sip {
	union {
		__u32 v6[4];
		__u32 v4;
	} saddr;
	__u16 sport;
	__u16 family;
	__u8 protocol;
};

struct flowtuple {
  struct vip vip;
  struct sip sip;
};

#endif
