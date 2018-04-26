#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") testmap = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64 ),
	.value_size = sizeof(__u64 ),
	.max_entries = 256,
};

SEC("xdp_tx_iptunnel")
int _xdp_tx_iptunnel(struct xdp_md *xdp)
{
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
