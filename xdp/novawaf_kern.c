// NovaWAF - XDP/eBPF 前置过滤器（内核态，Linux 5.x+）
// 在网卡驱动层直接丢弃恶意包，不进入协议栈，性能接近线速。
// 编译: clang -O2 -target bpf -c novawaf_kern.c -o novawaf_kern.o
// 加载: ip link set dev <iface> xdp obj novawaf_kern.o sec xdp
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// 黑名单 IP 映射（用户态通过 BPF map 动态下发）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u8);
} blacklist SEC(".maps");

// 统计计数器
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

enum stat_type {
    STAT_TOTAL = 0,
    STAT_DROPPED = 1,
    STAT_PASSED = 2,
};

static __always_inline void inc_stat(enum stat_type t) {
    __u32 key = t;
    __u64 *v = bpf_map_lookup_elem(&stats, &key);
    if (v) __sync_fetch_and_add(v, 1);
}

// 检查 TCP 标志位，丢弃明显畸形包
static __always_inline int is_malformed_tcp(struct tcphdr *tcp, void *data_end) {
    if ((void *)(tcp + 1) > data_end) return 1;
    // NULL 扫描 / XMAS 扫描等异常标志组合
    __u8 flags = ((__u8 *)tcp)[13];
    if (flags == 0) return 1;                       // NULL scan
    if ((flags & 0x3F) == 0x3F) return 1;           // XMAS scan
    // SYN+FIN 同时置位
    if ((flags & 0x03) == 0x03) return 1;
    return 0;
}

SEC("xdp")
int novawaf_xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    inc_stat(STAT_TOTAL);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_DROP;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_DROP;

    // 黑名单 IP 检查（源地址）
    __u32 src = ip->saddr;
    __u8 *blocked = bpf_map_lookup_elem(&blacklist, &src);
    if (blocked && *blocked) {
        inc_stat(STAT_DROPPED);
        return XDP_DROP;
    }

    // TCP 畸形包检查
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if (is_malformed_tcp(tcp, data_end)) {
            inc_stat(STAT_DROPPED);
            return XDP_DROP;
        }
    }

    inc_stat(STAT_PASSED);
    return XDP_PASS;
}
