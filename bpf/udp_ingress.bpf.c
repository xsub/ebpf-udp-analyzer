// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/socket.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifndef AF_INET
#define AF_INET 2
#endif

struct udp_key {
    __u8 family;
    __u8 ip_proto;
    __u16 src_port;
    __u16 dst_port;
    __u32 ifindex;
    __u32 src_ip4;
    __u32 dst_ip4;
};

struct udp_counters {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct udp_key);
    __type(value, struct udp_counters);
} udp_ingress_counters SEC(".maps");

static __always_inline int account_udp4(struct __sk_buff *skb, void *data, void *data_end)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return BPF_OK;
    }

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return BPF_OK;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return BPF_OK;
    }

    if (ip->protocol != IPPROTO_UDP) {
        return BPF_OK;
    }

    __u32 ip_header_bytes = ip->ihl * 4;
    if (ip_header_bytes < sizeof(*ip)) {
        return BPF_OK;
    }

    struct udphdr *udp = (void *)ip + ip_header_bytes;
    if ((void *)(udp + 1) > data_end) {
        return BPF_OK;
    }

    __u16 udp_len = bpf_ntohs(udp->len);
    __u64 payload_bytes = 0;
    if (udp_len >= sizeof(*udp)) {
        payload_bytes = udp_len - sizeof(*udp);
    }

    struct udp_key key = {
        .family = AF_INET,
        .ip_proto = IPPROTO_UDP,
        .src_port = bpf_ntohs(udp->source),
        .dst_port = bpf_ntohs(udp->dest),
        .ifindex = skb->ifindex,
        .src_ip4 = ip->saddr,
        .dst_ip4 = ip->daddr,
    };

    struct udp_counters zero = {};
    struct udp_counters *counters = bpf_map_lookup_elem(&udp_ingress_counters, &key);
    if (!counters) {
        bpf_map_update_elem(&udp_ingress_counters, &key, &zero, BPF_NOEXIST);
        counters = bpf_map_lookup_elem(&udp_ingress_counters, &key);
        if (!counters) {
            return BPF_OK;
        }
    }

    counters->packets += 1;
    counters->bytes += payload_bytes;
    return BPF_OK;
}

SEC("classifier/udp_ingress")
int udp_ingress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    return account_udp4(skb, data, data_end);
}

char LICENSE[] SEC("license") = "GPL";
