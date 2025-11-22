#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

// 1. Khai báo Map: Blacklist (Key: IP, Value: Flag)
// BCC hỗ trợ macro BPF_HASH cực tiện
BPF_HASH(blacklist, u32, u8);

// 2. Hàm xử lý gói tin
int xdp_firewall(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet Header
    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    // Chỉ bắt gói IP (IPv4)
    if (eth->h_proto != b htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP Header
    struct iphdr *iph = data + sizeof(*eth);
    if ((void*)iph + sizeof(*iph) > data_end)
        return XDP_PASS;

    // Lấy Source IP
    u32 src_ip = iph->saddr;

    // 3. Tra cứu trong Map (Signature Matching)
    u8 *rule_exists = blacklist.lookup(&src_ip);
    
    if (rule_exists) {
        // Nếu khớp mẫu: Ghi log và DROP
        // bpf_trace_printk là hàm debug, sẽ bắn log về Python
        bpf_trace_printk("PHAT HIEN BAT THUONG! Block IP: %x\n", src_ip);
        return XDP_DROP;
    }

    return XDP_PASS;
}