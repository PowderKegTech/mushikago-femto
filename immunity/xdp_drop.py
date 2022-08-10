from bcc import BPF
import sys
import time
from ast import literal_eval

def decimal_to_human(input_value):
  input_value = int(input_value)
  hex_value = hex(input_value)[2:]
  pt3 = literal_eval((str('0x'+str(hex_value[-2:]))))
  pt2 = literal_eval((str('0x'+str(hex_value[-4:-2]))))
  pt1 = literal_eval((str('0x'+str(hex_value[-6:-4]))))
  pt0 = literal_eval((str('0x'+str(hex_value[-8:-6]))))
  result = str(pt3)+'.'+str(pt2)+'.'+str(pt1)+'.'+str(pt0)
  return result



bpf_text = """
#define KBUILD_MODNAME "xdp_drop"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <uapi/linux/ptrace.h>

//BPF_HASH(dropcnt, u32, u32);
BPF_HASH(dropcnt, u16, u32);

//struct data_t {
//    char tcp_data[128];
//};
//BPF_PERF_OUTPUT(events);

int xdp_drop_icmp(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;
    u32 value = 0, *vp;
    u32 protocol;
    u32 src, dst;
    u16 src_port, dst_port;
    u64 nh_off = sizeof(*eth);

    if (data + nh_off > data_end)
        return XDP_PASS;

    if (eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *iph = data + nh_off;
        if ((void*)&iph[1] > data_end)
            return XDP_PASS;

        protocol = iph->protocol;
        //if (protocol == 1) {
        //    src = iph->saddr;
        //    dst = iph->daddr;
        //    //vp = dropcnt.lookup_or_init(&protocol, &value);
        //    vp = dropcnt.lookup_or_init(&src, &value);
        //    *vp += 1;
        //    //return XDP_DROP;
        //    return XDP_PASS;
        //} else if (protocol == 6) {

        if (protocol == 6) {
            //data += iph->ihl * 4;
            struct tcphdr *tcph = data + nh_off + iph->ihl * 4;
            int payload_len = ntohs(iph->tot_len) - (tcph->doff*4 + iph->ihl*4);
            //int payload_len = ntohs(iph->tot_len) - ((tcph->doff << 2) + (iph->ihl << 2));
            int tcp_len = ntohs(iph->tot_len) - (iph->ihl << 2);

            if (tcph + 1 > (struct tcphdr *)data_end) {
                return XDP_DROP;
            }

            src = iph->saddr;
            dst = iph->daddr;
            src_port = ntohs(tcph->source);
            dst_port = ntohs(tcph->dest);

            //vp = dropcnt.lookup_or_init(&protocol, &value);
            vp = dropcnt.lookup_or_init(&src_port, &value);
            *vp += 1;
            //return XDP_DROP;

            //events.perf_submit(ctx, &raw, sizeof(struct data_t));
            unsigned int datalen = data_end - data;
            unsigned int ether_len = (void *)iph - (void *)eth;
            void *payload_addr = (void *)eth + ether_len + (iph->ihl << 2) + (tcph->doff << 2);
            //struct data_t *payload_addr = (void *)eth + ether_len + (iph->ihl << 2) + (tcph->doff << 2);
            
            if ((payload_len > 0) && ((int)src_port == 54810)) {
                bpf_trace_printk("data = %p, data_end = %p\\n", data, data_end);
                bpf_trace_printk("datalen = %d\\n", datalen);
                bpf_trace_printk("ether_addr = %p\\n", eth);
                bpf_trace_printk("iph_addr = %p\\n", iph);
                bpf_trace_printk("tcph_addr = %p\\n", tcph);
                bpf_trace_printk("ether_header_len = %u\\n", ether_len);
                bpf_trace_printk("ip_header_len = %u\\n", iph->ihl<<2);
                bpf_trace_printk("tcp_header_len = %u\\n", tcph->doff<<2);
                bpf_trace_printk("tcp_header_len2 = %u\\n", (void *)payload_addr - (void *)tcph);
                bpf_trace_printk("ip_len = %d\\n", ntohs(iph->tot_len));
                bpf_trace_printk("tcp_len = %d\\n", tcp_len);
                bpf_trace_printk("payload_len = %d\\n", payload_len);
                bpf_trace_printk("payload_offset = %d\\n", ether_len + (iph->ihl << 2) + (tcph->doff << 2));
                bpf_trace_printk("payload_addr = %p\\n", payload_addr);
                bpf_trace_printk("payload_data = %x\\n", payload_addr);
                bpf_trace_printk("payload_data = %d\\n", *tcph);
                bpf_trace_printk("payload_data = %d\\n", tcph->source);
                bpf_trace_printk("payload_data = %d\\n", payload_addr);
                bpf_trace_printk("payload_data = %s\\n", payload_addr);
                bpf_trace_printk("src_port = %d\\n", src_port);
                bpf_trace_printk("dst_port = %d\\n", dst_port);
                bpf_trace_printk("tcp_data = %x\\n", tcph->source);
                bpf_trace_printk("tcp_data = %x\\n", tcph->dest);

                int a = 100;
                
                int *aa = &a;
                bpf_trace_printk("a = %d\\n", a);
                bpf_trace_printk("aa = %d\\n", *aa);

                unsigned long p;
                p = load_byte(payload_addr, 0);
                //if (p == "H") {
                //    bpf_trace_printk("OKOKOKOK\\n");
                //} else {
                //    bpf_trace_printk("aaaaaa\\n");
                //}

                //int i;
                //for (i = 0; i < payload_len; i+=4) {
                //    bpf_trace_printk("payload = %x\\n", *(payload_addr+i));
                //}
            }

            return XDP_PASS;
        } else if (protocol == 17) {
            //data += iph->ihl * 4;
            data += sizeof(struct iphdr);
            struct udphdr *udph = data;
            src = iph->saddr;
            dst = iph->daddr;
            src_port = udph->source;
            dst_port = udph->dest;
            //vp = dropcnt.lookup_or_init(&protocol, &value);
            vp = dropcnt.lookup_or_init(&dst_port, &value);
            *vp += 1;
            //return XDP_DROP;
            return XDP_PASS;
        }
    }

  return XDP_PASS;
}
"""

b = BPF(text=bpf_text)
fn = b.load_func("xdp_drop_icmp", BPF.XDP)

device = sys.argv[1]
b.attach_xdp(device, fn)
dropcnt = b.get_table("dropcnt")

#def print_event(cpu, data, size):
#  event = b["events"].event(data)
#  print("{} {} {}".format(time.strftime("%H:%M:%S"), event.pid, event.comm.decode()))
#
#b["events"].open_perf_buffer(print_event)

while True:
  try:
    dropcnt.clear()
    time.sleep(1)
    for k, v in dropcnt.items():
      print("{} {}: {} pkt/s".format(time.strftime("%H:%M:%S"), k.value, v.value))
      #print("{} {}: {} pkt/s".format(time.strftime("%H:%M:%S"), decimal_to_human(k.value), v.value))
    #b.perf_buffer_poll()
    b.trace_print()
  except KeyboardInterrupt:
    break
  except ValueError:
    continue

b.remove_xdp(device)
