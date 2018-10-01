#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <string.h>
#include <arpa/inet.h>  // inet_pton()
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <libnet/libnet-macros.h>
#define LIBNET_LIL_ENDIAN 1
#include <libnet/libnet-headers.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
using namespace std;

uint32_t before_ip, after_ip;
unsigned char *change_data;

// TCP Checksum calculation header
#pragma pack(push,1)
struct pseudo_header{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t reserved = 0;
    uint8_t proto;
    uint16_t tcp_len;
};
#pragma pack(pop)

// for debugging, dump code
void dump(unsigned char *pkt, int len)
{
    printf("\n");
    for(int i = 0; i < len; i++)
    {
        printf("%02X ", pkt[i]);
    }
    printf("\n");
}

uint16_t calc_checksum(uint16_t *data, uint32_t len)
{
    uint8_t oddbyte = 0;
    uint32_t sum = 0;
    while(len > 1)
    {
            sum += ntohs(*data++);
            len -= 2;
    }

    if(len == 1)
    {
        oddbyte = (uint8_t)*data;
        sum += ntohs(oddbyte);
    }

    sum = (sum >> 16) + (sum & 0xffff);

    return (uint16_t)sum;
}

uint16_t checksum(uint8_t *data, uint32_t len, int ch)
{
    if(ch == 0)
    {
        struct pseudo_header pseudoh;
        struct libnet_ipv4_hdr *iph;
        struct libnet_tcp_hdr *tcph;

        // set ip, tcp header
        iph = (struct libnet_ipv4_hdr *)data;
        data += sizeof(struct libnet_ipv4_hdr);
        tcph = (struct libnet_tcp_hdr *)data;
        tcph->th_sum = 0x00;

        // set pseudo header
        memcpy(&pseudoh.src_ip, &iph->ip_src, sizeof(pseudoh.src_ip));
        memcpy(&pseudoh.dst_ip, &iph->ip_dst, sizeof(pseudoh.dst_ip));
        pseudoh.proto = iph->ip_p;
        pseudoh.tcp_len = htons(len - (iph->ip_hl * 4));

        // calc checksum
        uint16_t pseudo_checksum = calc_checksum((uint16_t *)&pseudoh, sizeof(pseudoh));
        uint16_t tcp_checksum = calc_checksum((uint16_t *)tcph, ntohs(pseudoh.tcp_len));

        // change tcp checksum
        uint16_t total_checksum;
        int sum = pseudo_checksum + tcp_checksum;

        total_checksum = (sum >> 16) + (sum & 0xffff);

        total_checksum = ntohs(~total_checksum);
        tcph->th_sum = total_checksum;

        return total_checksum;
    }

    else if(ch == 1)
    {
        // set ip header
        struct libnet_ipv4_hdr * iph;
        iph = (struct libnet_ipv4_hdr *)data;
        iph->ip_sum = 0x00;

        // calc checksum
        uint16_t ip_checksum = calc_checksum((uint16_t *)&iph, sizeof(struct libnet_ipv4_hdr));

        // change ip checksum
        iph->ip_sum = htons(ip_checksum);

        return ip_checksum;
    }
}

static int callback(struct nfq_q_handle *qhandle, struct nfgenmsg *nfmsg,
                    struct nfq_data *nf_data, void *data)
{
    u_int32_t id=0;
    unsigned char *packet;
    int ret;
    struct nfqnl_msg_packet_hdr *ph;

    if((ph = nfq_get_msg_packet_hdr(nf_data)))
        id = ntohl(ph->packet_id);

    ret = nfq_get_payload(nf_data,&packet);
    if(ret > 0)
    {
        change_data = packet;

        struct libnet_ipv4_hdr *iph, *change_iph;
        struct libnet_tcp_hdr *tcph;

        iph = (struct libnet_ipv4_hdr *)packet;
        change_iph = (struct libnet_ipv4_hdr *)change_data;
        packet += sizeof(struct libnet_ipv4_hdr);
        tcph = (struct libnet_tcp_hdr *)packet;

        //  If the destination IP is the same as before_IP, change to after_IP.
        if(iph->ip_p == 6 && (iph->ip_dst.s_addr == before_ip))
        {
            cout << ">>[Request] : Changed dst_ip => before_ip" << endl;

            // change ip
            change_iph->ip_dst.s_addr = after_ip;

            // First. calc IP checksum
            checksum(change_data, ret, 1);

            // Second. calc TCP checksum
            checksum(change_data, ret, 0);

            return nfq_set_verdict(qhandle, id, NF_ACCEPT, ret, change_data);
        }
        // If source IP is after_IP, change to before_IP.
        if(iph->ip_p == 6 && (iph->ip_src.s_addr == after_ip))
        {
            cout << ">>[Reply] : Changed src_ip => after_ip" << endl;

            // change ip
            change_iph->ip_src.s_addr = before_ip;

            // First. calc IP checksum
            checksum(change_data, ret, 1);

            // Second. calc TCP checksum
            checksum(change_data, ret, 0);

            return nfq_set_verdict(qhandle, id, NF_ACCEPT, ret, change_data);
        }

        else
            return nfq_set_verdict(qhandle, id, NF_ACCEPT, 0, NULL);
    }
}

int main(int argc, char **argv)
{
    if(argc != 3)
    {
        printf("Usage : ./ip_change [Before_IP] [After_IP]\n");
        return 0;
    }

    inet_pton(AF_INET, argv[1], &before_ip);
    inet_pton(AF_INET, argv[2], &after_ip);

    struct nfq_handle *handle;
    struct nfq_q_handle *qhandle;
    int fd;
    int rv;
    char pkt[4096];

    printf("opening library handle\n");
    if(!(handle = nfq_open()))
    {
        fprintf(stderr,"nfq_open ERROR\n");
        exit(1);
    }

    if(nfq_unbind_pf(handle,AF_INET) < 0)
    {
        fprintf(stderr,"nfq_unbind_pf ERROR\n");
        exit(1);
    }

    if(nfq_bind_pf(handle,AF_INET) < 0)
    {
        fprintf(stderr,"nfq_bind_pf ERROR\n");
        exit(1);
    }

    if(!(qhandle = nfq_create_queue(handle,0,&callback,NULL)))
    {
        fprintf(stderr,"nfq_create_queue ERROR\n");
        exit(1);
    }

    if(nfq_set_mode(qhandle, NFQNL_COPY_PACKET, 0xffff) <0)
    {
        fprintf(stderr,"can't set packet copy mode");
        exit(1);
    }

    fd = nfq_fd(handle);

    while(true)
    {
        if((rv = recv(fd,pkt,sizeof(pkt),0))>= 0)
        {
            nfq_handle_packet(handle,pkt,rv);
            continue;
        }

        if(rv < 0 && errno == ENOBUFS)
        {
            printf("losing packet!\n");
            continue;
        }

        perror("recv failed!\n");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qhandle);

    printf("closing library handle!\n");
    nfq_close(handle);

}
