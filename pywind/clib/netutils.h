#ifndef __NETUTILS_H
#define __NETUTILS_H
#include<sys/types.h>
#include<arpa/inet.h>

struct netutil_iphdr{
    unsigned char ver_and_ihl;
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_info;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned char src_addr[4];
    unsigned char dst_addr[4];
};

struct netutil_ip_ps_header{
    unsigned char src_addr[4];
    unsigned char dst_addr[4];
    unsigned char pad[1];
    unsigned char protocol;
    unsigned short length;
};

struct netutil_ip6hdr{
    unsigned char ver_and_tc;
    unsigned char flow_label[3];
    unsigned short payload_len;
    unsigned char next_header;
    unsigned char hop_limit;
    unsigned char src_addr[16];
    unsigned char dst_addr[16];
};

/// IPv6伪首部
struct netutil_ip6_ps_header{
    unsigned char src_addr[16];
    unsigned char dst_addr[16];
    unsigned int length;
    unsigned char pad[3];
    unsigned char next_header;
};

/// IPv6分片头部
struct netutil_ip6_frag_header{
    unsigned char next_header;
    unsigned char reserved;
    unsigned short frag_off;
    unsigned int id;
};

struct netutil_udphdr{
    unsigned short src_port;
    unsigned short dst_port;
    union 
    {
        unsigned short length;
        unsigned short csum_coverage;
    };
    unsigned short checksum;
};

struct netutil_tcphdr{
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int seq_num;
    unsigned int ack_num;
    unsigned short header_len_and_flag;
    unsigned short win_size;
    unsigned short csum;
    unsigned short urgent_pointer;
};

#pragma pack(push)
#pragma pack(1)
struct netutil_icmphdr{
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
};

struct netutil_icmpecho{
    struct netutil_icmphdr icmphdr;
    unsigned short id;
    unsigned short seq_num;
};

struct netutil_icmpv6hdr{
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
};

struct netutil_icmpv6echo{
    struct netutil_icmpv6hdr icmpv6hdr;
    unsigned short id;
    unsigned short seq_num;
};

#pragma pack(pop)

#define IPv6_HEADER_SET(ip6_header,traffic_cls,flw_label,payload_length,next_hdr,hop,src_ipaddr,dst_ipaddr) \
ip6_header->ver_and_tc= 0x60 | (traffic_cls & 0xf0 >>4);\
ip6_header->flow_label[0]=(traffic_cls & 0x0f) << 4;\
ip6_header->flow_label[0]=ip6_header->flow_label[0] | ((flw_label & 0x0f0000) >> 16);\
ip6_header->flow_label[1]= (flw_label & 0x00ff00) >> 8;\
ip6_header->flow_label[2]= flw_label & 0x0000ff;\
ip6_header->payload_len=htons(payload_length);\
ip6_header->next_header=next_hdr;\
ip6_header->hop_limit=hop;\
memcpy(ip6_header->src_addr,src_ipaddr,16);\
memcpy(ip6_header->dst_addr,dst_ipaddr,16)


/// 计算掩码
int msk_calc(unsigned char prefix,int is_ipv6,unsigned char *res);
/// 计算子网
int subnet_calc_with_prefix(unsigned char *address,unsigned char prefix,int is_ipv6,unsigned char *res);
int subnet_calc_with_msk(unsigned char *address,unsigned char *msk,int is_ipv6,unsigned char *res);

/** calc inrement csum **/
unsigned short csum_calc_incre(unsigned short old_field,unsigned short new_field,unsigned short old_csum);
unsigned short csum_calc(unsigned short *buffer,size_t size);


/// 构建IPv4数据包头部
// 如果opt_len长度为0表示选项结束
int build_ipv4_header(struct netutil_iphdr *iphdr,const char options[][40],unsigned char every_opt_len[],void *res);

/// 构建UDP数据包
// return:返回数据包的大小
char *build_udp_packet(\
unsigned char *src_addr,unsigned char *dst_addr,unsigned short src_port,unsigned short dst_port,\
char *user_data,unsigned short user_data_len,char *res,int *offset,int is_ipv6,\
int is_udplite,int udplite_csum_coverage);

/// 检查是否是IPv4地址
int is_ipv4_address(const char *address);
/// 检查是否是IPv6地址
int is_ipv6_address(const char *address);
/// 是否是合法端口 
int is_valid_port(const char *s);

/// 检查IP头部是否合法
int check_ippkt_is_ok(struct netutil_iphdr *iphdr);

/// 重写IP地址,is_src不为0表示重写源地址,否则重写目标地址
void rewrite_ip_addr(struct netutil_iphdr *iphdr,unsigned char *new_addr,int is_src);
/// 重写IPv6地址
void rewrite_ip6_addr(struct netutil_ip6hdr *ip6hdr,unsigned char *new_addr,int is_src);
/// 检查是否在同一个子网内
int is_same_subnet(unsigned char *address,unsigned char *subnet,unsigned char prefix,int is_ipv6);
int is_same_subnet_with_msk(unsigned char *address,unsigned char *subnet,unsigned char *mask,int is_ipv6);

#endif