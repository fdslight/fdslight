#include<string.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<sys/socket.h>

#include "netutils.h"

/// 增加SSE2指令支持
#ifdef __x86_64__
#include<emmintrin.h>
/// 使用SSE2指令集优化IPv6子网计算
static inline
int subnet_calc_with_msk_for_ipv6(unsigned char *address,unsigned char *msk,unsigned char *res)
{
	__m128i *mem_addr=(__m128i *)res;
	__m128i *xa=(__m128i *)address;
	__m128i *xb=(__m128i *)msk;

    __m128i a=_mm_loadu_si128(xa);
    __m128i b=_mm_loadu_si128(xb);

    a=_mm_and_si128(a,b);

    _mm_storeu_si128(mem_addr,a);

    return 0;
}
#endif

/// ARM NEON指令支持
#ifdef __aarch64__
#include<arm_neon.h>
/// 使用neon优化IPv6子网计算
static inline
int subnet_calc_with_msk_for_ipv6(unsigned char *address,unsigned char *msk,unsigned char *res)
{
    uint8x16_t ra=vld1q_u8(address);
    uint8x16_t rb=vld1q_u8(msk);

    ra=vandq_u8(ra,rb);
    vst1q_u8(res,ra);

    return 0;
}

#endif


int msk_calc(unsigned char prefix,int is_ipv6,unsigned char *res)
{
    unsigned char a,b,constant=0xff;
    unsigned char tables[]={
        0,128,192,224,240,248,252,254,255
    };

    if(is_ipv6 && prefix>128) return -1;
    if(!is_ipv6 && prefix>32) return -1;

    // 计算出掩码
    a=prefix / 8;
    b=prefix % 8;

    if(is_ipv6) bzero(res,16);
    else bzero(res,4);

    for(int n=0;n<a;n++){
        res[n]=constant;
    }
    
    if(b) res[a]=tables[b];

    return 0;
}

int subnet_calc_with_prefix(unsigned char *address,unsigned char prefix,int is_ipv6,unsigned char *res)
{
    unsigned char msk[16];
    int rs=msk_calc(prefix,is_ipv6,msk);
    if(rs<0) return -1;

    return subnet_calc_with_msk(address,msk,is_ipv6,res);
}

inline 
int subnet_calc_with_msk(unsigned char *address,unsigned char *msk,int is_ipv6,unsigned char *res)
{
    size_t size=4;

    if(is_ipv6){
#ifdef __x86_64__
        return subnet_calc_with_msk_for_ipv6(address,msk,res);
#elif defined(__aarch64__)
        return subnet_calc_with_msk_for_ipv6(address,msk,res);
#else
        size=16;
#endif
    }
    for(size_t n=0;n<size;n++){
        res[n]= address[n] & msk[n];
    }
    return 0;
}

inline 
unsigned short csum_calc_incre(unsigned short old_field,unsigned short new_field,unsigned short old_csum)
{
    unsigned long csum = old_csum - (~old_field & 0xFFFF) - new_field ;
    csum = (csum >> 16) + (csum & 0xffff);
    csum +=  (csum >> 16);
    return csum;
}

unsigned short csum_calc(unsigned short *buffer,size_t size)
{
    unsigned long sum;
    
    sum = 0;

    while (size > 1) {
        sum += *buffer++;
        size -= 2;
    }
    
    if (size) sum += *(unsigned char *)buffer;
    while (sum >> 16) sum  = (sum & 0xffff) + (sum >> 16);

    return (unsigned short)(~sum);
}


int build_ipv4_header(struct netutil_iphdr *iphdr,const char options[][40],unsigned char every_opt_len[],void *res)
{
    struct netutil_iphdr *t=res;
    unsigned short header_len=sizeof(struct netutil_iphdr),csum;
    unsigned char *s=res;

    memcpy(res,iphdr,sizeof(struct netutil_iphdr));

    s=res+sizeof(struct netutil_iphdr);

    t->ver_and_ihl= (4 & 0xff) << 4;
    t->checksum=0;

    for(int n=0;;n++){
        // 检查长度是否为0
        if(!every_opt_len[n]) break;
        if(every_opt_len[n]>40) return -1;

        memcpy(s,options[n],every_opt_len[n]);

        header_len+=every_opt_len[n];
        s+=every_opt_len[n];
    }

    if(header_len>60) return -1;
    t->ver_and_ihl|=(header_len & 0xff); 

    csum=csum_calc((unsigned short *)res,header_len);
    t->checksum=htons(csum);

    return 0;
}

/// 构建UDP或者UDPLite数据包
char *build_udp_packet(\
unsigned char *src_addr,unsigned char *dst_addr,unsigned short src_port,unsigned short dst_port,\
char *user_data,unsigned short user_data_len,char *res,int *offset,int is_ipv6,\
int is_udplite,int udplite_csum_coverage)
{

    unsigned char protocol=is_udplite?136:17;
    unsigned short csum=0,length;
    unsigned char *s=NULL;
    int size=0;

    struct pseudo_header{
        unsigned char src_addr[4];
        unsigned char dst_addr[4];
        unsigned char __pad;
        unsigned char protocol;
        unsigned short length;
    } header;

    struct pseudo_header6{
        unsigned char src_addr[16];
        unsigned char dst_addr[16];
        unsigned char __pad;
        unsigned char protocol;
        unsigned short length;
    } header6;

    struct udphdr{
        unsigned short src_port;
        unsigned short dst_port;
        union{
            // UDP
            unsigned short length;
            // UDPLite
            unsigned short checksum_coverage;
        };
        unsigned short checksum;
    } *udphdr;

    // 限制数据包最大值以及最小值
    if(user_data_len>65535 || user_data_len<1) return NULL;

    src_port=htons(src_port);
    dst_port=htons(dst_port);
    length=htons(user_data_len);

    if(is_ipv6) {
        memcpy(header6.src_addr,src_addr,16);
        memcpy(header6.dst_addr,dst_addr,16);

        header6.__pad=0;
        header6.protocol=protocol;
        header6.length=length;

        s=(unsigned char *)(&header6);
        size=sizeof(struct pseudo_header6);
    }else {
        memcpy(header.src_addr,src_addr,4);
        memcpy(header.dst_addr,dst_addr,4);

        header.__pad=0;
        header.protocol=protocol;
        header.length=length;

        s=(unsigned char *)(&header);
        size=sizeof(struct pseudo_header);
    }

    udphdr=(struct udphdr *)(res+size);

    udphdr->src_port=src_port;
    udphdr->dst_port=dst_port;
    udphdr->length=length;
    udphdr->checksum=0;

    memcpy(res,s,size);
    memcpy(res+size,&udphdr,8);
    memcpy(res+size+8,user_data,user_data_len);

    if(is_udplite){
        csum=0;
    }else{
        csum=csum_calc((unsigned short *)s,size+8+user_data_len);
        udphdr->checksum=htons(csum);
    }

    *offset=size;

    return res+size;
}

/// 检查是否是IPv4地址
int is_ipv4_address(const char *address)
{
    struct in_addr s;
    int rs=inet_pton(AF_INET,address,(void *)&s);

    rs=rs>0?1:0;

    return rs;
}

/// 检查是否是IPv6地址
int is_ipv6_address(const char *address)
{
    struct in6_addr s;

    int rs=inet_pton(AF_INET6,address,(void *)&s);

    rs=rs>0?1:0;

    return rs;
}

int is_valid_port(const char *s)
{
    int port=atoi(s);

    if(port<1 || port>0xffff) return 0;

    return 1;
}

int check_ippkt_is_ok(struct netutil_iphdr *iphdr)
{
    return 1;
}


void rewrite_ip_addr(struct netutil_iphdr *iphdr,unsigned char *new_addr,int is_src)
{
    unsigned char *addr=is_src?iphdr->src_addr:iphdr->dst_addr;
    unsigned short csum=iphdr->checksum;
    unsigned short *u16_addr=(unsigned short *)addr;
    unsigned short *u16_new_addr=(unsigned short *)new_addr;
    unsigned short offset;
    int hdr_len=((iphdr->ver_and_ihl) & 0x0f) * 4;
    struct netutil_udphdr *udphdr;
    struct netutil_tcphdr *tcphdr;


    for(int n=0;n<2;n++) csum=csum_calc_incre(*u16_addr++,*u16_new_addr++,csum);
    
    iphdr->checksum=csum;
    
    // 只修改第一个分片的TCP以及UDP
    offset=htons(iphdr->frag_info) & 0x1fff;
    if(offset!=0) goto __NETUTIL_COPY_ADDR;

    // 重置指针位置
    u16_addr=(unsigned short *)addr;
    u16_new_addr=(unsigned short *)new_addr;

    // 对TCP/UDP的检验和进行计算
    switch(iphdr->protocol){
        case 6:
            tcphdr=(struct netutil_tcphdr *)(((char *)iphdr)+hdr_len);
            csum=tcphdr->csum;
            for(int n=0;n<2;n++) csum=csum_calc_incre(*u16_addr++,*u16_new_addr++,csum);
            tcphdr->csum=csum;
            break;
        case 17:
            udphdr=(struct netutil_udphdr *)(((char *)iphdr)+hdr_len);
            csum=udphdr->checksum;
            for(int n=0;n<2;n++) csum=csum_calc_incre(*u16_addr++,*u16_new_addr++,csum);
            udphdr->checksum=csum;
            break;
    }

__NETUTIL_COPY_ADDR:
    if(is_src) memcpy(iphdr->src_addr,new_addr,4);
    else memcpy(iphdr->dst_addr,new_addr,4);
}

void rewrite_ip6_addr(struct netutil_ip6hdr *ip6hdr,unsigned char *new_addr,int is_src)
{
    unsigned char old_addr[16];
    unsigned char *csum_ptr=NULL;
    unsigned short csum;
    unsigned char *ptr=(unsigned char *)(ip6hdr);
    unsigned short *old_u16addr,*new_u16addr=(unsigned short *)new_addr;
    unsigned char next_header=ip6hdr->next_header;
    struct netutil_ip6_frag_header *frag_header;

    int flags=1;
    int x=40;

    if(is_src) {
        memcpy(old_addr,ip6hdr->src_addr,16);
        memcpy(ip6hdr->src_addr,new_addr,16);
    }else{
        memcpy(old_addr,ip6hdr->dst_addr,16);
        memcpy(ip6hdr->dst_addr,new_addr,16);    
    }

    old_u16addr=(unsigned short *)(old_addr);

    if(next_header==44){
        frag_header=(struct netutil_ip6_frag_header *)(((char *)ip6hdr)+40);
        next_header=frag_header->next_header;
        x+=8;
    }

    switch(next_header){
        case 6:
            csum_ptr=ptr+x+16;
            break;
        case 17:
            csum_ptr=ptr+x+6;
            break;
        case 44:
            break;
        case 58:
            csum_ptr=ptr+x+2;
            break;
        default:
            flags=0;
            break;
    }

    // 不需要重写传输层校验和直接跳过
    if(!flags) return;

    memcpy(&csum,csum_ptr,2);

    for(int n=0;n<8;n++){
        csum=csum_calc_incre(*old_u16addr++,*new_u16addr++,csum);
    }

    memcpy(csum_ptr,&csum,2);
}

int is_same_subnet(unsigned char *address,unsigned char *subnet,unsigned char prefix,int is_ipv6)
{
    unsigned char tmp_addr[16];
    int size=is_ipv6?16:4;

    subnet_calc_with_prefix(address,prefix,is_ipv6,tmp_addr);

    if(memcmp(tmp_addr,subnet,size)) return 0;

    return 1;
}

int is_same_subnet_with_msk(unsigned char *address,unsigned char *subnet,unsigned char *mask,int is_ipv6)
{
    unsigned char tmp_addr[16];
    int size=is_ipv6?16:4;
    subnet_calc_with_msk(address,mask,is_ipv6,tmp_addr);
    
    if(memcmp(tmp_addr,subnet,size)) return 0;

    return 1;
}