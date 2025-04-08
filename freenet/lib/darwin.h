#ifndef FDSL_DARWIN_H
#define FDSL_DARWIN_H

#include<stddef.h>

int open_tun_socket (char *ifname,size_t ifname_len,int o_nonblock_flags);
void close_tun_socket(int fd);

#endif