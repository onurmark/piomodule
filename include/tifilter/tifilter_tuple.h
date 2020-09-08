#ifndef _TIFILTER_TIFILTER_TUPLE_H
#define _TIFILTER_TIFILTER_TUPLE_H 1

#include <linux/in.h>
#include <linux/in6.h>

union tf_hw_addr {
    __u8 all[6];
};

union tf_arp_addr {
    __u8 all[6];
};

union tf_inet_addr {
    __u32  all[4];
    __be32 ip;
    __be32 ip6[4];
    struct in_addr in;
    struct in6_addr in6;
};

union tf_appl_addr {
    __be16 all;
    struct {
        __be16 port;
    } tcp;
    struct {
        __be16 port;
    } udp;
    struct {
        u_int8_t type, code;
    } icmp;
    struct {
        u_int8_t op;
    } arp;
};

struct tf_tuple {
    int ifindex;

    u_int16_t etype;
    u_int8_t  protocol;

    struct {
        union tf_hw_addr   h;
        union tf_arp_addr  arp;
        union tf_inet_addr n;
        union tf_appl_addr t;
    } src, dst;
};
#endif /* ifndef _TIFILTER_TIFILTER_TUPLE_H */
