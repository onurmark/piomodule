#ifndef _TIFILTER_TIFILTER_HOOK_H
#define _TIFILTER_TIFILTER_HOOK_H 1

#include <linux/init.h>
#include <linux/netdevice.h>

#include <tifilter/tifilter_tuple.h>

#define TF_DROP        0
#define TF_ACCEPT      1
#define TF_REPEAT      2
#define TF_SKIP        3
#define TF_STOP        4
#define TF_MAX_VERDICT TF_STOP

#define TF_MAX_HOOKS   8

#define TF_PROTO_IPV4  0
#define TF_PROTO_IPV6  1
#define TF_PROTO_TCP   2
#define TF_PROTO_UDP   3
#define TF_PROTO_ICMP  4
#define TF_PROTO_ARP   5
#define TF_PROTO_MAC   6

enum {
    TF_PRI_FIRST  = INT_MIN,
    TF_PRI_FILTER = 0,
    TF_PRI_LAST   = INT_MAX
};

struct sk_buff;

typedef unsigned int tf_hookfn(struct sk_buff *skb,
                               const struct net_device *in,
                               struct tf_tuple *tuple);

struct tf_hook_ops {
    struct list_head list;

    tf_hookfn *hook;
    struct module *owner;
    int pf;
    int priority;
};

int
tf_hook_slow(u_int8_t pf, struct sk_buff *skb,
             struct net_device *indev, int hook_thresh);

extern struct list_head tf_hooks[TF_MAX_HOOKS];

static inline bool
tf_hook_active(u_int8_t pf)
{
    return !list_empty(&tf_hooks[pf]);
}

static inline int
tf_hook_thresh(u_int8_t pf,
               struct sk_buff *skb,
               struct net_device *indev,
               int thresh)
{
    if (tf_hook_active(pf))
        return tf_hook_slow(pf, skb, indev, thresh);

    return 1;
}

static inline int
tf_hook(u_int8_t pf,
        struct sk_buff *skb,
        struct net_device *indev)
{
    return tf_hook_thresh(pf, skb, indev, INT_MIN);
}

static inline int
TF_HOOK_COND(u_int8_t pf,
             struct sk_buff *skb,
             struct net_device *indev,
             bool cond)
{
    int ret;

    if (cond) {
        ret = tf_hook_thresh(pf, skb, indev, INT_MIN);
    }

    return ret;
}

static inline int
TF_HOOK(u_int8_t pf,
        struct sk_buff *skb,
        struct net_device *indev)
{
    return tf_hook_thresh(pf, skb, indev, INT_MIN);
}

int
tf_register_hook(struct tf_hook_ops *reg);

void
tf_unregister_hook(struct tf_hook_ops *reg);

int
tf_register_hooks(struct tf_hook_ops *reg, unsigned int n);

void
tf_unregister_hooks(struct tf_hook_ops *reg, unsigned int n);

int
tifilter_hook_init(void);

void
tifilter_hook_exit(void);

#endif /* ifndef _TIFILTER_TIFILTER_HOOK_H */
