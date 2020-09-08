#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/if_ether.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>

#include <tifilter/tifilter_hook.h>

struct list_head tf_hooks[TF_MAX_HOOKS] __read_mostly;
EXPORT_SYMBOL(tf_hooks);
static DEFINE_MUTEX(tf_hooks_mutex);

int
tf_register_hook(struct tf_hook_ops *reg)
{
    struct tf_hook_ops *elem;
    int err;

    err = mutex_lock_interruptible(&tf_hooks_mutex);
    if (err < 0)
        return err;

    list_for_each_entry(elem, &tf_hooks[reg->pf], list) {
        if (reg->priority < elem->priority)
            break;
    }
    list_add_rcu(&reg->list, elem->list.prev);
    mutex_unlock(&tf_hooks_mutex);

    return 0;
}
EXPORT_SYMBOL(tf_register_hook);

void
tf_unregister_hook(struct tf_hook_ops *reg)
{
    mutex_lock(&tf_hooks_mutex);
    list_del_rcu(&reg->list);
    mutex_unlock(&tf_hooks_mutex);

    synchronize_net();
}
EXPORT_SYMBOL(tf_unregister_hook);

int
tf_register_hooks(struct tf_hook_ops *reg, unsigned int n)
{
    unsigned int i;
    int err = 0;

    for (i = 0; i < n; i++) {
        err = tf_register_hook(&reg[i]);
        if (err)
            goto err;
    }
    return 0;

err:
    if (i < 0) {
        tf_unregister_hooks(reg, i);
    }
    return err;
}
EXPORT_SYMBOL(tf_register_hooks);

void
tf_unregister_hooks(struct tf_hook_ops *reg, unsigned int n)
{
    while (n-- > 0)
        tf_unregister_hook(&reg[n]);
}
EXPORT_SYMBOL(tf_unregister_hooks);

static inline void
tf_parse_tuple(struct sk_buff *skb, struct tf_tuple *tuple)
{
    struct ethhdr *ehdr;

    ehdr = eth_hdr(skb);

    tuple->etype = skb->protocol;
    memcpy(&tuple->src.h.all, &ehdr->h_source, ETH_HLEN);
    memcpy(&tuple->dst.h.all, &ehdr->h_dest,  ETH_HLEN);

    if (skb->protocol == htons(ETH_P_ARP)) {
        return;
    }

    if (skb->protocol == htons(ETH_P_IP)) {
        struct iphdr *iph = ip_hdr(skb);
        struct tcphdr *thdr;
        struct icmphdr *ihdr;

        tuple->protocol = iph->protocol;
        tuple->src.n.ip = iph->saddr;
        tuple->dst.n.ip = iph->daddr;

        switch (iph->protocol) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
            thdr = tcp_hdr(skb);
            tuple->src.t.tcp.port = thdr->source;
            tuple->dst.t.tcp.port = thdr->dest;
            break;
        case IPPROTO_ICMP:
            ihdr = icmp_hdr(skb);
            tuple->src.t.icmp.type = ihdr->type;
            tuple->src.t.icmp.code = ihdr->code;
            break;
        }

        return;
    }
}

static unsigned int
tf_iterate(struct list_head *head,
           struct sk_buff *skb,
           const struct net_device *indev,
           struct tf_hook_ops **elemp,
           int hook_thresh)
{
    unsigned int verdict;
    struct tf_tuple tuple;

    tuple.ifindex = indev->ifindex;
    tf_parse_tuple(skb, &tuple);

    list_for_each_entry_continue_rcu((*elemp), head, list) {
        if (hook_thresh > (*elemp)->priority)
            continue;

repeat:
        verdict = (*elemp)->hook(skb, indev, &tuple);
        if (verdict != TF_ACCEPT) {
            if (verdict != TF_REPEAT)
                return verdict;
            goto repeat;
        }
    }

    return TF_ACCEPT;
}

int
tf_hook_slow(u_int8_t pf, struct sk_buff *skb,
             struct net_device *indev, int hook_thresh)
{
    struct tf_hook_ops *elem;
    struct list_head *tf_hook_list;
    unsigned int verdict;

    rcu_read_lock();

    tf_hook_list = &tf_hooks[pf];

    elem = list_entry_rcu(tf_hook_list, struct tf_hook_ops, list);

    verdict = tf_iterate(&tf_hooks[pf], skb, indev, &elem, hook_thresh);
    if (verdict == TF_ACCEPT || verdict == TF_STOP) {
        goto unlock;
    }
unlock:
    rcu_read_unlock();

    return verdict;
}
EXPORT_SYMBOL(tf_hook_slow);

int
tifilter_hook_init(void)
{
    int i;

    for (i = 0; i < TF_MAX_HOOKS; i++) {
        INIT_LIST_HEAD(&tf_hooks[i]);
    }

    return 0;
}

void
tifilter_hook_exit(void)
{
}
