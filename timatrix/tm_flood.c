#include <linux/module.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <linux/memory.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <net/tcp.h>

#include <tifilter/tifilter_hook.h>
#include <tifilter/tifilter_notifier.h>

MODULE_LICENSE("GPL");

enum {
    TM_MODE_DISABLE,
    TM_MODE_DETECT,
    TM_MODE_BLOCK,
};

enum {
    TM_FLOOD_TYPE_SYN = 0,
    TM_FLOOD_TYPE_MAX
};

static struct {
    char name[32];
    int mode;
    int count;
    int interval;
    int timeout;
} tm_flood_args[TM_FLOOD_TYPE_MAX] = {
    [TM_FLOOD_TYPE_SYN] = {
        .name = "SYN flood",
        .mode = TM_MODE_BLOCK,
        .count = 100,
        .interval = 1,
        .timeout = 10,
    },
};

struct flood_entry {
    struct hlist_node list;

    spinlock_t lock;

    int ifindex;
    __be32 saddr;
    __be32 daddr;
    __be16 dport;

    uint32_t      count;
    unsigned long tstamp;
    int block;
};

#define HASHSZ 256

static struct hlist_head flood_htable[HASHSZ];
static DEFINE_RWLOCK(flood_htable_lock);

inline static unsigned int
hashfn(int ifindex, __be32 saddr, __be32 daddr)
{
    return jhash_3words(ifindex, saddr, daddr, 0) % HASHSZ;
}

inline static int
tuple_compare(struct flood_entry *a, struct tf_tuple *tuple)
{
    int ret;

    ret = tuple->ifindex - a->ifindex;
    if (ret != 0)
        return ret;

    ret = tuple->src.n.ip - a->saddr;
    if (ret != 0)
        return ret;

    ret = tuple->dst.n.ip - a->daddr;
    if (ret != 0)
        return ret;

    return 0;
}

static struct flood_entry *
flood_entry_insert(struct tf_tuple *tuple)
{
    struct flood_entry *elem;
    unsigned int h;

    h = hashfn(tuple->ifindex, tuple->src.n.ip, tuple->dst.n.ip);

    write_lock(&flood_htable_lock);
    hlist_for_each_entry(elem, &flood_htable[h], list) {
        if (tuple_compare(elem, tuple) == 0) {
            write_unlock(&flood_htable_lock);
            return elem;
        }
    }

    elem = kzalloc(sizeof(struct flood_entry), GFP_KERNEL);
    if (elem == NULL) {
        printk(KERN_ERR "%s: Can't alloc memory!\n", __FUNCTION__);
        write_unlock(&flood_htable_lock);
        return NULL;
    }

    INIT_HLIST_NODE(&elem->list);
    spin_lock_init(&elem->lock);

    elem->ifindex = tuple->ifindex;
    elem->saddr = tuple->src.n.ip;
    elem->daddr = tuple->dst.n.ip;
    elem->dport = tuple->dst.t.tcp.port;
    hlist_add_head(&elem->list, &flood_htable[h]);

    write_unlock(&flood_htable_lock);

    return elem;
}

static struct flood_entry *
flood_htable_lookup(struct tf_tuple *tuple)
{
    struct flood_entry *elem;
    unsigned int h;

    h = hashfn(tuple->ifindex, tuple->src.n.ip, tuple->dst.n.ip);

    read_lock(&flood_htable_lock);
    hlist_for_each_entry(elem, &flood_htable[h], list) {
        if (tuple_compare(elem, tuple) == 0) {
            read_unlock(&flood_htable_lock);
            return elem;
        }
    }
    read_unlock(&flood_htable_lock);

    return flood_entry_insert(tuple);
}

static void
flood_htable_clear(void)
{
    int i;

    for (i = 0; i < HASHSZ; i++) {
        struct flood_entry *elem;
        struct hlist_node *pos;

        write_lock(&flood_htable_lock);
        hlist_for_each_entry_safe(elem, pos, &flood_htable[i], list) {
            hlist_del(&elem->list);
            kfree(elem);
        }
        write_unlock(&flood_htable_lock);
    }
}

static unsigned int
packet_in(struct sk_buff *skb,
          const struct net_device *in,
          struct tf_tuple *tuple)
{
    struct tcphdr *tcph = NULL;
    struct flood_entry *elem;
    int index;

    if (tuple->protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        if ((tcp_flag_word(tcph) & TCP_FLAG_SYN) == TCP_FLAG_SYN) {
            if (tm_flood_args[TM_FLOOD_TYPE_SYN].mode == TM_MODE_DISABLE)
                goto skip;
            index = TM_FLOOD_TYPE_SYN;
        } else {
            goto skip;
        }
    } else {
        goto skip;
    }

    elem = flood_htable_lookup(tuple);
    if (elem == NULL) {
        goto skip;
    }

    spin_lock(&elem->lock);
    if (elem->block) {
        if (time_after(jiffies, elem->tstamp + (tm_flood_args[index].timeout * HZ))) {
            goto reset;
        }
        goto detect;
    }

    if (time_after(jiffies, elem->tstamp + (tm_flood_args[index].interval * HZ))) {
        goto reset;
    }

    if (++(elem->count) < tm_flood_args[index].count) {
        goto skip_unlock;
    }

    elem->block = 1;
    printk(KERN_ERR "%s attack found %pI4 -> %pI4\n",
           tm_flood_args[index].name,
           &elem->saddr, &elem->daddr);

    tf_notifier_call(TF_MSG_FILTER_ADD, NULL);

detect:
    elem->tstamp = jiffies;
    (elem->count)++;
    spin_unlock(&elem->lock);

    return tm_flood_args[index].mode != TM_MODE_BLOCK ? TF_ACCEPT : TF_DROP;

reset:
    elem->tstamp = jiffies;
    elem->count  = 1;
    elem->block  = 0;
skip_unlock:
    spin_unlock(&elem->lock);
skip:
    return TF_ACCEPT;
}

static struct tf_hook_ops hook_ops[] = {
    {
        .hook     = packet_in,
        .owner    = THIS_MODULE,
        .pf       = TF_PROTO_IPV4,
        .priority = 1,
    }
};

static int __init
flood_init(void)
{
    int i, ret;

    for (i = 0; i < HASHSZ; i++)
        INIT_HLIST_HEAD(&flood_htable[i]);

    ret = tf_register_hooks(hook_ops, ARRAY_SIZE(hook_ops));
    if (ret < 0) {
        pr_err("Can't register tifilter hook\n");
        goto err;
    }

    return 0;

err:
    return ret;
}
module_init(flood_init);

static void __exit
flood_exit(void)
{
    tf_unregister_hooks(hook_ops, ARRAY_SIZE(hook_ops));

    flood_htable_clear();
}
module_exit(flood_exit);
