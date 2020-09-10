#include <linux/module.h>
#include <linux/version.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

// TiFILTER
#include <tifilter/tifilter_hook.h>
#include <tifilter/tifilter_notifier.h>

MODULE_LICENSE("GPL");

/* Rule */
/*
 * | PROTO | SADDR           | DADDR           | SPORT | DPORT | ext match | priority  | action       |
 * | tcp   | *               | *               | *     | *     | flag syn  | 10        | toTimatrix   | <- 보안 검사 수행
 * | tcp   | 192.168.0.10/32 | 192.168.0.20/32 | *     | *     | flag syn  | 1         | DROP         | <- 공격탐지 차단
 * | tcp   | 192.168.0.10/32 | 192.168.0.20/32 | *     | *     | flag syn  | 1         | ACCEPT       |
 *
 * priority를 가지는 prefix match가 가능한 filter 구조 필요
 * filter_add() notifier - 룰 추가
 * filter_del() notifier - 룰 삭제
 * filter_lookup_and_verdict() 룰을 match하여 action 수행
 *
 * action
 *  - toTimatrix 보안 검사를 위해 TF_HOOK으로 진행
 *  - DROP 패킷을 차단
 *  - ACCEPT 보안 검사 수행하지 않고 허용
 */
static int
filter_lookup_and_verdict(struct sk_buff *skb)
{
    /* 검사하기를 원하는 패킷을 TF_HOOK()으로 인입
     * 예제에서는 모든 IP 패킷을 인입하였지만
     * 실제 프로그램에서는 SYN, ACK 등 필요한 공격 탐지에 필요한 패킷만
     * 입력시켜서 부하를 줄여야 한다.
     *  1. 불필요한 패킷 제외
     *  2. 이미 공격으로 차단된 패킷은 drop
     **/
    return 0;
}

static void
print_debug_skb(struct sk_buff *skb)
{
    printk(KERN_ERR "skb->data: %p, skb->data_len: %u\n",
           skb->data, skb->data_len);

    print_hex_dump(KERN_DEBUG, "skb: ", DUMP_PREFIX_OFFSET,
                   16, 1, skb->data, 120, true);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
static unsigned int
packet_in(const struct nf_hook_ops *ops,
          struct sk_buff *skb,
          const struct net_device *in,
          const struct net_device *out,
          int (*okfn)(struct sk_buff *))
#else
static unsigned int
packet_in(void *priv,
          struct sk_buff *skb,
          const struct nf_hook_state *state)
#endif
{
    int verdict = TF_ACCEPT;

    print_debug_skb(skb);

    if (filter_lookup_and_verdict(skb)) {
        return NF_ACCEPT;
    }

    if (skb->protocol == htons(ETH_P_IP)) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
        verdict = TF_HOOK(TF_PROTO_IPV4, skb, (struct net_device *)in);
#else
        verdict = TF_HOOK(TF_PROTO_IPV4, skb, state->in);
#endif
    }

    return verdict == TF_ACCEPT ? NF_ACCEPT : NF_DROP;
}

static struct nf_hook_ops hooks[] __read_mostly = {
    {
        .hook     = packet_in,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
        .owner    = THIS_MODULE,
#endif
        .hooknum  = NF_INET_FORWARD,
        .pf       = PF_INET,
        .priority = NF_IP_PRI_FIRST,
    },
};

/*
 * struct tifilter_filter
 * 확정된 자료구조 아님.
 * 테스트를 위한 샘플 코드
 */
static int
filter_add(struct tifilter_filter *filter)
{
    /* filter 에 추가 */
    return 0;
}

static int
filter_del(struct tifilter_filter *filter)
{
    /* filter 에 삭제 */
    return 0;
}

static int
filter_notify(struct notifier_block *self,
              unsigned long msg_type,
              void *data)
{
    int ret;

    switch (msg_type) {
    case TF_MSG_FILTER_ADD:
        ret = filter_add(data);
        break;
    case TF_MSG_FILTER_DEL:
        ret = filter_del(data);
        break;
    }

    return ret;
}

static struct notifier_block filter_notifier = {
    .notifier_call = filter_notify,
};

static int __init
nfglue_init(void)
{
    int ret;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
    ret = nf_register_hooks(hooks, ARRAY_SIZE(hooks));
#else
    ret = nf_register_net_hooks(&init_net, hooks, ARRAY_SIZE(hooks));
#endif
    if (ret < 0) {
        pr_err("Fail to register netfilter hooks\n");
        goto err;
    }

    ret = tf_register_raw_notifier(&filter_notifier);
    if (ret < 0) {
        pr_err("Fail to register tifilter notifier\n");
        goto tf_register_failure;
    }

    printk(KERN_INFO "Load nfglue for TiMatrix\n");

    return 0;

tf_register_failure:
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
    nf_unregister_hooks(hooks, ARRAY_SIZE(hooks));
#else
    nf_unregister_net_hooks(&init_net, hooks, ARRAY_SIZE(hooks));
#endif
err:
    return ret;
}
module_init(nfglue_init);

static void __exit
nfglue_exit(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
    nf_unregister_hooks(hooks, ARRAY_SIZE(hooks));
#else
    nf_unregister_net_hooks(&init_net, hooks, ARRAY_SIZE(hooks));
#endif

    printk(KERN_ERR "Bye nfglue\n");
}
module_exit(nfglue_exit);
