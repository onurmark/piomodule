#include <linux/kernel.h>

#include <tifilter/tifilter_notifier.h>

static RAW_NOTIFIER_HEAD(tf_notifier_chain);

int
tf_register_raw_notifier(struct notifier_block *nb)
{
    int ret;

    ret = raw_notifier_chain_register(&tf_notifier_chain, nb);
    if (ret < 0) {
        goto err;
    }

err:
    return ret;
}
EXPORT_SYMBOL(tf_register_raw_notifier);

int
tf_unregister_raw_notifier(struct notifier_block *nb)
{
    int ret;

    ret = raw_notifier_chain_unregister(&tf_notifier_chain, nb);
    if (ret < 0) {
        goto err;
    }

    return 0;

err:
    return ret;
}
EXPORT_SYMBOL(tf_unregister_raw_notifier);

int
tf_notifier_call(unsigned long val, void *data)
{
    return raw_notifier_call_chain(&tf_notifier_chain, val, data);
}
EXPORT_SYMBOL(tf_notifier_call);
