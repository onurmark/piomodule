#include <linux/module.h>

#include <tifilter/tifilter_hook.h>

MODULE_LICENSE("GPL");

static int __init
tifilter_init(void)
{
    int ret;

    ret = tifilter_hook_init();
    if (ret < 0) {
        pr_err("Fail to init tifilter hook\n");
        goto err;
    }

    printk(KERN_INFO "TiFilter example skeleton loaded\n");

    return 0;
err:
    return ret;
}
module_init(tifilter_init);

static void __exit
tifilter_exit(void)
{
    tifilter_hook_exit();

    printk(KERN_ERR "Bye TiFilter\n");
}
module_exit(tifilter_exit);
