#ifndef TIFILTER_NOTIFIER_H_6ONSN9DV
#define TIFILTER_NOTIFIER_H_6ONSN9DV

#include <linux/notifier.h>

enum {
    TF_MSG_FILTER_ADD,
    TF_MSG_FILTER_DEL
};

/* 인터페이스가 아직 설계 되지 않음 */
/* sample로 간단히 작성 */
struct tifilter_filter {
    struct {
        uint32_t saddr;
        uint32_t daddr;
    } val, mask;
};

int
tf_register_raw_notifier(struct notifier_block *nb);

int
tf_unregister_raw_notifier(struct notifier_block *nb);

int
tf_notifier_call(unsigned long val, void *data);

#endif /* end of include guard: TIFILTER_NOTIFIER_H_6ONSN9DV */
