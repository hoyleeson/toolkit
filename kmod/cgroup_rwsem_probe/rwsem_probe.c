#include <linux/init.h>
#include <linux/version.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/cgroup-defs.h>

unsigned long (*diag_kallsyms_lookup_name)(const char *name);

static int (*diag_kallsyms_on_each_symbol)(int (*fn)(void *, const char *,
            struct module *, unsigned long), void *data);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#include <linux/kprobes.h>
static struct kprobe kprobe_kallsyms_lookup_name = {
    .symbol_name = "kallsyms_lookup_name"
};

int diag_init_symbol(void)
{
    register_kprobe(&kprobe_kallsyms_lookup_name);
    diag_kallsyms_lookup_name = (void *)kprobe_kallsyms_lookup_name.addr;
    unregister_kprobe(&kprobe_kallsyms_lookup_name);

    printk("diag_kallsyms_lookup_name is %p\n", diag_kallsyms_lookup_name);

    if (!diag_kallsyms_lookup_name) {
        return -EINVAL;
    }

    diag_kallsyms_on_each_symbol = (void *)diag_kallsyms_lookup_name("kallsyms_on_each_symbol");
    if (!diag_kallsyms_on_each_symbol) {
        return -EINVAL;
    }

    return 0;
}
#else
#endif

struct rwsem_measure {
    int idx;
    s64 pre_down_ts;
    s64 post_down_ts;
    s64 pre_up_ts;
    s64 post_up_ts;
};

static DEFINE_PER_CPU(struct rwsem_measure, measure_percpu);

struct rwsem_probe {
    int cnt;
    int idle_cnt;
    int block_cnt;
    int active_cnt;
    int read_cnt;
    int runc_cnt;
    int oncpu_cnt;
};

static struct rwsem_probe sampling;

#define per_cpu_sum(var)                        \
    ({                                  \
     typeof(var) __sum = 0;                      \
     int cpu;                            \
     compiletime_assert_atomic_type(__sum);              \
     for_each_possible_cpu(cpu)                  \
     __sum += per_cpu(var, cpu);             \
     __sum;                              \
     })

static struct percpu_rw_semaphore *cgroup_tg_rwsem = NULL;

static void peek_percpu_rwsem(struct percpu_rw_semaphore *sem)
{
    struct task_struct *task;
    char name[TASK_COMM_LEN] = {0};
    pid_t pid = 0, tgid = 0;
    int on_rq = 0, on_cpu = 0, cpu = 0, state = 0;

    rcu_read_lock();
    task = rcu_dereference(sem->writer.task);
    if (task) {
        snprintf(name, sizeof(name), "%s", task->comm);
        pid = task->pid;
        tgid = task->tgid;
        on_rq = task->on_rq;
        on_cpu = task->on_cpu;
        cpu = task->cpu;
        state = task->__state;
    }
    rcu_read_unlock();

    sampling.cnt++;
    if (rcu_sync_is_idle(&sem->rss)) {
        sampling.idle_cnt++;
    }

    if (atomic_read(&sem->block) > 0) {
        sampling.block_cnt++;
    }

    if (rcuwait_active(&sem->writer))
        sampling.active_cnt++;

    if (per_cpu_sum(*sem->read_count) > 0)
        sampling.read_cnt++;

    if (on_cpu)
        sampling.oncpu_cnt++;

    if (!strcmp(name, "runc"))
        sampling.runc_cnt++;

    if (sampling.cnt % 100 == 0) {
        printk("=>%d, %d, %d, %d, %s(%d,%d, %d,%d,%d,%d)\n", rcu_sync_is_idle(&sem->rss),
                atomic_read(&sem->block), rcuwait_active(&sem->writer),
                per_cpu_sum(*sem->read_count),
                name, pid, tgid, on_rq, on_cpu, cpu, state);
        printk("->cnt:%d, idle:%d, block:%d, active:%d, runc:%d, read:%d, oncpu:%d\n",
                sampling.cnt, sampling.idle_cnt, sampling.block_cnt,
                sampling.active_cnt, sampling.runc_cnt, sampling.read_cnt, sampling.oncpu_cnt);

        sampling.idle_cnt = 0;
        sampling.block_cnt = 0;
        sampling.active_cnt = 0;
        sampling.read_cnt = 0;
        sampling.oncpu_cnt = 0;
        sampling.runc_cnt = 0;
    }
}

static void print_percpu_rwsem(struct percpu_rw_semaphore *sem, const char *tag)
{
    char name[TASK_COMM_LEN] = {0};
    struct task_struct *task;

    if (!sem)
        return;

    rcu_read_lock();
    task = rcu_dereference(sem->writer.task);
    if (task)
        snprintf(name, sizeof(name), "%s", task->comm);
    rcu_read_unlock();

    printk("rwsem[%s]=>%d, %d, %d, %d, %s\n", tag,
            rcu_sync_is_idle(&sem->rss),
            atomic_read(&sem->block), rcuwait_active(&sem->writer),
            per_cpu_sum(*sem->read_count), name);
}

//#define CONN_STATS_REFRESH_PERIOD       (HZ)
#define CONN_STATS_REFRESH_PERIOD       (1)
static struct timer_list sampling_timer;

static void fw_samplingats_handler(struct timer_list *t)
{
    if (!cgroup_tg_rwsem)
        return;

    peek_percpu_rwsem(cgroup_tg_rwsem);
    mod_timer(&sampling_timer, jiffies + CONN_STATS_REFRESH_PERIOD);
}

static int percpu_down_write_kret_entry_handler(struct kretprobe_instance *ri,
        struct pt_regs *regs)
{
    struct rwsem_measure *measure;

    measure = this_cpu_ptr(&measure_percpu);
    ++measure->idx;
    measure->pre_down_ts = ktime_to_ms(ktime_get());

    print_percpu_rwsem(cgroup_tg_rwsem, "pre_down");
    return 0;
}

static int percpu_down_write_kret_handler(struct kretprobe_instance *ri,
        struct pt_regs *regs)
{
    struct rwsem_measure *measure;

    measure = this_cpu_ptr(&measure_percpu);
    measure->post_down_ts = ktime_to_ms(ktime_get());

    print_percpu_rwsem(cgroup_tg_rwsem, "post_down");
    return 0;
}

static int percpu_up_write_kret_entry_handler(struct kretprobe_instance *ri,
        struct pt_regs *regs)
{
    struct rwsem_measure *measure;

    measure = this_cpu_ptr(&measure_percpu);
    measure->pre_up_ts = ktime_to_ms(ktime_get());

    print_percpu_rwsem(cgroup_tg_rwsem, "pre_up");
    return 0;
}

static int percpu_up_write_kret_handler(struct kretprobe_instance *ri,
        struct pt_regs *regs)
{
    struct rwsem_measure *measure;

    measure = this_cpu_ptr(&measure_percpu);
    measure->post_up_ts = ktime_to_ms(ktime_get());

    print_percpu_rwsem(cgroup_tg_rwsem, "post_up");
    printk("timecost - [cpu %4d] %8d: %14llu %14llu %14llu %14llu [%10lld]<%10lld>[%10lld]\n",
            smp_processor_id(), measure->idx,
            measure->pre_down_ts, measure->post_down_ts,
            measure->pre_up_ts, measure->post_up_ts,
            (measure->post_down_ts - measure->pre_down_ts),
            (measure->pre_up_ts - measure->post_down_ts),
            (measure->post_up_ts - measure->pre_up_ts));
    return 0;
}

static struct kretprobe my_kretprobe[] = {
    {
        .kp.symbol_name = "percpu_down_write",
        .handler = percpu_down_write_kret_handler,
        .entry_handler = percpu_down_write_kret_entry_handler,
    },
    {
        .kp.symbol_name = "percpu_up_write",
        .handler = percpu_up_write_kret_handler,
        .entry_handler = percpu_up_write_kret_entry_handler,
    }
};

static int resolv_cgroup_tg_rwsem(void)
{
    struct percpu_rw_semaphore *sem;

    sem = (struct percpu_rw_semaphore *)diag_kallsyms_lookup_name("cgroup_threadgroup_rwsem");
    if (!sem) {
        printk("Not found symbol 'cgroup_threadgroup_rwsem'\n");
        return -ENOENT;
    }

    cgroup_tg_rwsem = sem;
    return 0;
}

static int __init rwsem_probe_init(void)
{
    int i;
    int ret;

    diag_init_symbol();

    ret = resolv_cgroup_tg_rwsem();
    if (ret)
        return ret;

    for (i = 0; i < ARRAY_SIZE(my_kretprobe); i++) {
        ret = register_kretprobe(&my_kretprobe[i]);
        if (ret < 0) {
            pr_err("register_kretprobe %s failed, returned %d\n",
                    my_kretprobe[i].kp.symbol_name, ret);
            goto fail;
        }
        pr_info("Planted kretprobe at %s\n", my_kretprobe[i].kp.symbol_name);
    }

    timer_setup(&sampling_timer, fw_samplingats_handler, 0);
    mod_timer(&sampling_timer, jiffies + CONN_STATS_REFRESH_PERIOD);

    printk("resem probe kmod init successed.%d\n", HZ);

    return 0;

fail:
    while (i > 0) {
        unregister_kretprobe(&my_kretprobe[i - 1]);
    }
    return -EINVAL;
}

static void __exit rwsem_probe_exit(void)
{
    int i;

    del_timer_sync(&sampling_timer);

    for (i = 0; i < ARRAY_SIZE(my_kretprobe); i++) {
        unregister_kretprobe(&my_kretprobe[i]);
        pr_info("kretprobe at %s unregistered\n", my_kretprobe[i].kp.symbol_name);
    }

    printk("resem probe kmod release.\n");
}

module_init(rwsem_probe_init);
module_exit(rwsem_probe_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("hoyleeson");
MODULE_VERSION("1.0.0");
MODULE_DESCRIPTION("rwsem_probe module");

