//#include <assert.h>
//#include <stdlib.h>
//#include <string.h>
//#include <sys/time.h>

#include "timer.h"

#define TIMER_INFINITE (-1)
#define PQ_DEFAULT_SIZE 10

typedef int (*prio_queue_comparator)(void *pi, void *pj);

/* priority queue with binary heap */
typedef struct {
    void **priv;
    size_t nalloc;
    size_t size;
    prio_queue_comparator comp;
} prio_queue_t;

static bool prio_queue_init(prio_queue_t *ptr,
                            prio_queue_comparator comp,
                            size_t size)
{
    ptr->priv = kmalloc(sizeof(void *) * (size + 1), GFP_KERNEL);
    if (!ptr->priv) {
        pr_err("prio_queue_init: malloc failed");
        return false;
    }

    ptr->nalloc = 0;
    ptr->size = size + 1;
    ptr->comp = comp;
    return true;
}

static inline bool prio_queue_is_empty(prio_queue_t *ptr)
{
    return ptr->nalloc == 0;
}

static inline size_t prio_queue_size(prio_queue_t *ptr)
{
    return ptr->nalloc;
}

static inline void *prio_queue_min(prio_queue_t *ptr)
{
    return prio_queue_is_empty(ptr) ? NULL : ptr->priv[1];
}

static bool resize(prio_queue_t *ptr, size_t new_size)
{
    if (new_size <= ptr->nalloc) {
        pr_err("resize: new_size to small");
        return false;
    }

    /* TODO: use memory pool to avoid unexpected fragmentation */
    void **new_ptr = kmalloc(sizeof(void *) * new_size, GFP_KERNEL);
    if (!new_ptr) {
        pr_err("resize: malloc failed");
        return false;
    }

    memcpy(new_ptr, ptr->priv, sizeof(void *) * (ptr->nalloc + 1));
    kfree(ptr->priv);
    ptr->priv = new_ptr;
    ptr->size = new_size;
    return true;
}

static inline void swap_t(prio_queue_t *ptr, size_t i, size_t j)
{
    void *tmp = ptr->priv[i];
    ptr->priv[i] = ptr->priv[j];
    ptr->priv[j] = tmp;
}

static inline void swim(prio_queue_t *ptr, size_t k)
{
    while (k > 1 && ptr->comp(ptr->priv[k], ptr->priv[k / 2])) {
        swap_t(ptr, k, k / 2);
        k /= 2;
    }
}

static size_t sink(prio_queue_t *ptr, size_t k)
{
    size_t nalloc = ptr->nalloc;

    while (2 * k <= nalloc) {
        size_t j = 2 * k;
        if (ptr->comp(ptr->priv[j + 1], ptr->priv[j]))
            j++;
        if (!ptr->comp(ptr->priv[j], ptr->priv[k]))
            break;
        swap_t(ptr, j, k);
        k = j;
    }

    return k;
}

/* remove the item with minimum key value from the heap */
static bool prio_queue_delmin(prio_queue_t *ptr)
{
    if (prio_queue_is_empty(ptr))
        return true;

    swap_t(ptr, 1, ptr->nalloc);
    ptr->nalloc--;
    sink(ptr, 1);
    if (ptr->nalloc > 0 && ptr->nalloc <= (ptr->size - 1) / 4) {
        if (!resize(ptr, ptr->size / 2))
            return false;
    }
    return true;
}

/* add a new item to the heap */
static bool prio_queue_insert(prio_queue_t *ptr, void *item)
{
    if (ptr->nalloc + 1 == ptr->size) {
        if (!resize(ptr, ptr->size * 2))
            return false;
    }

    ptr->priv[++ptr->nalloc] = item;
    swim(ptr, ptr->nalloc);
    return true;
}

static int timer_comp(void *ti, void *tj)
{
    return ((timer_node *) ti)->key < ((timer_node *) tj)->key ? 1 : 0;
}

static prio_queue_t timer;
static size_t current_msec;

static void time_update(void)
{
    // struct timeval tv;
    ktime_t kt = ktime_get_real();
    // int rc = gettimeofday(&tv, NULL);
    // BUG_ON(kt == 0 && "time_update: ktime_get_real error");
    // current_msec = tv.tv_sec * 1000 + tv.tv_usec / 1000;
    current_msec = ktime_to_ms(kt);
}

int timer_init()
{
    bool ret = prio_queue_init(&timer, timer_comp, PQ_DEFAULT_SIZE);
    if (!ret) {
        pr_err("prio_queue_init error\n");
    }
    // BUG_ON(ret && "prio_queue_init error");

    time_update();
    return 0;
}

int find_timer()
{
    int time = TIMER_INFINITE;

    while (!prio_queue_is_empty(&timer)) {
        time_update();
        timer_node *node = prio_queue_min(&timer);
        // BUG_ON(node && "prio_queue_min error");

        if (node->deleted) {
            bool ret = prio_queue_delmin(&timer);
            // BUG_ON(ret && "prio_queue_delmin");
            kfree(node);
            continue;
        }

        time = (int) (node->key - current_msec);
        time = (time > 0 ? time : 0);
        break;
    }

    return time;
}

void handle_expired_timers()
{
    bool ret;

    while (!prio_queue_is_empty(&timer)) {
        pr_info("handle_expired_timers, size = %zu", prio_queue_size(&timer));
        time_update();
        timer_node *node = prio_queue_min(&timer);
        // BUG_ON(node && "prio_queue_min error");

        if (node->deleted) {
            ret = prio_queue_delmin(&timer);
            if (!ret) {
                pr_err("handle_expired_timers: prio_queue_delmin error\n");
            }
            // BUG_ON(ret && "handle_expired_timers: prio_queue_delmin error");
            kfree(node);
            continue;
        }

        if (node->key > current_msec)
            return;
        if (node->callback)
            node->callback(node->request);

        ret = prio_queue_delmin(&timer);
        if (!ret) {
            pr_err("handle_expired_timers: prio_queue_delmin error\n");
        }
        // BUG_ON(ret && "handle_expired_timers: prio_queue_delmin error");
        kfree(node);
    }
}

void add_timer_t(struct khttp *req, size_t timeout, timer_callback cb)
{
    timer_node *node = kmalloc(sizeof(timer_node), GFP_KERNEL);
    // BUG_ON(node && "add_timer: malloc error");

    time_update();
    req->timer = node;
    node->key = current_msec + timeout;
    node->deleted = false;
    node->callback = cb;
    node->request = req;

    bool ret = prio_queue_insert(&timer, node);
    if (!ret) {
        pr_err("add_timer: prio_queue_insert error");
    }
    // BUG_ON(ret && "add_timer: prio_queue_insert error");
}

void del_timer_t(struct khttp *req)
{
    time_update();
    timer_node *node = req->timer;
    // BUG_ON(node && "del_timer: req->timer is NULL");

    node->deleted = true;
}