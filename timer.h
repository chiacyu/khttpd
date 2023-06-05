#ifndef TIMER_H
#define TIMER_H

//#include <stdbool.h>
#include "http_server.h"

#define TIMEOUT_DEFAULT 500 /* ms */

typedef int (*timer_callback)(struct khttp *req);

typedef struct {
    size_t key;
    bool deleted; /* if remote client close socket first, set deleted true */
    timer_callback callback;
    struct khttp *request;
} timer_node;

int timer_init(void);
int find_timer(void);
void handle_expired_timers(void);

void add_timer_t(struct khttp *req, size_t timeout, timer_callback cb);
void del_timer_t(struct khttp *req);

#endif