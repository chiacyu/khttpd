#ifndef KHTTPD_HTTP_SERVER_H
#define KHTTPD_HTTP_SERVER_H

#include <linux/workqueue.h>
#include <net/sock.h>

struct http_server_param {
    struct socket *listen_socket;
};

struct khttp_server_service {
    bool is_stopped;
    struct list_head worker;
};

struct khttp {
    struct socket *sock;
    struct list_head list;
    struct work_struct khttp_work;
    void *timer;
};


extern int http_server_daemon(void *);

#endif
