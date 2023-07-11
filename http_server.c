#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kthread.h>
#include <linux/sched/signal.h>
#include <linux/tcp.h>

#include "http_parser.h"
#include "http_server.h"

#include "timer.c"

#define CRLF "\r\n"
#define BUFFER_SIZE 4096

#define HTTP_RESPONSE_200_DUMMY                               \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Close" CRLF CRLF "Hello World!" CRLF
#define HTTP_RESPONSE_200_KEEPALIVE_DUMMY                     \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Keep-Alive" CRLF CRLF "Hello World!" CRLF
#define HTTP_RESPONSE_501                                              \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: Close" CRLF CRLF "501 Not Implemented" CRLF
#define HTTP_RESPONSE_501_KEEPALIVE                                    \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: KeepAlive" CRLF CRLF "501 Not Implemented" CRLF

#define RECV_BUFFER_SIZE 4096

struct http_request {
    struct socket *socket;
    enum http_method method;
    char request_url[128];
    int complete;
    struct dir_context ctx;
};

extern struct workqueue_struct *khttp_wq;

struct khttp_server_service daemon = {.is_stopped = false};

static int http_server_recv(struct socket *sock, char *buf, size_t size)
{
    struct kvec iov = {.iov_base = (void *) buf, .iov_len = size};
    struct msghdr msg = {.msg_name = 0,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    return kernel_recvmsg(sock, &msg, &iov, 1, size, msg.msg_flags);
}

static int http_server_send(struct socket *sock, const char *buf, size_t size)
{
    struct msghdr msg = {.msg_name = NULL,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    int done = 0;
    while (done < size) {
        struct kvec iov = {
            .iov_base = (void *) ((char *) buf + done),
            .iov_len = size - done,
        };
        int length = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
        if (length < 0) {
            pr_err("write error: %d\n", length);
            break;
        }
        done += length;
    }
    return done;
}

// static int http_server_response(struct http_request *request, int keep_alive)
// {
//     char *response;

//     pr_info("requested_url = %s\n", request->request_url);
//     if (request->method != HTTP_GET)
//         response = keep_alive ? HTTP_RESPONSE_501_KEEPALIVE :
//         HTTP_RESPONSE_501;
//     else
//         response = keep_alive ? HTTP_RESPONSE_200_KEEPALIVE_DUMMY
//                               : HTTP_RESPONSE_200_DUMMY;
//     http_server_send(request->socket, response, strlen(response));
//     return 0;
// }

static int http_parser_callback_message_begin(http_parser *parser)
{
    struct http_request *request = parser->data;
    struct socket *socket = request->socket;
    memset(request, 0x00, sizeof(struct http_request));
    request->socket = socket;
    return 0;
}

static int http_parser_callback_request_url(http_parser *parser,
                                            const char *p,
                                            size_t len)
{
    struct http_request *request = parser->data;
    strncat(request->request_url, p, len);
    return 0;
}

static int http_parser_callback_header_field(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_header_value(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_headers_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    request->method = parser->method;
    return 0;
}

static int http_parser_callback_body(http_parser *parser,
                                     const char *p,
                                     size_t len)
{
    return 0;
}

static int printdir(struct dir_context *ctx,
                    const char *name,
                    int namlen,
                    loff_t offset,
                    u64 ino,
                    unsigned int d_type)
{
    char *buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);
    struct http_request *request = container_of(ctx, struct http_request, ctx);

    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
        return 0;
    }

    snprintf(buf, BUFFER_SIZE, "<li><a href=%s>%s</a></li>", name, name);
    http_server_send(request->socket, buf, BUFFER_SIZE);
    return 0;
}

static void list_directory_info(struct http_request *request)
{
    pr_info("Into : list_directory_info()\n");

    char *response = kmalloc(BUFFER_SIZE, GFP_KERNEL);

    if (request->method != HTTP_GET) {
        response = HTTP_RESPONSE_501;
        http_server_send(request->socket, response, strlen(response));
        kfree(response);
    }

    char *path = daemon.root;
    pr_info("The current path is %s\n", path);
    request->ctx.actor = &printdir;
    struct file *fp = filp_open(path, O_DIRECTORY, S_IRWXU | S_IRWXG | S_IRWXO);
    if (IS_ERR(fp)) {
        pr_err("Open file error\n");
    }

    snprintf(response, BUFFER_SIZE, "HTTP/1.1 200 OK \r\n%s%s%s",
             "Server: localhost\r\n", "Content-Type: text/html\r\n",
             "Keep-Alive: timeout=5, max=999\r\n\r\n");
    http_server_send(request->socket, response, BUFFER_SIZE);
    memset(response, '\0', BUFFER_SIZE);

    snprintf(response, BUFFER_SIZE,
             "<!DOCTYPE html><html><head><title>Page "
             "Title</title></head><body><ul>");
    http_server_send(request->socket, response, BUFFER_SIZE);
    memset(response, '\0', BUFFER_SIZE);
    iterate_dir(fp, &(request->ctx));

    snprintf(response, BUFFER_SIZE, "</ul></body></html>");
    http_server_send(request->socket, response, BUFFER_SIZE);
    kfree(response);

    return;
}

static int http_parser_callback_message_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    // http_server_response(request, http_should_keep_alive(parser));
    list_directory_info(request);
    request->complete = 1;
    return 0;
}

static void http_server_worker(struct work_struct *work)
{
    struct khttp *worker = container_of(work, struct khttp, khttp_work);
    char *buf;
    struct http_parser parser;
    struct http_parser_settings setting = {
        .on_message_begin = http_parser_callback_message_begin,
        .on_url = http_parser_callback_request_url,
        .on_header_field = http_parser_callback_header_field,
        .on_header_value = http_parser_callback_header_value,
        .on_headers_complete = http_parser_callback_headers_complete,
        .on_body = http_parser_callback_body,
        .on_message_complete = http_parser_callback_message_complete};
    struct http_request request;
    struct socket *socket = worker->sock;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    buf = kzalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
    if (!buf) {
        pr_err("can't allocate memory!\n");
    }

    request.socket = socket;
    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &request;
    add_timer_t(worker, TIMEOUT_DEFAULT, kernel_sock_shutdown);

    while (!daemon.is_stopped) {
        int ret;
        memset(buf, 0, RECV_BUFFER_SIZE - 1);
        ret = http_server_recv(socket, buf, RECV_BUFFER_SIZE - 1);
        if (ret <= 0) {
            if (ret)
                pr_err("recv error: %d\n", ret);
            break;
        }
        http_parser_execute(&parser, &setting, buf, ret);
        if (request.complete && !http_should_keep_alive(&parser))
            break;
        memset(buf, 0, RECV_BUFFER_SIZE);
    }
    kernel_sock_shutdown(socket, SHUT_RDWR);
    del_timer_t(worker);
    sock_release(socket);
    kfree(buf);
}

static struct work_struct *create_work(struct socket *sk)
{
    struct khttp *work;

    if (!(work = kmalloc(sizeof(struct khttp), GFP_KERNEL)))
        return NULL;

    work->sock = sk;

    INIT_WORK(&work->khttp_work, http_server_worker);

    // list_add(&work->list, &daemon.worker);
    list_add_rcu(&work->list, &daemon.worker);

    return &work->khttp_work;
}

static void free_work(void)
{
    struct khttp *l, *tar;
    /* cppcheck-suppress uninitvar */

    rcu_read_lock();
    list_for_each_entry_rcu(tar, &daemon.worker, list)
    {
        // list_for_each_entry_safe (tar, l, &daemon.worker, list) {
        kernel_sock_shutdown(tar->sock, SHUT_RDWR);
        flush_work(&tar->khttp_work);
        sock_release(tar->sock);
        kfree(tar);
    }
    rcu_read_unlock();
}

int http_server_daemon(void *arg)
{
    struct socket *socket;
    struct work_struct *work;
    struct http_server_param *param = (struct http_server_param *) arg;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    timer_init();
    INIT_LIST_HEAD(&daemon.worker);

    while (!kthread_should_stop()) {
        int time = find_timer();
        // pr_info("wait time = %d\n", time);
        handle_expired_timers();

        // int err = kernel_accept(param->listen_socket, &socket, 0);
        int err = kernel_accept(param->listen_socket, &socket, SOCK_NONBLOCK);
        if (err < 0) {
            if (signal_pending(current))
                break;
            // pr_err("kernel_accept() error: %d\n", err);
            continue;
        }

        if (unlikely(!(work = create_work(socket)))) {
            printk(KERN_ERR "khttp : create work error, connection closed\n");
            kernel_sock_shutdown(socket, SHUT_RDWR);
            sock_release(socket);
            continue;
        }

        /* start server worker */
        queue_work(khttp_wq, work);
    }
    printk("khttp : daemon shutdown in progress...\n");

    daemon.is_stopped = true;

    free_work();

    return 0;
}
