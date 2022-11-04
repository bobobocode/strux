
// BoBoBo


static char *sx_error_log(sx_conf_t *cf, sx_command_t *cmd, void *conf);
static char *sx_log_set_levels(sx_conf_t *cf, sx_log_t *log);
static void sx_log_insert(sx_log_t *log, sx_log_t *new_log);


#if (NGX_DEBUG)

static void sx_log_memory_writer(sx_log_t *log, sx_uint_t level,
    u_char *buf, size_t len);
static void sx_log_memory_cleanup(void *data);


typedef struct {
    u_char        *start;
    u_char        *end;
    u_char        *pos;
    sx_atomic_t   written;
} sx_log_memory_buf_t;

#endif


static sx_log_t        sx_log;
static sx_open_file_t  sx_log_file;
sx_uint_t              sx_use_stderr = 1;


static sx_str_t err_levels[] = {
    sx_null_string,
    sx_string("emerg"),
    sx_string("alert"),
    sx_string("crit"),
    sx_string("error"),
    sx_string("warn"),
    sx_string("notice"),
    sx_string("info"),
    sx_string("debug")
};

static const char *debug_levels[] = {
    "debug_core", "debug_alloc", "debug_mutex", "debug_event",
    "debug_http", "debug_mail", "debug_stream"
};


#if (NGX_HAVE_VARIADIC_MACROS)

void
sx_log_error_core(sx_uint_t level, sx_log_t *log, sx_err_t err,
    const char *fmt, ...)

#else

void
sx_log_error_core(sx_uint_t level, sx_log_t *log, sx_err_t err,
    const char *fmt, va_list args)

#endif
{
#if (NGX_HAVE_VARIADIC_MACROS)
    va_list      args;
#endif
    u_char      *p, *last, *msg;
    ssize_t      n;
    sx_uint_t   wrote_stderr, debug_connection;
    u_char       errstr[NGX_MAX_ERROR_STR];

    last = errstr + NGX_MAX_ERROR_STR;

    p = sx_cpymem(errstr, sx_cached_err_log_time.data,
                   sx_cached_err_log_time.len);

    p = sx_slprintf(p, last, " [%V] ", &err_levels[level]);

    /* pid#tid */
    p = sx_slprintf(p, last, "%P#" NGX_TID_T_FMT ": ",
                    sx_log_pid, sx_log_tid);

    if (log->connection) {
        p = sx_slprintf(p, last, "*%uA ", log->connection);
    }

    msg = p;

#if (NGX_HAVE_VARIADIC_MACROS)

    va_start(args, fmt);
    p = sx_vslprintf(p, last, fmt, args);
    va_end(args);

#else

    p = sx_vslprintf(p, last, fmt, args);

#endif

    if (err) {
        p = sx_log_errno(p, last, err);
    }

    if (level != NGX_LOG_DEBUG && log->handler) {
        p = log->handler(log, p, last - p);
    }

    if (p > last - NGX_LINEFEED_SIZE) {
        p = last - NGX_LINEFEED_SIZE;
    }

    sx_linefeed(p);

    wrote_stderr = 0;
    debug_connection = (log->log_level & NGX_LOG_DEBUG_CONNECTION) != 0;

    while (log) {

        if (log->log_level < level && !debug_connection) {
            break;
        }

        if (log->writer) {
            log->writer(log, level, errstr, p - errstr);
            goto next;
        }

        if (sx_time() == log->disk_full_time) {

            /*
             * on FreeBSD writing to a full filesystem with enabled softupdates
             * may block process for much longer time than writing to non-full
             * filesystem, so we skip writing to a log for one second
             */

            goto next;
        }

        n = sx_write_fd(log->file->fd, errstr, p - errstr);

        if (n == -1 && sx_errno == NGX_ENOSPC) {
            log->disk_full_time = sx_time();
        }

        if (log->file->fd == sx_stderr) {
            wrote_stderr = 1;
        }

    next:

        log = log->next;
    }

    if (!sx_use_stderr
        || level > NGX_LOG_WARN
        || wrote_stderr)
    {
        return;
    }

    msg -= (7 + err_levels[level].len + 3);

    (void) sx_sprintf(msg, "nginx: [%V] ", &err_levels[level]);

    (void) sx_write_console(sx_stderr, msg, p - msg);
}


#if !(NGX_HAVE_VARIADIC_MACROS)

void sx_cdecl
sx_log_error(sx_uint_t level, sx_log_t *log, sx_err_t err,
    const char *fmt, ...)
{
    va_list  args;

    if (log->log_level >= level) {
        va_start(args, fmt);
        sx_log_error_core(level, log, err, fmt, args);
        va_end(args);
    }
}


void sx_cdecl
sx_log_debug_core(sx_log_t *log, sx_err_t err, const char *fmt, ...)
{
    va_list  args;

    va_start(args, fmt);
    sx_log_error_core(NGX_LOG_DEBUG, log, err, fmt, args);
    va_end(args);
}

#endif


void sx_cdecl
sx_log_abort(sx_err_t err, const char *fmt, ...)
{
    u_char   *p;
    va_list   args;
    u_char    errstr[NGX_MAX_CONF_ERRSTR];

    va_start(args, fmt);
    p = sx_vsnprintf(errstr, sizeof(errstr) - 1, fmt, args);
    va_end(args);

    sx_log_error(NGX_LOG_ALERT, sx_cycle->log, err,
                  "%*s", p - errstr, errstr);
}


void sx_cdecl
sx_log_stderr(sx_err_t err, const char *fmt, ...)
{
    u_char   *p, *last;
    va_list   args;
    u_char    errstr[NGX_MAX_ERROR_STR];

    last = errstr + NGX_MAX_ERROR_STR;

    p = sx_cpymem(errstr, "nginx: ", 7);

    va_start(args, fmt);
    p = sx_vslprintf(p, last, fmt, args);
    va_end(args);

    if (err) {
        p = sx_log_errno(p, last, err);
    }

    if (p > last - NGX_LINEFEED_SIZE) {
        p = last - NGX_LINEFEED_SIZE;
    }

    sx_linefeed(p);

    (void) sx_write_console(sx_stderr, errstr, p - errstr);
}


u_char *
sx_log_errno(u_char *buf, u_char *last, sx_err_t err)
{
    if (buf > last - 50) {

        /* leave a space for an error code */

        buf = last - 50;
        *buf++ = '.';
        *buf++ = '.';
        *buf++ = '.';
    }

#if (NGX_WIN32)
    buf = sx_slprintf(buf, last, ((unsigned) err < 0x80000000)
                                       ? " (%d: " : " (%Xd: ", err);
#else
    buf = sx_slprintf(buf, last, " (%d: ", err);
#endif

    buf = sx_strerror(err, buf, last - buf);

    if (buf < last) {
        *buf++ = ')';
    }

    return buf;
}


sx_log_t *
sx_log_init(u_char *prefix, u_char *error_log)
{
    u_char  *p, *name;
    size_t   nlen, plen;

    sx_log.file = &sx_log_file;
    sx_log.log_level = NGX_LOG_NOTICE;

    if (error_log == NULL) {
        error_log = (u_char *) NGX_ERROR_LOG_PATH;
    }

    name = error_log;
    nlen = sx_strlen(name);

    if (nlen == 0) {
        sx_log_file.fd = sx_stderr;
        return &sx_log;
    }

    p = NULL;

#if (NGX_WIN32)
    if (name[1] != ':') {
#else
    if (name[0] != '/') {
#endif

        if (prefix) {
            plen = sx_strlen(prefix);

        } else {
#ifdef NGX_PREFIX
            prefix = (u_char *) NGX_PREFIX;
            plen = sx_strlen(prefix);
#else
            plen = 0;
#endif
        }

        if (plen) {
            name = malloc(plen + nlen + 2);
            if (name == NULL) {
                return NULL;
            }

            p = sx_cpymem(name, prefix, plen);

            if (!sx_path_separator(*(p - 1))) {
                *p++ = '/';
            }

            sx_cpystrn(p, error_log, nlen + 1);

            p = name;
        }
    }

    sx_log_file.fd = sx_open_file(name, NGX_FILE_APPEND,
                                    NGX_FILE_CREATE_OR_OPEN,
                                    NGX_FILE_DEFAULT_ACCESS);

    if (sx_log_file.fd == NGX_INVALID_FILE) {
        sx_log_stderr(sx_errno,
                       "[alert] could not open error log file: "
                       sx_open_file_n " \"%s\" failed", name);
#if (NGX_WIN32)
        sx_event_log(sx_errno,
                       "could not open error log file: "
                       sx_open_file_n " \"%s\" failed", name);
#endif

        sx_log_file.fd = sx_stderr;
    }

    if (p) {
        sx_free(p);
    }

    return &sx_log;
}


sx_int_t
sx_log_open_default(sx_cycle_t *cycle)
{
    sx_log_t  *log;

    if (sx_log_get_file_log(&cycle->new_log) != NULL) {
        return NGX_OK;
    }

    if (cycle->new_log.log_level != 0) {
        /* there are some error logs, but no files */

        log = sx_pcalloc(cycle->pool, sizeof(sx_log_t));
        if (log == NULL) {
            return NGX_ERROR;
        }

    } else {
        /* no error logs at all */
        log = &cycle->new_log;
    }

    log->log_level = NGX_LOG_ERR;

    log->file = sx_conf_open_file(cycle, &cycle->error_log);
    if (log->file == NULL) {
        return NGX_ERROR;
    }

    if (log != &cycle->new_log) {
        sx_log_insert(&cycle->new_log, log);
    }

    return NGX_OK;
}


sx_int_t
sx_log_redirect_stderr(sx_cycle_t *cycle)
{
    sx_fd_t  fd;

    if (cycle->log_use_stderr) {
        return NGX_OK;
    }

    /* file log always exists when we are called */
    fd = sx_log_get_file_log(cycle->log)->file->fd;

    if (fd != sx_stderr) {
        if (sx_set_stderr(fd) == NGX_FILE_ERROR) {
            sx_log_error(NGX_LOG_ALERT, cycle->log, sx_errno,
                          sx_set_stderr_n " failed");

            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


sx_log_t *
sx_log_get_file_log(sx_log_t *head)
{
    sx_log_t  *log;

    for (log = head; log; log = log->next) {
        if (log->file != NULL) {
            return log;
        }
    }

    return NULL;
}


static char *
sx_log_set_levels(sx_conf_t *cf, sx_log_t *log)
{
    sx_uint_t   i, n, d, found;
    sx_str_t   *value;

    if (cf->args->nelts == 2) {
        log->log_level = NGX_LOG_ERR;
        return NGX_CONF_OK;
    }

    value = cf->args->elts;

    for (i = 2; i < cf->args->nelts; i++) {
        found = 0;

        for (n = 1; n <= NGX_LOG_DEBUG; n++) {
            if (sx_strcmp(value[i].data, err_levels[n].data) == 0) {

                if (log->log_level != 0) {
                    sx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "duplicate log level \"%V\"",
                                       &value[i]);
                    return NGX_CONF_ERROR;
                }

                log->log_level = n;
                found = 1;
                break;
            }
        }

        for (n = 0, d = NGX_LOG_DEBUG_FIRST; d <= NGX_LOG_DEBUG_LAST; d <<= 1) {
            if (sx_strcmp(value[i].data, debug_levels[n++]) == 0) {
                if (log->log_level & ~NGX_LOG_DEBUG_ALL) {
                    sx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid log level \"%V\"",
                                       &value[i]);
                    return NGX_CONF_ERROR;
                }

                log->log_level |= d;
                found = 1;
                break;
            }
        }


        if (!found) {
            sx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid log level \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }
    }

    if (log->log_level == NGX_LOG_DEBUG) {
        log->log_level = NGX_LOG_DEBUG_ALL;
    }

    return NGX_CONF_OK;
}


static char *
sx_error_log(sx_conf_t *cf, sx_command_t *cmd, void *conf)
{
    sx_log_t  *dummy;

    dummy = &cf->cycle->new_log;

    return sx_log_set_log(cf, &dummy);
}


char *
sx_log_set_log(sx_conf_t *cf, sx_log_t **head)
{
    sx_log_t          *new_log;
    sx_str_t          *value, name;
    sx_syslog_peer_t  *peer;

    if (*head != NULL && (*head)->log_level == 0) {
        new_log = *head;

    } else {

        new_log = sx_pcalloc(cf->pool, sizeof(sx_log_t));
        if (new_log == NULL) {
            return NGX_CONF_ERROR;
        }

        if (*head == NULL) {
            *head = new_log;
        }
    }

    value = cf->args->elts;

    if (sx_strcmp(value[1].data, "stderr") == 0) {
        sx_str_null(&name);
        cf->cycle->log_use_stderr = 1;

        new_log->file = sx_conf_open_file(cf->cycle, &name);
        if (new_log->file == NULL) {
            return NGX_CONF_ERROR;
        }

    } else if (sx_strncmp(value[1].data, "memory:", 7) == 0) {

#if (NGX_DEBUG)
        size_t                 size, needed;
        sx_pool_cleanup_t    *cln;
        sx_log_memory_buf_t  *buf;

        value[1].len -= 7;
        value[1].data += 7;

        needed = sizeof("MEMLOG  :" NGX_LINEFEED)
                 + cf->conf_file->file.name.len
                 + NGX_SIZE_T_LEN
                 + NGX_INT_T_LEN
                 + NGX_MAX_ERROR_STR;

        size = sx_parse_size(&value[1]);

        if (size == (size_t) NGX_ERROR || size < needed) {
            sx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid buffer size \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        buf = sx_pcalloc(cf->pool, sizeof(sx_log_memory_buf_t));
        if (buf == NULL) {
            return NGX_CONF_ERROR;
        }

        buf->start = sx_pnalloc(cf->pool, size);
        if (buf->start == NULL) {
            return NGX_CONF_ERROR;
        }

        buf->end = buf->start + size;

        buf->pos = sx_slprintf(buf->start, buf->end, "MEMLOG %uz %V:%ui%N",
                                size, &cf->conf_file->file.name,
                                cf->conf_file->line);

        sx_memset(buf->pos, ' ', buf->end - buf->pos);

        cln = sx_pool_cleanup_add(cf->pool, 0);
        if (cln == NULL) {
            return NGX_CONF_ERROR;
        }

        cln->data = new_log;
        cln->handler = sx_log_memory_cleanup;

        new_log->writer = sx_log_memory_writer;
        new_log->wdata = buf;

#else
        sx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "nginx was built without debug support");
        return NGX_CONF_ERROR;
#endif

    } else if (sx_strncmp(value[1].data, "syslog:", 7) == 0) {
        peer = sx_pcalloc(cf->pool, sizeof(sx_syslog_peer_t));
        if (peer == NULL) {
            return NGX_CONF_ERROR;
        }

        if (sx_syslog_process_conf(cf, peer) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }

        new_log->writer = sx_syslog_writer;
        new_log->wdata = peer;

    } else {
        new_log->file = sx_conf_open_file(cf->cycle, &value[1]);
        if (new_log->file == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    if (sx_log_set_levels(cf, new_log) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    if (*head != new_log) {
        sx_log_insert(*head, new_log);
    }

    return NGX_CONF_OK;
}


static void
sx_log_insert(sx_log_t *log, sx_log_t *new_log)
{
    sx_log_t  tmp;

    if (new_log->log_level > log->log_level) {

        /*
         * list head address is permanent, insert new log after
         * head and swap its contents with head
         */

        tmp = *log;
        *log = *new_log;
        *new_log = tmp;

        log->next = new_log;
        return;
    }

    while (log->next) {
        if (new_log->log_level > log->next->log_level) {
            new_log->next = log->next;
            log->next = new_log;
            return;
        }

        log = log->next;
    }

    log->next = new_log;
}


#if (NGX_DEBUG)

static void
sx_log_memory_writer(sx_log_t *log, sx_uint_t level, u_char *buf,
    size_t len)
{
    u_char                *p;
    size_t                 avail, written;
    sx_log_memory_buf_t  *mem;

    mem = log->wdata;

    if (mem == NULL) {
        return;
    }

    written = sx_atomic_fetch_add(&mem->written, len);

    p = mem->pos + written % (mem->end - mem->pos);

    avail = mem->end - p;

    if (avail >= len) {
        sx_memcpy(p, buf, len);

    } else {
        sx_memcpy(p, buf, avail);
        sx_memcpy(mem->pos, buf + avail, len - avail);
    }
}


static void
sx_log_memory_cleanup(void *data)
{
    sx_log_t *log = data;

    sx_log_debug0(NGX_LOG_DEBUG_CORE, log, 0, "destroy memory log buffer");

    log->wdata = NULL;
}

ngx_log_t *
ngx_log_init(u_char *prefix, u_char *error_log)
{
    u_char  *p, *name;
    size_t   nlen, plen;

    ngx_log.file = &ngx_log_file;
    ngx_log.log_level = NGX_LOG_NOTICE;

    if (error_log == NULL) {
        error_log = (u_char *) NGX_ERROR_LOG_PATH;
    }

    name = error_log;
    nlen = ngx_strlen(name);

    if (nlen == 0) {
        ngx_log_file.fd = ngx_stderr;
        return &ngx_log;
    }

    p = NULL;

#if (NGX_WIN32)
    if (name[1] != ':') {
#else
    if (name[0] != '/') {
#endif

        if (prefix) {
            plen = ngx_strlen(prefix);

        } else {
#ifdef NGX_PREFIX
            prefix = (u_char *) NGX_PREFIX;
            plen = ngx_strlen(prefix);
#else
            plen = 0;
#endif
        }

        if (plen) {
            name = malloc(plen + nlen + 2);
            if (name == NULL) {
                return NULL;
            }

            p = ngx_cpymem(name, prefix, plen);

            if (!ngx_path_separator(*(p - 1))) {
                *p++ = '/';
            }

            ngx_cpystrn(p, error_log, nlen + 1);

            p = name;
        }
    }

    ngx_log_file.fd = ngx_open_file(name, NGX_FILE_APPEND,
                                    NGX_FILE_CREATE_OR_OPEN,
                                    NGX_FILE_DEFAULT_ACCESS);

    if (ngx_log_file.fd == NGX_INVALID_FILE) {
        ngx_log_stderr(ngx_errno,
                       "[alert] could not open error log file: "
                       ngx_open_file_n " \"%s\" failed", name);
#if (NGX_WIN32)
        ngx_event_log(ngx_errno,
                       "could not open error log file: "
                       ngx_open_file_n " \"%s\" failed", name);
#endif

        ngx_log_file.fd = ngx_stderr;
    }

    if (p) {
        ngx_free(p);
    }

    return &ngx_log;
}

#endif
