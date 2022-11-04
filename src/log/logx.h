
// BoBoBo

#ifndef _LOGX_H_INCLUDED_
#define _LOGX_H_INCLUDED_


#define SX_LOG_STDERR            0
#define SX_LOG_EMERG             1
#define SX_LOG_ALERT             2
#define SX_LOG_CRIT              3
#define SX_LOG_ERR               4
#define SX_LOG_WARN              5
#define SX_LOG_NOTICE            6
#define SX_LOG_INFO              7
#define SX_LOG_DEBUG             8

#define SX_LOG_DEBUG_CORE        0x010
#define SX_LOG_DEBUG_ALLOC       0x020
#define SX_LOG_DEBUG_MUTEX       0x040
#define SX_LOG_DEBUG_EVENT       0x080
#define SX_LOG_DEBUG_HTTP        0x100
#define SX_LOG_DEBUG_MAIL        0x200
#define SX_LOG_DEBUG_STREAM      0x400

/*
 * do not forget to update debug_levels[] in src/core/sx_log.c
 * after the adding a new debug level
 */

#define SX_LOG_DEBUG_FIRST       SX_LOG_DEBUG_CORE
#define SX_LOG_DEBUG_LAST        SX_LOG_DEBUG_STREAM
#define SX_LOG_DEBUG_CONNECTION  0x80000000
#define SX_LOG_DEBUG_ALL         0x7ffffff0


typedef u_char *(*sx_log_handler_pt) (sx_log_t *log, u_char *buf, size_t len);
typedef void (*sx_log_writer_pt) (sx_log_t *log, sx_uint_t level,
    u_char *buf, size_t len);


struct sx_log_s {
    sx_uint_t           log_level;
    sx_open_file_t     *file;

    sx_atomic_uint_t    connection;

    time_t               disk_full_time;

    sx_log_handler_pt   handler;
    void                *data;

    sx_log_writer_pt    writer;
    void                *wdata;

    /*
     * we declare "action" as "char *" because the actions are usually
     * the static strings and in the "u_char *" case we have to override
     * their types all the time
     */

    char                *action;

    sx_log_t           *next;
};


#define SX_MAX_ERROR_STR   2048


/*********************************/

#if (SX_HAVE_C99_VARIADIC_MACROS)

#define SX_HAVE_VARIADIC_MACROS  1

#define sx_log_error(level, log, ...)                                        \
    if ((log)->log_level >= level) sx_log_error_core(level, log, __VA_ARGS__)

void sx_log_error_core(sx_uint_t level, sx_log_t *log, sx_err_t err,
    const char *fmt, ...);

#define sx_log_debug(level, log, ...)                                        \
    if ((log)->log_level & level)                                             \
        sx_log_error_core(SX_LOG_DEBUG, log, __VA_ARGS__)

/*********************************/

#elif (SX_HAVE_GCC_VARIADIC_MACROS)

#define SX_HAVE_VARIADIC_MACROS  1

#define sx_log_error(level, log, args...)                                    \
    if ((log)->log_level >= level) sx_log_error_core(level, log, args)

void sx_log_error_core(sx_uint_t level, sx_log_t *log, sx_err_t err,
    const char *fmt, ...);

#define sx_log_debug(level, log, args...)                                    \
    if ((log)->log_level & level)                                             \
        sx_log_error_core(SX_LOG_DEBUG, log, args)

/*********************************/

#else /* no variadic macros */

#define SX_HAVE_VARIADIC_MACROS  0

void sx_cdecl sx_log_error(sx_uint_t level, sx_log_t *log, sx_err_t err,
    const char *fmt, ...);
void sx_log_error_core(sx_uint_t level, sx_log_t *log, sx_err_t err,
    const char *fmt, va_list args);
void sx_cdecl sx_log_debug_core(sx_log_t *log, sx_err_t err,
    const char *fmt, ...);


#endif /* variadic macros */


/*********************************/

sx_log_t *sx_log_init(u_char *prefix, u_char *error_log);
void sx_cdecl sx_log_abort(sx_err_t err, const char *fmt, ...);
void sx_cdecl sx_log_stderr(sx_err_t err, const char *fmt, ...);
u_char *sx_log_errno(u_char *buf, u_char *last, sx_err_t err);
sx_int_t sx_log_open_default(sx_cycle_t *cycle);
sx_int_t sx_log_redirect_stderr(sx_cycle_t *cycle);
sx_log_t *sx_log_get_file_log(sx_log_t *head);
char *sx_log_set_log(sx_conf_t *cf, sx_log_t **head);


/*
 * sx_write_stderr() cannot be implemented as macro, since
 * MSVC does not allow to use #ifdef inside macro parameters.
 *
 * sx_write_fd() is used instead of sx_write_console(), since
 * CharToOemBuff() inside sx_write_console() cannot be used with
 * read only buffer as destination and CharToOemBuff() is not needed
 * for sx_write_stderr() anyway.
 */
static inline void
sx_write_stderr(char *text)
{
    (void) sx_write_fd(sx_stderr, text, sx_strlen(text));
}


static inline void
sx_write_stdout(char *text)
{
    (void) sx_write_fd(sx_stdout, text, sx_strlen(text));
}


extern sx_module_t  sx_errlog_module;
extern sx_uint_t    sx_use_stderr;


#endif /* _LOGX_H_INCLUDED_ */
