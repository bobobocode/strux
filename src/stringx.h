
// BoBoBo

#ifndef _STRINGX_H_INCLUDED_
#define _STRINGX_H_INCLUDED_

#include "typex.h"

typedef struct {
    size_t      len;
    u_char     *data;
} sx_str_t;


typedef struct {
    sx_str_t   key;
    sx_str_t   value;
} sx_keyval_t;


typedef struct {
    unsigned    len:28;

    unsigned    valid:1;
    unsigned    no_cacheable:1;
    unsigned    not_found:1;
    unsigned    escape:1;

    u_char     *data;
} sx_variable_value_t;


#define sx_string(str)     { sizeof(str) - 1, (u_char *) str }
#define sx_null_string     { 0, NULL }
#define sx_str_set(str, text)                                               \
    (str)->len = sizeof(text) - 1; (str)->data = (u_char *) text
#define sx_str_null(str)   (str)->len = 0; (str)->data = NULL


#define sx_tolower(c)      (u_char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
#define sx_toupper(c)      (u_char) ((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)

void sx_strlow(u_char *dst, u_char *src, size_t n);


#define sx_strncmp(s1, s2, n)  strncmp((const char *) s1, (const char *) s2, n)


/* msvc and icc7 compile strcmp() to inline loop */
#define sx_strcmp(s1, s2)  strcmp((const char *) s1, (const char *) s2)


#define sx_strstr(s1, s2)  strstr((const char *) s1, (const char *) s2)
#define sx_strlen(s)       strlen((const char *) s)

size_t sx_strnlen(u_char *p, size_t n);

#define sx_strchr(s1, c)   strchr((const char *) s1, (int) c)

static sx_inline u_char *
sx_strlchr(u_char *p, u_char *last, u_char c)
{
    while (p < last) {

        if (*p == c) {
            return p;
        }

        p++;
    }

    return NULL;
}


/*
 * msvc and icc7 compile memset() to the inline "rep stos"
 * while ZeroMemory() and bzero() are the calls.
 * icc7 may also inline several mov's of a zeroed register for small blocks.
 */
#define sx_memzero(buf, n)       (void) memset(buf, 0, n)
#define sx_memset(buf, c, n)     (void) memset(buf, c, n)

void sx_explicit_memzero(void *buf, size_t n);


#if (SX_MEMCPY_LIMIT)

void *sx_memcpy(void *dst, const void *src, size_t n);
#define sx_cpymem(dst, src, n)   (((u_char *) sx_memcpy(dst, src, n)) + (n))

#else

/*
 * gcc3, msvc, and icc7 compile memcpy() to the inline "rep movs".
 * gcc3 compiles memcpy(d, s, 4) to the inline "mov"es.
 * icc8 compile memcpy(d, s, 4) to the inline "mov"es or XMM moves.
 */
#define sx_memcpy(dst, src, n)   (void) memcpy(dst, src, n)
#define sx_cpymem(dst, src, n)   (((u_char *) memcpy(dst, src, n)) + (n))

#endif


#if ( __INTEL_COMPILER >= 800 )

/*
 * the simple inline cycle copies the variable length strings up to 16
 * bytes faster than icc8 autodetecting _intel_fast_memcpy()
 */

static sx_inline u_char *
sx_copy(u_char *dst, u_char *src, size_t len)
{
    if (len < 17) {

        while (len) {
            *dst++ = *src++;
            len--;
        }

        return dst;

    } else {
        return sx_cpymem(dst, src, len);
    }
}

#else

#define sx_copy                  sx_cpymem

#endif


#define sx_memmove(dst, src, n)   (void) memmove(dst, src, n)
#define sx_movemem(dst, src, n)   (((u_char *) memmove(dst, src, n)) + (n))


/* msvc and icc7 compile memcmp() to the inline loop */
#define sx_memcmp(s1, s2, n)  memcmp((const char *) s1, (const char *) s2, n)


u_char *sx_cpystrn(u_char *dst, u_char *src, size_t n);
u_char * sx_cdecl sx_sprintf(u_char *buf, const char *fmt, ...);
u_char * sx_cdecl sx_snprintf(u_char *buf, size_t max, const char *fmt, ...);
u_char * sx_cdecl sx_slprintf(u_char *buf, u_char *last, const char *fmt,
    ...);
u_char *sx_vslprintf(u_char *buf, u_char *last, const char *fmt, va_list args);
#define sx_vsnprintf(buf, max, fmt, args)                                   \
    sx_vslprintf(buf, buf + (max), fmt, args)

sx_int_t sx_strcasecmp(u_char *s1, u_char *s2);
sx_int_t sx_strncasecmp(u_char *s1, u_char *s2, size_t n);

u_char *sx_strnstr(u_char *s1, char *s2, size_t n);

u_char *sx_strstrn(u_char *s1, char *s2, size_t n);
u_char *sx_strcasestrn(u_char *s1, char *s2, size_t n);
u_char *sx_strlcasestrn(u_char *s1, u_char *last, u_char *s2, size_t n);

sx_int_t sx_rstrncmp(u_char *s1, u_char *s2, size_t n);
sx_int_t sx_rstrncasecmp(u_char *s1, u_char *s2, size_t n);
sx_int_t sx_memn2cmp(u_char *s1, u_char *s2, size_t n1, size_t n2);
sx_int_t sx_dns_strcmp(u_char *s1, u_char *s2);
sx_int_t sx_filename_cmp(u_char *s1, u_char *s2, size_t n);

sx_int_t sx_atoi(u_char *line, size_t n);
sx_int_t sx_atofp(u_char *line, size_t n, size_t point);
ssize_t sx_atosz(u_char *line, size_t n);
off_t sx_atoof(u_char *line, size_t n);
time_t sx_atotm(u_char *line, size_t n);
sx_int_t sx_hextoi(u_char *line, size_t n);

u_char *sx_hex_dump(u_char *dst, u_char *src, size_t len);


#define sx_base64_encoded_length(len)  (((len + 2) / 3) * 4)
#define sx_base64_decoded_length(len)  (((len + 3) / 4) * 3)

void sx_encode_base64(sx_str_t *dst, sx_str_t *src);
void sx_encode_base64url(sx_str_t *dst, sx_str_t *src);
sx_int_t sx_decode_base64(sx_str_t *dst, sx_str_t *src);
sx_int_t sx_decode_base64url(sx_str_t *dst, sx_str_t *src);

uint32_t sx_utf8_decode(u_char **p, size_t n);
size_t sx_utf8_length(u_char *p, size_t n);
u_char *sx_utf8_cpystrn(u_char *dst, u_char *src, size_t n, size_t len);


#define SX_ESCAPE_URI            0
#define SX_ESCAPE_ARGS           1
#define SX_ESCAPE_URI_COMPONENT  2
#define SX_ESCAPE_HTML           3
#define SX_ESCAPE_REFRESH        4
#define SX_ESCAPE_MEMCACHED      5
#define SX_ESCAPE_MAIL_AUTH      6

#define SX_UNESCAPE_URI       1
#define SX_UNESCAPE_REDIRECT  2

uintptr_t sx_escape_uri(u_char *dst, u_char *src, size_t size,
    sx_uint_t type);
void sx_unescape_uri(u_char **dst, u_char **src, size_t size, sx_uint_t type);
uintptr_t sx_escape_html(u_char *dst, u_char *src, size_t size);
uintptr_t sx_escape_json(u_char *dst, u_char *src, size_t size);


typedef struct {
    sx_rbtree_node_t         node;
    sx_str_t                 str;
} sx_str_node_t;


void sx_str_rbtree_insert_value(sx_rbtree_node_t *temp,
    sx_rbtree_node_t *node, sx_rbtree_node_t *sentinel);
sx_str_node_t *sx_str_rbtree_lookup(sx_rbtree_t *rbtree, sx_str_t *name,
    uint32_t hash);


void sx_sort(void *base, size_t n, size_t size,
    sx_int_t (*cmp)(const void *, const void *));
#define sx_qsort             qsort


#define sx_value_helper(n)   #n
#define sx_value(n)          sx_value_helper(n)


#endif /* _STRINGX_H_INCLUDED_ */
