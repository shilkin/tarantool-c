#ifndef TP_H_INCLUDED
#define TP_H_INCLUDED

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "msgpuck.h"
#include "sha1.h"
#include "base64.h"

#ifdef __cplusplus
extern "C" {
#endif

#define tpfunction_unused __attribute__((unused))

#if !defined __GNUC_MINOR__ || defined __INTEL_COMPILER || \
	defined __SUNPRO_C || defined __SUNPRO_CC
#define TP_GCC_VERSION(major, minor) 0
#else
#define TP_GCC_VERSION(major, minor) (__GNUC__ > (major) || \
	(__GNUC__ == (major) && __GNUC_MINOR__ >= (minor)))
#endif

#if !defined(__has_builtin)
#define __has_builtin(x) 0 /* clang */
#endif

#if TP_GCC_VERSION(2, 9) || __has_builtin(__builtin_expect)
#define tplikely(x) __builtin_expect(!!(x), 1)
#define tpunlikely(x) __builtin_expect(!!(x), 0)
#else
#define tplikely(x) (x)
#define tpunlikely(x) (x)
#endif

struct tp;

typedef char *(*tp_reserve)(struct tp *p, size_t req, size_t *size);

/* available types */
enum tp_type {
	TP_NIL = MP_NIL,
	TP_UINT = MP_UINT,
	TP_INT = MP_INT,
	TP_STR = MP_STR,
	TP_BIN = MP_BIN,
	TP_ARRAY = MP_ARRAY,
	TP_MAP = MP_MAP,
	TP_BOOL = MP_BOOL,
	TP_FLOAT = MP_FLOAT,
	TP_DOUBLE = MP_DOUBLE,
	TP_EXT = MP_EXT
};

/* header */
enum tp_header_key_t {
	TP_CODE = 0x00,
	TP_SYNC = 0x01
};

/* request body */
enum tp_body_key_t {
	TP_SPACE = 0x10,
	TP_INDEX = 0x11,
	TP_LIMIT = 0x12,
	TP_OFFSET = 0x13,
	TP_ITERATOR = 0x14,
	TP_KEY = 0x20,
	TP_TUPLE = 0x21,
	TP_FUNCTION = 0x22,
	TP_USERNAME = 0x23
};

/* response body */
enum tp_response_key_t {
	TP_DATA = 0x30,
	TP_ERROR = 0x31
};

/* request types */
enum tp_request_type {
	TP_SELECT = 1,
	TP_INSERT = 2,
	TP_REPLACE = 3,
	TP_UPDATE = 4,
	TP_DELETE = 5,
	TP_CALL = 6,
	TP_AUTH = 7,
	TP_PING = 64
};

static const uint32_t SCRAMBLE_SIZE = 20;

/*
 * Main tp request object - points either to a request buffer.
 *
 * All fields except tp->p should not be accessed directly.
 * Appropriate accessors should be used instead.
*/
struct tp {
	char *s, *p, *e;       /* start, pos, end */
	char *size;            /* pointer to lenght field of current request */
	char *sync;            /* pointer to sync field of current request */
	tp_reserve reserve;    /* realloc function pointer */
	void *obj;             /* realloc function pointer */
};

/**
 * Get currently allocated buffer pointer
 */
static inline char*
tp_buf(struct tp *p)
{
	return p->s;
}

/**
 * Get currently allocated buffer size
 */
static inline size_t
tp_size(struct tp *p)
{
	return p->e - p->s;
}

/**
 * Get the size of data in the buffer
 */
static inline size_t
tp_used(struct tp *p)
{
	return p->p - p->s;
}

/**
 * Get the size available for write
 */
static inline size_t
tp_unused(struct tp *p)
{
	return p->e - p->p;
}

/**
 * A common reallocation function, can be used
 * for 'reserve' param in tp_init().
 * Resizes the buffer twice the previous size using realloc().
 *
 * struct tp req;
 * tp_init(&req, NULL, tp_realloc, NULL);
 * tp_ping(&req); // will call the reallocator
 *
 * data must be manually freed when the buffer is no longer
 * needed.
 * (eg. free(p->s) or tp_free(p) );
 * if realloc will return NULL, then you must destroy previous memory.
 * (eg.
 * if (tp_realloc(p, ..) == NULL) {
 * 	tp_free(p)
 * 	return NULL;
 * }
*/
tpfunction_unused static char*
tp_realloc(struct tp *p, size_t required, size_t *size)
{
	size_t toalloc = tp_size(p) * 2;
	if (tpunlikely(toalloc < required))
		toalloc = tp_size(p) + required;
	*size = toalloc;
	return realloc(p->s, toalloc);
}

/**
 * Free function for use in a pair with tp_realloc.
 * Don't use it when tp inited with static buffer!
 */
static inline void
tp_free(struct tp *p)
{
	free(p->s);
}

/**
 * Main initialization function.
 *
 * buf     - current buffer, may be NULL
 * size    - current buffer size
 * reserve - reallocation function, may be NULL
 * obj     - pointer to be passed to the reallocation function as
 *           context
 *
 * Either a buffer pointer or a reserve function must be
 * provided.
 * If reserve function is provided, data must be manually freed
 * when the buffer is no longer needed.
 *  (eg. free(p->s) or tp_free(p) );
 */
static inline void
tp_init(struct tp *p, char *buf, size_t size,
        tp_reserve reserve, void *obj)
{
	p->s = buf;
	p->p = p->s;
	p->e = p->s + size;
	p->size = NULL;
	p->sync = NULL;
	p->reserve = reserve;
	p->obj = obj;
}

/**
 * Ensure that buffer has enough space to fill size bytes, resize
 * buffer if needed. Returns -1 on error, and new allocated size
 * of success.
 */
static inline ssize_t
tp_ensure(struct tp *p, size_t size)
{
	if (tplikely(tp_unused(p) >= size))
		return 0;
	if (tpunlikely(p->reserve == NULL))
		return -1;
	size_t sz;
	char *np = p->reserve(p, size, &sz);
	if (tpunlikely(np == NULL))
		return -1;
	if (tplikely(p->size))
		p->size = (np + (((char*)p->size) - p->s));
	if (tplikely(p->sync))
		p->sync = (np + (((char*)p->sync) - p->s));
	p->p = np + (p->p - p->s);
	p->s = np;
	p->e = np + sz;
	return sz;
}

/**
 * Accept a data of specified size.
 * This is an function for internal use, and is not part of an API
 */
static inline char*
tp_add(struct tp *p, size_t size)
{
	void *ptr = p->p;
	p->p += size;
	assert(p->size);
	*p->size = 0xce;
	*(uint32_t*)(p->size + 1) = mp_bswap_u32(p->p - p->size - 5);
	return ptr;
}

/**
 * Append a select request.
 *
 * char buf[64];
 * struct tp req;
 * tp_init(&req, buf, sizeof(buf), NULL, NULL);
 * tp_select(&req, 0, 0, 0, 100);
 * tp_key(&req, 1);
 * tp_sz(&req, "key");
 */
static inline char*
tp_select(struct tp *p, uint32_t space, uint32_t index,
	  uint32_t offset, uint32_t limit)
{
	int sz = 5 +
		mp_sizeof_map(2) +
		mp_sizeof_uint(TP_CODE) +
		mp_sizeof_uint(TP_SELECT) +
		mp_sizeof_uint(TP_SYNC) +
		5 +
		mp_sizeof_map(5) +
		mp_sizeof_uint(TP_SPACE) +
		mp_sizeof_uint(space) +
		mp_sizeof_uint(TP_INDEX) +
		mp_sizeof_uint(index) +
		mp_sizeof_uint(TP_OFFSET) +
		mp_sizeof_uint(offset) +
		mp_sizeof_uint(TP_LIMIT) +
		mp_sizeof_uint(limit) +
		mp_sizeof_uint(TP_KEY);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	p->size = p->p;
	char *h = mp_encode_map(p->p + 5, 2);
	h = mp_encode_uint(h, TP_CODE);
	h = mp_encode_uint(h, TP_SELECT);
	h = mp_encode_uint(h, TP_SYNC);
	p->sync = h;
	*h = 0xce;
	*(uint32_t*)(h + 1) = 0;
	h += 5;
	h = mp_encode_map(h, 5);
	h = mp_encode_uint(h, TP_SPACE);
	h = mp_encode_uint(h, space);
	h = mp_encode_uint(h, TP_INDEX);
	h = mp_encode_uint(h, index);
	h = mp_encode_uint(h, TP_OFFSET);
	h = mp_encode_uint(h, offset);
	h = mp_encode_uint(h, TP_LIMIT);
	h = mp_encode_uint(h, limit);
	h = mp_encode_uint(h, TP_KEY);
	return tp_add(p, sz);
}

/**
 * Create an insert request.
 *
 * char buf[64];
 * struct tp req;
 * tp_init(&req, buf, sizeof(buf), NULL, NULL);
 * tp_insert(&req, 0);
 * tp_tuple(&req, 2);
 * tp_sz(&req, "key");
 * tp_sz(&req, "value");
 */
static inline char*
tp_insert(struct tp *p, uint32_t space)
{
	int sz = 5 +
		mp_sizeof_map(2) +
		mp_sizeof_uint(TP_CODE) +
		mp_sizeof_uint(TP_INSERT) +
		mp_sizeof_uint(TP_SYNC) +
		5 +
		mp_sizeof_map(5) +
		mp_sizeof_map(2) +
		mp_sizeof_uint(TP_SPACE) +
		mp_sizeof_uint(space) +
		mp_sizeof_uint(TP_TUPLE);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	p->size = p->p;
	char *h = mp_encode_map(p->p + 5, 2);
	h = mp_encode_uint(h, TP_CODE);
	h = mp_encode_uint(h, TP_INSERT);
	h = mp_encode_uint(h, TP_SYNC);
	p->sync = h;
	*h = 0xce;
	*(uint32_t*)(h + 1) = 0;
	h += 5;
	h = mp_encode_map(h, 2);
	h = mp_encode_uint(h, TP_SPACE);
	h = mp_encode_uint(h, space);
	h = mp_encode_uint(h, TP_TUPLE);
	return tp_add(p, sz);
}

/**
 * Create an replace request.
 *
 * char buf[64];
 * struct tp req;
 * tp_init(&req, buf, sizeof(buf), NULL, NULL);
 * tp_insert(&req, 0);
 * tp_tuple(&req, 2);
 * tp_sz(&req, "key");
 * tp_sz(&req, "value");
 */
static inline char*
tp_replace(struct tp *p, uint32_t space)
{
	int sz = 5 +
		mp_sizeof_map(2) +
		mp_sizeof_uint(TP_CODE) +
		mp_sizeof_uint(TP_REPLACE) +
		mp_sizeof_uint(TP_SYNC) +
		5 +
		mp_sizeof_map(2) +
		mp_sizeof_uint(TP_SPACE) +
		mp_sizeof_uint(space) +
		mp_sizeof_uint(TP_TUPLE);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	p->size = p->p;
	char *h = mp_encode_map(p->p + 5, 2);
	h = mp_encode_uint(h, TP_CODE);
	h = mp_encode_uint(h, TP_REPLACE);
	h = mp_encode_uint(h, TP_SYNC);
	p->sync = h;
	*h = 0xce;
	*(uint32_t*)(h + 1) = 0;
	h += 5;
	h = mp_encode_map(h, 2);
	h = mp_encode_uint(h, TP_SPACE);
	h = mp_encode_uint(h, space);
	h = mp_encode_uint(h, TP_TUPLE);
	return tp_add(p, sz);
}

/**
 * Create a delete request.
 *
 * char buf[64];
 * struct tp req;
 * tp_init(&req, buf, sizeof(buf), NULL, NULL);
 * tp_delete(&req, 0);
 * tp_key(&req, 1);
 * tp_sz(&req, "key");
 */
static inline char*
tp_delete(struct tp *p, uint32_t space)
{
	int sz = 5 +
		mp_sizeof_map(2) +
		mp_sizeof_uint(TP_CODE) +
		mp_sizeof_uint(TP_DELETE) +
		mp_sizeof_uint(TP_SYNC) +
		5 +
		mp_sizeof_map(2) +
		mp_sizeof_uint(TP_SPACE) +
		mp_sizeof_uint(space) +
		mp_sizeof_uint(TP_KEY);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	p->size = p->p;
	char *h = mp_encode_map(p->p + 5, 2);
	h = mp_encode_uint(h, TP_CODE);
	h = mp_encode_uint(h, TP_DELETE);
	h = mp_encode_uint(h, TP_SYNC);
	p->sync = h;
	*h = 0xce;
	*(uint32_t*)(h + 1) = 0;
	h += 5;
	h = mp_encode_map(h, 2);
	h = mp_encode_uint(h, TP_SPACE);
	h = mp_encode_uint(h, space);
	h = mp_encode_uint(h, TP_KEY);
	return tp_add(p, sz);
}

/**
 * Create a call request.
 *
 * char buf[64];
 * struct tp req;
 * tp_init(&req, buf, sizeof(buf), NULL, NULL);
 *
 * char proc[] = "hello_proc";
 * tp_call(&req, proc, sizeof(proc) - 1);
 * tp_encode_array(&req, 2);
 * tp_sz(&req, "arg1");
 * tp_sz(&req, "arg2");
 */
static inline char*
tp_call(struct tp *p, const char *function, int len)
{
	int sz = 5 +
		mp_sizeof_map(2) +
		mp_sizeof_uint(TP_CODE) +
		mp_sizeof_uint(TP_CALL) +
		mp_sizeof_uint(TP_SYNC) +
		5 +
		mp_sizeof_map(2) +
		mp_sizeof_uint(TP_FUNCTION) +
		mp_sizeof_str(len) +
		mp_sizeof_uint(TP_TUPLE);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	p->size = p->p;
	char *h = mp_encode_map(p->p + 5, 2);
	h = mp_encode_uint(h, TP_CODE);
	h = mp_encode_uint(h, TP_CALL);
	h = mp_encode_uint(h, TP_SYNC);
	p->sync = h;
	*h = 0xce;
	*(uint32_t*)(h + 1) = 0;
	h += 5;
	h = mp_encode_map(h, 2);
	h = mp_encode_uint(h, TP_FUNCTION);
	h = mp_encode_str(h, function, len);
	h = mp_encode_uint(h, TP_TUPLE);
	return tp_add(p, sz);
}

/**
 * Create a ping request.
 *
 * char buf[64];
 * struct tp req;
 * tp_init(&req, buf, sizeof(buf), NULL, NULL);
 * tp_ping(&req);
 */
static inline char*
tp_ping(struct tp *p)
{
	int sz = 5 +
		mp_sizeof_map(2) +
		mp_sizeof_uint(TP_CODE) +
		mp_sizeof_uint(TP_PING) +
		mp_sizeof_uint(TP_SYNC) +
		5;
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	p->size = p->p;
	char *h = mp_encode_map(p->p + 5, 2);
	h = mp_encode_uint(h, TP_CODE);
	h = mp_encode_uint(h, TP_PING);
	h = mp_encode_uint(h, TP_SYNC);
	p->sync = h;
	*h = 0xce;
	*(uint32_t*)(h + 1) = 0;
	h += 5;
	return tp_add(p, sz);
}

/**
 * Create an update request.
 *
 * char buf[64];
 * struct tp req;
 * tp_init(&req, buf, sizeof(buf), NULL, NULL);
 * tp_update(&req, 0); // update of space 0
 * tp_key(&req, 1); // key with one part
 * tp_sz(&req, "key"); // one and only part of the key
 * tp_updatebegin(&req, 2); // update with two operations
 * tp_op(&req, "+", 2); // add to field 2 ..
 * tp_encode_uint(&req, 1); // .. a value 1
 * tp_op(&req, "=", 3); // set a field 3 ..
 * tp_sz(&req, "value"); // .. a value "value"
 */
static inline char*
tp_update(struct tp *p, uint32_t space)
{
	int sz = 5 +
		mp_sizeof_map(2) +
		mp_sizeof_uint(TP_CODE) +
		mp_sizeof_uint(TP_UPDATE) +
		mp_sizeof_uint(TP_SYNC) +
		5 +
		mp_sizeof_map(3) +
		mp_sizeof_uint(TP_SPACE) +
		mp_sizeof_uint(space) +
		mp_sizeof_uint(TP_KEY);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	p->size = p->p;
	char *h = mp_encode_map(p->p + 5, 2);
	h = mp_encode_uint(h, TP_CODE);
	h = mp_encode_uint(h, TP_UPDATE);
	h = mp_encode_uint(h, TP_SYNC);
	p->sync = h;
	*h = 0xce;
	*(uint32_t*)(h + 1) = 0;
	h += 5;
	h = mp_encode_map(h, 3);
	h = mp_encode_uint(h, TP_SPACE);
	h = mp_encode_uint(h, space);
	h = mp_encode_uint(h, TP_KEY);
	return tp_add(p, sz);
}

/**
 * Begin update operations.
 * See tp_update description for details.
 */
static inline char*
tp_updatebegin(struct tp *p, uint32_t op_count)
{
	int sz = mp_sizeof_uint(TP_TUPLE) + mp_sizeof_array(op_count);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	char *h = mp_encode_uint(p->p, TP_TUPLE);
	mp_encode_array(h, op_count);
	return tp_add(p, sz);
}

/**
 * Add an update operation.
 * See tp_update description.
 * Operation op could be:
 * "=" - assign operation argument to field <field_no>;
 *  will extend the tuple if <field_no> == <max_field_no> + 1
 * "#" - delete <argument> fields starting from <field_no>
 * "!" - insert <argument> before <field_no>
 * The following operation(s) are only defined for integer
 * types:
 * "+" - add argument to field <field_no>, argument
 * are integer
 * "-" - subtract argument from the field <field_no>
 * "&" - bitwise AND of argument and field <field_no>
 * "^" - bitwise XOR of argument and field <field_no>
 * "|" - bitwise OR of argument and field <field_no>
 */
static inline char*
tp_op(struct tp *p, char op, uint32_t field_no)
{
	int sz = mp_sizeof_array(3) + mp_sizeof_str(1) +
		mp_sizeof_uint(field_no);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	char *h = mp_encode_array(p->p, 3);
	h = mp_encode_str(h, &op, 1);
	h = mp_encode_uint(h, field_no);
	return tp_add(p, sz);
}

/**
 * xor
 * The function is for internal use, not part of the API
 */
static inline void
xor(unsigned char *to, unsigned const char *left,
    unsigned const char *right, uint32_t len)
{
	const uint8_t *end = to + len;
	while (to < end)
		*to++= *left++ ^ *right++;
}

/**
 * scramble_prepare
 * The function is for internal use, not part of the API
 */
static inline void
scramble_prepare(void *out, const void *salt, const void *password,
		 int password_len)
{
	unsigned char hash1[SCRAMBLE_SIZE];
	unsigned char hash2[SCRAMBLE_SIZE];
	SHA1_CTX ctx;

	SHA1Init(&ctx);
	SHA1Update(&ctx, password, password_len);
	SHA1Final(hash1, &ctx);

	SHA1Init(&ctx);
	SHA1Update(&ctx, hash1, SCRAMBLE_SIZE);
	SHA1Final(hash2, &ctx);

	SHA1Init(&ctx);
	SHA1Update(&ctx, salt, SCRAMBLE_SIZE);
	SHA1Update(&ctx, hash2, SCRAMBLE_SIZE);
	SHA1Final(out, &ctx);

	xor(out, hash1, out, SCRAMBLE_SIZE);
}

static inline char*
tp_auth(struct tp *p, const char *salt_base64, const char *user, int ulen, const char *pass, int plen)
{
	int sz = 5 +
		mp_sizeof_map(2) +
		mp_sizeof_uint(TP_CODE) +
		mp_sizeof_uint(TP_AUTH) +
		mp_sizeof_uint(TP_SYNC) +
		5 +
		mp_sizeof_map(2) +
		mp_sizeof_uint(TP_USERNAME) +
		mp_sizeof_str(ulen) +
		mp_sizeof_uint(TP_TUPLE) +
		mp_sizeof_array(2) +
		mp_sizeof_str(0) +
		mp_sizeof_str(SCRAMBLE_SIZE);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	p->size = p->p;
	char *h = mp_encode_map(p->p + 5, 2);
	h = mp_encode_uint(h, TP_CODE);
	h = mp_encode_uint(h, TP_AUTH);
	h = mp_encode_uint(h, TP_SYNC);
	p->sync = h;
	*h = 0xce;
	*(uint32_t*)(h + 1) = 0;
	h += 5;
	h = mp_encode_map(h, 2);
	h = mp_encode_uint(h, TP_USERNAME);
	h = mp_encode_str(h, user, ulen);
	h = mp_encode_uint(h, TP_TUPLE);
	h = mp_encode_array(h, 2);
	h = mp_encode_str(h, 0, 0);

	char salt[64];
	base64_decode(salt_base64, 44, salt, 64);
	char scramble[SCRAMBLE_SIZE];
	scramble_prepare(scramble, salt, pass, plen);
	h = mp_encode_str(h, scramble, SCRAMBLE_SIZE);

	return tp_add(p, sz);
}

/**
 * Set the current request id.
 */
static inline void
tp_reqid(struct tp *p, uint32_t reqid)
{
	assert(p->sync != NULL);
	char *h = p->sync;
	*h = 0xce;
	*(uint32_t*)(h + 1) = mp_bswap_u32(reqid);
}

static inline char*
tp_encode_nil(struct tp *p)
{
	int sz = mp_sizeof_nil();
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	mp_encode_nil(p->p);
	return tp_add(p, sz);
}

static inline char*
tp_encode_uint(struct tp *p, uint64_t num)
{
	int sz = mp_sizeof_uint(num);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	mp_encode_uint(p->p, num);
	return tp_add(p, sz);
}

static inline char*
tp_encode_int(struct tp *p, int64_t num)
{
	int sz = mp_sizeof_int(num);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	mp_encode_int(p->p, num);
	return tp_add(p, sz);
}

static inline char*
tp_encode_str(struct tp *p, const char *str, uint32_t len)
{
	int sz = mp_sizeof_str(len);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	mp_encode_str(p->p, str, len);
	return tp_add(p, sz);
}

static inline char*
tp_encode_sz(struct tp *p, const char *str)
{
	uint32_t len = (uint32_t)strlen(str);
	int sz = mp_sizeof_str(len);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	mp_encode_str(p->p, str, len);
	return tp_add(p, sz);
}

static inline char*
tp_sz(struct tp *p, const char *str)
{
	return tp_encode_sz(p, str);
}

static inline char*
tp_encode_bin(struct tp *p, const char *str, uint32_t len)
{
	int sz = mp_sizeof_bin(len);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	mp_encode_bin(p->p, str, len);
	return tp_add(p, sz);
}

static inline char*
tp_encode_array(struct tp *p, uint32_t size)
{
	int sz = mp_sizeof_array(size);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	mp_encode_array(p->p, size);
	return tp_add(p, sz);
}

static inline char*
tp_encode_map(struct tp *p, uint32_t size)
{
	int sz = mp_sizeof_map(size);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	mp_encode_map(p->p, size);
	return tp_add(p, sz);
}

static inline char*
tp_encode_bool(struct tp *p, bool val)
{
	int sz = mp_sizeof_bool(val);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	mp_encode_bool(p->p, val);
	return tp_add(p, sz);
}

static inline char*
tp_encode_float(struct tp *p, float num)
{
	int sz = mp_sizeof_float(num);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	mp_encode_float(p->p, num);
	return tp_add(p, sz);
}

static inline char*
tp_encode_double(struct tp *p, double num)
{
	int sz = mp_sizeof_double(num);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	mp_encode_double(p->p, num);
	return tp_add(p, sz);
}

/* Write a tuple header */
static inline char*
tp_tuple(struct tp *p, uint32_t field_count)
{
	return tp_encode_array(p, field_count);
}

/* Write a key header */
static inline char*
tp_key(struct tp *p, uint32_t part_count)
{
	return tp_encode_array(p, part_count);
}


struct tpgreetings {
	const char *description;
	const char *salt_base64;
};

static inline int64_t
tp_greetings(struct tpgreetings *g, char *buf, size_t size)
{
	if (size < 128)
		return -1;
	g->description = buf;
	g->salt_base64 = buf + 64;
	return size - 128;
}

struct tp_array_itr {
	const char *data;
	const char *first_elem;
	const char *elem;
	const char *elem_end;
	uint32_t elem_count;
	int cur_index;
};

static inline int
tp_array_itr_init(struct tp_array_itr *itr, const char *data, size_t size)
{
	memset(itr, 0, sizeof(*itr));
	if (size == 0 || mp_typeof(*data) != MP_ARRAY)
		return -1;
	const char *e = data;
	if (mp_check(&e, data + size))
		return -1;
	itr->data = data;
	itr->first_elem = data;
	itr->elem_count = mp_decode_array(&itr->first_elem);
	itr->cur_index = -1;
	return 0;
}

static inline bool
tp_array_itr_next(struct tp_array_itr *itr)
{
	itr->cur_index++;
	if ((uint32_t)itr->cur_index >= itr->elem_count)
		return false;
	if (itr->cur_index == 0)
		itr->elem = itr->first_elem;
	else
		itr->elem = itr->elem_end;
	itr->elem_end = itr->elem;
	mp_next(&itr->elem_end);
	return true;
}

static inline void
tp_array_itr_reset(struct tp_array_itr *itr)
{
	itr->cur_index = -1;
	itr->elem = 0;
	itr->elem_end = 0;
}

struct tp_map_itr {
	const char *data;
	const char *first_key;
	const char *key;
	const char *key_end;
	const char *value;
	const char *value_end;
	uint32_t pair_count;
	int cur_index;
};

static inline int
tp_map_itr_init(struct tp_map_itr *itr, const char *data, size_t size)
{
	memset(itr, 0, sizeof(*itr));
	if (size == 0 || mp_typeof(*data) != MP_MAP)
		return -1;
	const char *e = data;
	if (mp_check(&e, data + size))
		return -1;
	itr->data = data;
	itr->first_key = data;
	itr->pair_count = mp_decode_array(&itr->first_key);
	itr->cur_index = -1;
	return 0;
}

static inline bool
tp_map_itr_next(struct tp_map_itr *itr)
{
	itr->cur_index++;
	if ((uint32_t)itr->cur_index >= itr->pair_count)
		return false;
	if (itr->cur_index == 0)
		itr->key = itr->first_key;
	else
		itr->key = itr->value_end;
	itr->key_end = itr->key;
	mp_next(&itr->value);
	itr->value = itr->key_end;
	itr->value_end = itr->value;
	mp_next(&itr->value_end);
	return true;
}

static inline void
tp_map_itr_reset(struct tp_map_itr *itr)
{
	itr->cur_index = -1;
	itr->key = 0;
	itr->key_end = 0;
	itr->value = 0;
	itr->value_end = 0;
}

struct tpresponse {
	uint64_t bitmap;
	const char *buf;
	uint32_t code;
	uint32_t sync;
	const char *error;
	const char *error_end;
	const char *data;
	const char *data_end;
	struct tp_array_itr tuple_itr;
	struct tp_array_itr field_itr;
};

static inline int64_t
tp_reply(struct tpresponse *r, const char * const buf, size_t size)
{
	memset(r, 0, sizeof(*r));
	if (size == 0)
		return 0;
	const char *p = buf;
	/* len */
	const char *test = p;
	if (mp_check(&test, buf + size))
		return -1;
	if (mp_typeof(*p) != MP_UINT)
		return -1;
	uint32_t len = mp_decode_uint(&p);
	if (size < len + (uint32_t)(p - buf))
		return 0;
	/* header */
	test = p;
	if (mp_check(&test, buf + size))
		return -1;
	if (mp_typeof(*p) != MP_MAP)
		return -1;
	uint32_t n = mp_decode_map(&p);
	while (n-- > 0) {
		if (mp_typeof(*p) != MP_UINT)
			return -1;
		uint32_t key = mp_decode_uint(&p);
		if (mp_typeof(*p) != MP_UINT)
			return -1;
		switch (key) {
		case TP_SYNC:
			if (mp_typeof(*p) != MP_UINT)
				return -1;
			r->sync = mp_decode_uint(&p);
			break;
		case TP_CODE:
			if (mp_typeof(*p) != MP_UINT)
				return -1;
			r->code = mp_decode_uint(&p);
			break;
		default:
			return -1;
		}
		r->bitmap |= (1ULL << key);
	}

	/* body */
	if (p == buf + len + 5)
		return len + 5; /* no body */
	test = p;
	if (mp_check(&test, buf + size))
		return -1;
	if (mp_typeof(*p) != MP_MAP)
		return -1;
	n = mp_decode_map(&p);
	while (n-- > 0) {
		uint32_t key = mp_decode_uint(&p);
		switch (key) {
		case TP_ERROR: {
			if (mp_typeof(*p) != MP_STR)
				return -1;
			uint32_t elen = 0;
			r->error = mp_decode_str(&p, &elen);
			r->error_end = r->error + elen;
			break;
		}
		case TP_DATA: {
			if (mp_typeof(*p) != MP_ARRAY)
				return -1;
			r->data = p;
			mp_next(&p);
			r->data_end = p;
			break;
		}
		}
		r->bitmap |= (1ULL << key);
	}
	if (r->data) {
		if (tp_array_itr_init(&r->tuple_itr, r->data, r->data_end - r->data))
			return -1;
	}
	return p - buf;
}

/**
 * Return the current request id
 */
static inline uint32_t
tp_getreqid(struct tpresponse *r)
{
	return r->sync;
}

/**
 * Check if the response has a tuple.
 * Automatically checked during tp_next() iteration.
 */
static inline int
tp_hasdata(struct tpresponse *r)
{
	return r->tuple_itr.elem_count > 0;
}

/**
 * Get tuple count in responce
 */
static inline uint32_t
tp_tuplecount(const struct tpresponse *r)
{
	return r->tuple_itr.elem_count;
}

/**
 * Rewind iteration to the first tuple.
 * Note that initialization of tpresponse via tp_reply
 * rewinds tuple iteration automatically
 */
static inline void
tp_rewind(struct tpresponse *r)
{
	tp_array_itr_reset(&r->tuple_itr);
	memset(&r->field_itr, 0, sizeof(r->field_itr));
}

/**
 * Skip to the next tuple or to the first tuple after rewind
 */
static inline int
tp_next(struct tpresponse *r)
{
	if (!tp_array_itr_next(&r->tuple_itr)) {
		memset(&r->field_itr, 0, sizeof(r->field_itr));
		return 0;
	}
	tp_array_itr_init(&r->field_itr, r->tuple_itr.elem, r->tuple_itr.elem_end - r->tuple_itr.elem);
	return 1;

}

/**
 * Check if there is a one more tuple.
 */
static inline int
tp_hasnext(struct tpresponse *r)
{
	return (uint32_t)(r->tuple_itr.cur_index + 1) < r->tuple_itr.elem_count;
}

/**
 * Get the current tuple data, all fields.
 */
static inline const char *
tp_gettuple(struct tpresponse *r)
{
	return r->tuple_itr.elem;
}

/**
 * Get the current tuple size in bytes.
 */
static inline uint32_t
tp_tuplesize(struct tpresponse *r)
{
	return (uint32_t)(r->tuple_itr.elem_end - r->tuple_itr.elem);
}

/**
 *  Get a pointer to the end of the current tuple.
 */
static inline const char *
tp_tupleend(struct tpresponse *r)
{
	return r->tuple_itr.elem_end;
}

/*
 * Rewind iteration to the first tuple field of the current tuple.
 * Note that iterating tuples of the response
 * rewinds field iteration automatically
 */
static inline void
tp_rewindfield(struct tpresponse *r)
{
	tp_array_itr_reset(&r->field_itr);
}

/**
 * Skip to the next field.
 */
static inline int
tp_nextfield(struct tpresponse *r) {
	return tp_array_itr_next(&r->field_itr);
}

/*
 * Check if the current tuple has a one more field.
 */
static inline int
tp_hasnextfield(struct tpresponse *r) {
	return (uint32_t)(r->field_itr.cur_index + 1) < r->field_itr.elem_count;
}


/**
 * Get the current field.
 */
static inline const char *
tp_getfield(struct tpresponse *r)
{
	return r->field_itr.elem;
}

/**
 * Get the current field size in bytes.
 */
static inline uint32_t
tp_getfieldsize(struct tpresponse *r)
{
	return (uint32_t)(r->field_itr.elem_end - r->field_itr.elem);
}

/*
 * Determine MsgPack type by a first byte \a c of encoded data.
 */
static inline enum tp_type
tp_typeof(const char c)
{
	return mp_typeof(c);
}

static inline uint64_t
tp_get_uint(const char *field)
{
	return mp_decode_uint(&field);
}

static inline int64_t
tp_get_int(const char *field)
{
	return mp_decode_int(&field);
}

static inline float
tp_get_float(const char *field)
{
	return mp_decode_float(&field);
}

static inline double
tp_get_double(const char *field)
{
	return mp_decode_double(&field);
}

static inline bool
tp_get_bool(const char *field)
{
	return mp_decode_bool(&field);
}

static inline const char *
tp_get_str(const char *field, uint32_t *size)
{
	return mp_decode_str(&field, size);
}

static inline const char *
tp_get_bin(const char *field, uint32_t *size)
{
	return mp_decode_bin(&field, size);
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
