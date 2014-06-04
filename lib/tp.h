#ifndef TP_H_INCLUDED
#define TP_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#define tpfunction_unused __attribute__((unused))
#define tppacked __attribute__((packed))
#define tpinline __attribute__((forceinline))
#define tpnoinline __attribute__((noinline))
#if defined(__GNUC__)
#if (__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
#define tphot __attribute__((hot))
#endif
#endif
#if !defined(tphot)
#define tphot
#endif

#define tplikely(expr) __builtin_expect(!! (expr), 1)
#define tpunlikely(expr) __builtin_expect(!! (expr), 0)

struct tp;

typedef char *(*tp_reserve)(struct tp *p, size_t req, size_t *size);

/* header */
#define TP_CODE     0x00
#define TP_SYNC     0x01

/* request body */
#define TP_SPACE    0x10
#define TP_INDEX    0x11
#define TP_LIMIT    0x12
#define TP_OFFSET   0x13
#define TP_ITERATOR 0x14
#define TP_KEY      0x20
#define TP_TUPLE    0x21
#define TP_FUNCTION 0x22

/* response body */
#define TP_DATA     0x30
#define TP_ERROR    0x31

/* code types */
#define TP_PING     0
#define TP_SELECT   1
#define TP_INSERT   2
#define TP_REPLACE  3
#define TP_UPDATE   4
#define TP_DELETE   5
#define TP_CALL     6
#define TP_AUTH     7

struct tp {
	char *s, *p, *e;
	char *h;
	tp_reserve reserve;
	void *obj;
};

static inline size_t
tp_size(struct tp *p) {
	return p->e - p->s;
}

static inline size_t
tp_used(struct tp *p) {
	return p->p - p->s;
}

static inline size_t
tp_unused(struct tp *p) {
	return p->e - p->p;
}

tpfunction_unused static char*
tp_realloc(struct tp *p, size_t required, size_t *size) {
	size_t toalloc = tp_size(p) * 2;
	if (tpunlikely(toalloc < required))
		toalloc = tp_size(p) + required;
	*size = toalloc;
	return realloc(p->s, toalloc);
}

static inline void
tp_free(struct tp *p) {
	free(p->s);
}

static inline char*
tp_buf(struct tp *p) {
	return p->s;
}

static inline void
tp_init(struct tp *p, char *buf, size_t size,
        tp_reserve reserve, void *obj) {
	p->h = NULL;
	p->s = buf;
	p->p = p->s;
	p->e = p->s + size;
	p->reserve = reserve;
	p->obj = obj;
}

static tpnoinline ssize_t
tp_ensure(struct tp *p, size_t size) {
	if (tplikely(tp_unused(p) >= size))
		return 0;
	if (tpunlikely(p->reserve == NULL))
		return -1;
	size_t sz;
	register char *np = p->reserve(p, size, &sz);
	if (tpunlikely(np == NULL))
		return -1;
	if (tplikely(p->h))
		p->h = (np + (((char*)p->h) - p->s));
	p->p = np + (p->p - p->s);
	p->s = np;
	p->e = np + sz;
	return sz;
}

static inline ssize_t
tp_use(struct tp *p, size_t size) {
	p->p += size;
	return tp_used(p);
}

static inline ssize_t
tp_append(struct tp *p, const void *data, size_t size) {
	if (tpunlikely(tp_ensure(p, size) == -1))
		return -1;
	memcpy(p->p, data, size);
	return tp_use(p, size);
}

static inline char*
tp_add(struct tp *p, size_t size) {
	void *ptr = p->p;
	p->p += size;
	if (tpunlikely(p->h == NULL))
		return ptr;
	char *h = p->h;
	*h = 0xce;
	*(uint32_t*)(h + 1) = mp_bswap_u32(p->p - p->h - 5);
	return ptr;
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
tp_encode_uint(struct tp *p, uint64_t num)
{
	int sz = mp_sizeof_uint(num);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	mp_encode_uint(p->p, num);
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

static inline char*
tp_encode_strl(struct tp *p, uint32_t len)
{
	int sz = mp_sizeof_strl(len);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	mp_encode_strl(p->p, len);
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
tp_encode_binl(struct tp *p, uint32_t len)
{
	int sz = mp_sizeof_binl(len);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	mp_encode_binl(p->p, len);
	return tp_add(p, sz);
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
tp_encode_nil(struct tp *p)
{
	int sz = mp_sizeof_nil();
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	mp_encode_nil(p->p);
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
tp_insert(struct tp *p, uint32_t space)
{
	int sz = 5 +
		mp_sizeof_uint(TP_CODE) +
		mp_sizeof_uint(TP_INSERT) +
		mp_sizeof_map(2) +
		mp_sizeof_uint(TP_SPACE) +
		mp_sizeof_uint(space) +
		mp_sizeof_uint(TP_TUPLE);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	char *h = mp_encode_map(p->p, 2);
	h = mp_encode_uint(h, TP_CODE);
	h = mp_encode_uint(h, TP_INSERT);
	h = mp_encode_map(h, 2);
	h = mp_encode_uint(h, TP_SPACE);
	h = mp_encode_uint(h, space);
	h = mp_encode_uint(h, TP_TUPLE);
	return tp_add(p, sz);
}

static inline char*
tp_replace(struct tp *p, uint32_t space)
{
	int sz = 5 +
		mp_sizeof_uint(TP_CODE) +
		mp_sizeof_uint(TP_REPLACE) +
		mp_sizeof_map(2) +
		mp_sizeof_uint(TP_SPACE) +
		mp_sizeof_uint(space) +
		mp_sizeof_uint(TP_TUPLE);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	char *h = mp_encode_map(p->p, 2);
	h = mp_encode_uint(h, TP_CODE);
	h = mp_encode_uint(h, TP_REPLACE);
	h = mp_encode_map(h, 2);
	h = mp_encode_uint(h, TP_SPACE);
	h = mp_encode_uint(h, space);
	h = mp_encode_uint(h, TP_TUPLE);
	return tp_add(p, sz);
}

static inline char*
tp_delete(struct tp *p, uint32_t space)
{
	int sz = 5 +
		mp_sizeof_uint(TP_CODE) +
		mp_sizeof_uint(TP_DELETE) +
		mp_sizeof_map(2) +
		mp_sizeof_uint(TP_SPACE) +
		mp_sizeof_uint(space) +
		mp_sizeof_uint(TP_KEY);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	char *h = mp_encode_map(p->p, 2);
	h = mp_encode_uint(h, TP_CODE);
	h = mp_encode_uint(h, TP_DELETE);
	h = mp_encode_map(h, 2);
	h = mp_encode_uint(h, TP_SPACE);
	h = mp_encode_uint(h, space);
	h = mp_encode_uint(h, TP_KEY);
	return tp_add(p, sz);
}

static inline char*
tp_update(struct tp *p, uint32_t space)
{
	int sz = 5 +
		mp_sizeof_uint(TP_CODE) +
		mp_sizeof_uint(TP_UPDATE) +
		mp_sizeof_map(2) +
		mp_sizeof_uint(TP_SPACE) +
		mp_sizeof_uint(space) +
		mp_sizeof_uint(TP_KEY);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	char *h = mp_encode_map(p->p, 2);
	h = mp_encode_uint(h, TP_CODE);
	h = mp_encode_uint(h, TP_UPDATE);
	h = mp_encode_map(h, 2);
	h = mp_encode_uint(h, TP_SPACE);
	h = mp_encode_uint(h, space);
	h = mp_encode_uint(h, TP_KEY);
	return tp_add(p, sz);
}

static inline char*
tp_select(struct tp *p, uint32_t space, uint32_t index)
{
	int sz = 5 +
		mp_sizeof_uint(TP_CODE) +
		mp_sizeof_uint(TP_SELECT) +
		mp_sizeof_map(3) +
		mp_sizeof_uint(TP_SPACE) +
		mp_sizeof_uint(space) +
		mp_sizeof_uint(TP_INDEX) +
		mp_sizeof_uint(index) +
		mp_sizeof_uint(TP_KEY);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	char *h = mp_encode_map(p->p, 2);
	h = mp_encode_uint(h, TP_CODE);
	h = mp_encode_uint(h, TP_SELECT);
	h = mp_encode_map(h, 3);
	h = mp_encode_uint(h, TP_SPACE);
	h = mp_encode_uint(h, space);
	h = mp_encode_uint(h, TP_INDEX);
	h = mp_encode_uint(h, index);
	h = mp_encode_uint(h, TP_KEY);
	return tp_add(p, sz);
}

static inline char*
tp_call(struct tp *p, const char *function, int len)
{
	int sz = 5 +
		mp_sizeof_uint(TP_CODE) +
		mp_sizeof_uint(TP_CALL) +
		mp_sizeof_map(2) +
		mp_sizeof_uint(TP_FUNCTION) +
		mp_sizeof_str(len) +
		mp_sizeof_uint(TP_TUPLE);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	char *h = mp_encode_map(p->p, 2);
	h = mp_encode_uint(h, TP_CODE);
	h = mp_encode_uint(h, TP_CALL);
	h = mp_encode_map(h, 2);
	h = mp_encode_uint(h, TP_FUNCTION);
	h = mp_encode_str(h, function, len);
	h = mp_encode_uint(h, TP_TUPLE);
	return tp_add(p, sz);
}

static inline char*
tp_auth(struct tp *p, const char *user, int len)
{
	int sz = 5 +
		mp_sizeof_uint(TP_CODE) +
		mp_sizeof_uint(TP_AUTH) +
		mp_sizeof_map(2) +
		mp_sizeof_uint(TP_KEY) +
		mp_sizeof_array(1) +
		mp_sizeof_str(len) +
		mp_sizeof_uint(TP_TUPLE);
	if (tpunlikely(tp_ensure(p, sz) == -1))
		return NULL;
	char *h = mp_encode_map(p->p, 2);
	h = mp_encode_uint(h, TP_CODE);
	h = mp_encode_uint(h, TP_AUTH);
	h = mp_encode_map(h, 2);
	h = mp_encode_uint(h, TP_KEY);
	h = mp_encode_array(h, 1);
	h = mp_encode_str(h, user, len);
	h = mp_encode_uint(h, TP_TUPLE);
	return tp_add(p, sz);
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
};

static inline int64_t
tp_response(struct tpresponse *r, char *buf, size_t size)
{
	if (size < 5)
		return -1;
	memset(r, 0, sizeof(*r));
	const char *p = buf;
	/* len */
	if (mp_typeof(*p) != MP_UINT)
		return -1;
	uint32_t len = mp_decode_uint(&p);
	if (size < (5 + len))
		return -1;
	/* header */
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
			r->sync = mp_decode_uint(&p);
			break;
		case TP_CODE:
			r->code = mp_decode_uint(&p);
			break;
		default:
			return -1;
		}
		r->bitmap |= (1ULL << key);
	}
	/* body */
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
	return p - buf;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
