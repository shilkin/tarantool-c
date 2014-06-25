
/*
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the
 *    following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * <COPYRIGHT HOLDER> OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
*/

#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
//#include <arpa/inet.h>

#include <tp.h>
#include <tp_io.h>

#include <stdio.h>
#include <limits.h>


#ifdef NDEBUG
#define VERIFY(x) x
#else
#define VERIFY(x) assert(x)
#endif

#if 0
static void
test_gh331(void)
{
	struct tp request;
	tp_init(&request, NULL, 0, tp_realloc, NULL);
	tp_call(&request, 0, "test", 4);
	tp_tuple(&request);
	tp_field(&request, "", 2*tp_size(&request)-1);
	assert(tp_used(&request) <= tp_size(&request));
}
#endif

/**
 * MP_EXT is printed as "EXT" only, all MP_EXT data is skipped
 */
static int
mp_print_internal(const char **beg)
{
	switch (mp_typeof(**beg)) {
	case MP_NIL:
		mp_next(beg);
		printf("NIL");
		break;
	case MP_UINT:
		printf("%" PRIu64, mp_decode_uint(beg));
		break;
	case MP_INT:
		printf("%" PRId64, mp_decode_int(beg));
		break;
	case MP_STR:
	{
		uint32_t strlen;
		const char *str = mp_decode_str(beg, &strlen);
		printf("\"%.*s\"", strlen, str);
		break;
	}
	case MP_BIN:
	{
		uint32_t binlen;
		const char *bin = mp_decode_bin(beg, &binlen);
		printf("(");
		const char *hex = "0123456789ABCDEF";
		for (uint32_t i = 0; i < binlen; i++) {
			unsigned char c = (unsigned char)bin[i];
			printf("%c%c", hex[c >> 4], hex[c & 0xF]);
		}
		printf(")");
		break;
	}
	case MP_ARRAY:
	{
		uint32_t size = mp_decode_array(beg);
		printf("[");
		for (uint32_t i = 0; i < size; i++) {
			if (i)
				printf(", ");
			mp_print_internal(beg);
		}
		printf("]");
		break;
	}
	case MP_MAP:
	{
		uint32_t size = mp_decode_map(beg);
		printf("{");
		for (uint32_t i = 0; i < size; i++) {
			if (i)
				printf(", ");
			mp_print_internal(beg);
			printf(":");
			mp_print_internal(beg);
		}
		printf("}");
		break;
	}
	case MP_BOOL:
		printf("%s", mp_decode_bool(beg) ? "true" : "false");
		break;
	case MP_FLOAT:
		printf("%g", mp_decode_float(beg));
		break;
	case MP_DOUBLE:
		printf("%lg", mp_decode_double(beg));
		break;
	case MP_EXT:
		mp_next(beg);
		printf("EXT");
		break;
	default:
		assert(false);
		return -1;
	}
	return 0;
}

/**
 * MP_EXT is printed as "EXT" only, all MP_EXT data is skipped
 */
int
mp_print(const char **beg)
{
	int res = mp_print_internal(beg);
	printf("\n");
	return res;
}

/**
 * %d, %i - int
 * %u - unsigned int
 * %ld, %li - long
 * %lu - unsigned long
 * %lld, %lli - long long
 * %llu - unsigned long long
 * %hd, %hi - short
 * %hu - unsigned short
 * %hhd, %hhi - char (as number)
 * %hhu - unsigned char (as number)
 * %f - float
 * %lf - double
 * %b - bool
 * %s - zero-end string
 * %.*s - string with specified length
 * %<smth else> assert and undefined behaviour
 * NIL - a nil value
 * all other symbols are ignored
 */
#define MP_PROTO
MP_PROTO size_t
mp_encode_f(char *data, size_t data_size, const char *format, ...)
{
	size_t result = 0;
	va_list vl;
	va_start(vl, format);

	for (const char *f = format; *f; f++) {
		if (f[0] == '[') {
			uint32_t size = 0;
			int level = 1;
			for (const char *e = f + 1; level && *e; e++) {
				if (*e == '[' || *e == '{') {
					if (level == 1)
						size++;
					level++;
				} else if (*e == ']' || *e == '}') {
					level--;
					/* opened '[' must be closed by ']' */
					assert(level || *e == ']');
				} else if (*e == '%') {
					if (e[1] == '%')
						e++;
					else if (level == 1)
						size++;
				} else if (*e == 'N' && e[1] == 'I' && e[2] == 'L' && level == 1) {
					size++;
				}
			}
			/* opened '[' must be closed */
			assert(level == 0);
			result += mp_sizeof_array(size);
			if (result <= data_size)
				data = mp_encode_array(data, size);
		} else if (f[0] == '{') {
			uint32_t count = 0;
			int level = 1;
			for (const char *e = f + 1; level && *e; e++) {
				if (*e == '[' || *e == '{') {
					if (level == 1)
						count++;
					level++;
				} else if (*e == ']' || *e == '}') {
					level--;
					/* opened '{' must be closed by '}' */
					assert(level || *e == '}');
				} else if (*e == '%') {
					if (e[1] == '%')
						e++;
					else if (level == 1)
						count++;
				} else if (*e == 'N' && e[1] == 'I' && e[2] == 'L' && level == 1) {
					count++;
				}
			}
			/* opened '{' must be closed */
			assert(level == 0);
			/* since map is a pair list, count must be even */
			assert(count % 2 == 0);
			uint32_t size = count / 2;
			result += mp_sizeof_map(size);
			if (result <= data_size)
				data = mp_encode_map(data, size);
		} else if (f[0] == '%') {
			f++;
			assert(f[0]);
			int64_t int_value = 0;
			int int_status = 0; /* 1 - signed, 2 - unsigned */

			if (f[0] == 'd' || f[0] == 'i') {
				int_value = va_arg(vl, int);
				int_status = 1;
			} else if (f[0] == 'u') {
				int_value = va_arg(vl, unsigned int);
				int_status = 2;
			} else if (f[0] == 's') {
				const char *str = va_arg(vl, const char *);
				uint32_t len = (uint32_t)strlen(str);
				result += mp_sizeof_str(len);
				if (result <= data_size)
					data = mp_encode_str(data, str, len);
			} else if (f[0] == '.' && f[1] == '*' && f[2] == 's') {
				uint32_t len = va_arg(vl, uint32_t);
				const char *str = va_arg(vl, const char *);
				result += mp_sizeof_str(len);
				if (result <= data_size)
					data = mp_encode_str(data, str, len);
				f += 2;
			} else if(f[0] == 'f') {
				float v = (float)va_arg(vl, double);
				result += mp_sizeof_float(v);
				if (result <= data_size)
					data = mp_encode_float(data, v);
			} else if(f[0] == 'l' && f[1] == 'f') {
				double v = va_arg(vl, double);
				result += mp_sizeof_double(v);
				if (result <= data_size)
					data = mp_encode_double(data, v);
				f++;
			} else if(f[0] == 'b') {
				bool v = (bool)va_arg(vl, int);
				result += mp_sizeof_bool(v);
				if (result <= data_size)
					data = mp_encode_bool(data, v);
			} else if (f[0] == 'l' && (f[1] == 'd' || f[1] == 'i')) {
				int_value = va_arg(vl, long);
				int_status = 1;
				f++;
			} else if (f[0] == 'l' && f[1] == 'u') {
				int_value = va_arg(vl, unsigned long);
				int_status = 2;
				f++;
			} else if (f[0] == 'l' && f[1] == 'l' && (f[2] == 'd' || f[2] == 'i')) {
				int_value = va_arg(vl, long long);
				int_status = 1;
				f += 2;
			} else if (f[0] == 'l' && f[1] == 'l' && f[2] == 'u') {
				int_value = va_arg(vl, unsigned long long);
				int_status = 2;
				f += 2;
			} else if (f[0] == 'h' && (f[1] == 'd' || f[1] == 'i')) {
				int_value = va_arg(vl, int);
				int_status = 1;
				f++;
			} else if (f[0] == 'h' && f[1] == 'u') {
				int_value = va_arg(vl, unsigned int);
				int_status = 2;
				f++;
			} else if (f[0] == 'h' && f[1] == 'h' && (f[2] == 'd' || f[2] == 'i')) {
				int_value = va_arg(vl, int);
				int_status = 1;
				f += 2;
			} else if (f[0] == 'h' && f[1] == 'h' && f[2] == 'u') {
				int_value = va_arg(vl, unsigned int);
				int_status = 2;
				f += 2;
			} else if (f[0] != '%') {
				/* unexpected format specifier */
				assert(false);
			}

			if (int_status == 1 && int_value < 0) {
				result += mp_sizeof_int(int_value);
				if (result <= data_size)
					data = mp_encode_int(data, int_value);
			} else if(int_status) {
				result += mp_sizeof_uint(int_value);
				if (result <= data_size)
					data = mp_encode_uint(data, int_value);
			}
		} else if (f[0] == 'N' && f[1] == 'I' && f[2] == 'L') {
			result += mp_sizeof_nil();
			if (result <= data_size)
				data = mp_encode_nil(data);
			f += 2;
		}
	}
	return result;
}

int
main(int argc, char * argv[])
{
	(void)argc;
	(void)argv;

#if 0
	test_gh331();
#endif

	/*
	char buf[1024];
	struct tp tp;
	tp_init(&tp, buf, sizeof(buf), NULL, NULL);
	tp_insert(&tp, 0);
	tp_encode_array(&tp, 2);
	tp_encode_uint(&tp, 10);
	tp_encode_uint(&tp, 20);
	*/


	#if 0
	char buf[1024];
	char *p = buf + 5;
	p = mp_encode_map(p, 2);
	p = mp_encode_uint(p, TP_CODE);
	p = mp_encode_uint(p, TP_INSERT);
	p = mp_encode_uint(p, TP_SYNC);
	p = mp_encode_uint(p, 0);
	p = mp_encode_map(p, 2);
	p = mp_encode_uint(p, TP_SPACE);
	p = mp_encode_uint(p, 0);
	p = mp_encode_uint(p, TP_TUPLE);
	p = mp_encode_array(p, 2);
	p = mp_encode_uint(p, 10);
	p = mp_encode_uint(p, 20);
	uint32_t size = p - buf;
	*buf = 0xce;
	*(uint32_t*)(buf+1) = mp_bswap_u32(size - 5);

	struct tbses s;
	tb_sesinit(&s);
	tb_sesset(&s, TP_HOST, "127.0.0.1");
	tb_sesset(&s, TP_PORT, 33013);
	tb_sesset(&s, TP_SENDBUF, 0);
	tb_sesset(&s, TP_READBUF, 0);
	int rc = tb_sesconnect(&s);
	if (rc == -1)
		return 1;
	tb_sessend(&s, buf, size);

	ssize_t len = tb_sesrecv(&s, buf, sizeof(buf), 0);
	struct tbresponse rp;
	int64_t r = tb_response(&rp, buf, len);
	if (r == -1)
		return 1;
	#endif


	int s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert(s >= 0);
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = 0x100007F;
	sa.sin_port = htons(33013);
	VERIFY(connect(s, (struct sockaddr *)&sa, sizeof(sa)) == 0);
	printf("connected\n");

	const int gbufsize = 128;
	char gbuf[gbufsize];
	struct tpgreetings greet;

	int pos = 0;
	do {
		int rres = read(s, gbuf + pos, gbufsize - pos);
		assert(rres > 0);
		if (rres <= 0)
			exit(errno);
		pos += rres;
	} while (tp_greetings(&greet, gbuf, pos) < 0);

	char ibuf[1024];
	const uint32_t reqid = 555;
	struct tp p;
	tp_init(&p, ibuf, 1024, 0, 0);
#if 0
	tp_select(&p, 512, 0, 0, 2);
	tp_key(&p, 1);
	tp_encode_uint(&p, 1);
#endif
#if 0
	const char func[] = "box.space.test:select";
	tp_call(&p, func, sizeof(func) - 1);
	tp_encode_array(&p, 3);
	tp_encode_uint(&p, 0);
	tp_encode_array(&p, 1);
	tp_encode_uint(&p, 1);
	tp_encode_array(&p, 0);
#endif
#if 0
	tp_insert(&p, 512);
	tp_encode_array(&p, 3);
	tp_encode_uint(&p, 5);
	tp_encode_uint(&p, 5);
	tp_encode_str(&p, "abc", 3);
#endif
#if 0
	tp_replace(&p, 512);
	tp_encode_array(&p, 3);
	tp_encode_uint(&p, 5);
	tp_encode_uint(&p, 5);
	tp_encode_str(&p, "def", 3);
#endif
#if 0
	tp_delete(&p, 512);
	tp_encode_array(&p, 2);
	tp_encode_uint(&p, 5);
	tp_encode_uint(&p, 5);
#endif

#if 1
	tp_update(&p, 512);
	tp_key(&p, 2);
	tp_encode_uint(&p, 1);
	tp_encode_uint(&p, 1);
	tp_updatebegin(&p, 1);
	tp_op(&p, '+', 1);
	tp_encode_uint(&p, 1);
#endif

#if 0
	tp_select(&p, 512, 0, 0, 88);
	tp_key(&p, 0);
#endif

#if 0
	tp_auth(&p, greet.salt_base64, "test", 4, "***", 3);
#endif

#if 0
	tp_ping(&p);
#endif

	tp_reqid(&p, reqid);

	pos = 0;
	int send_size = (int)tp_used(&p);
	do {
		int wres = write(s, ibuf + pos, send_size - pos);
		assert(wres > 0);
		if (wres <= 0)
			exit(errno);
		pos += wres;
	} while (pos < send_size);

	struct tpresponse r;
	pos = 0;
	const int buf_size = 1024;
	char obuf[buf_size];
	int reply_res = 0;
	do {
		int rres = read(s, obuf + pos, buf_size - pos);
		assert(rres > 0);
		if (rres <= 0)
			exit(errno);
		pos += rres;
	} while ((reply_res = tp_reply(&r, obuf, pos)) == 0 && pos != buf_size);

	if (reply_res < 0) {
		printf("error parsing result\n");
		return 0;
	}

	assert(tp_getreqid(&r) == reqid);

	if (r.error) {
		char errmsg[1024];
		memcpy(errmsg, r.error, r.error_end - r.error);
		errmsg[r.error_end - r.error] = 0;
		printf("Error: %s\n", errmsg);
		printf("errode: %d\n", r.code);
	} else if (r.data) {
		assert(r.data);
		printf("Size: %d\n", (int)(r.data_end - r.data));
		const char *s = r.data;
		int pr = mp_print(&s);
		if (pr)
			printf("print failed!");
		if (s != r.data_end)
			printf("Tail size %d detected!\n", (int)(r.data_end - s));
		while(tp_next(&r)) {
			printf("tuple:");
			while(tp_nextfield(&r)) {
				enum tp_type t = tp_typeof(*tp_getfield(&r));
				if (t == TP_NIL) {
					printf("NIL ");
				} else if (t == TP_INT) {
					printf("%ld ", tp_get_int(tp_getfield(&r)));
				} else if (t == TP_UINT) {
					printf("%ld ", tp_get_uint(tp_getfield(&r)));
				} else if (t == TP_STR) {
					uint32_t len;
					const char *s = tp_get_str(tp_getfield(&r), &len);
					printf("%.*s ", len, s);
				} else {
					printf("f ");
				}
			}
			printf("\n");
		}

	} else {
		printf("no data\n");
	}

	printf("ok\n");
	return 0;
}

