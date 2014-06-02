
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
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <lib/tp_io.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

static int
tp_bufinit(struct tpbuf *b, int size)
{
	b->off = 0;
	b->top = 0;
	b->size = size;
	b->buf = NULL;
	if (size == 0)
		return 0;
	b->buf = malloc(size);
	if (b->buf == NULL)
		return -1;
	return 0;
}

static void
tp_buffree(struct tpbuf *b)
{
	if (b->buf) {
		free(b->buf);
		b->buf = NULL;
	}
}

int tp_connect_init(struct tpconnection *s)
{
	s->host = strdup("127.0.0.1");
	if (s->host == NULL) {
		s->errno_ = ENOMEM;
		return -1;
	}
	s->connected = 0;
	s->port = 33013;
	s->rbuf = 16384;
	s->sbuf = 16384;
	s->fd = -1;
	s->tmc.tv_sec  = 16;
	s->tmc.tv_usec = 0;
	s->errno_ = 0;
	memset(&s->s, 0, sizeof(s->s));
	memset(&s->r, 0, sizeof(s->r));
	return 0;
}

int tp_connect_free(struct tpconnection *s)
{
	tp_close(s);
	if (s->host) {
		free(s->host);
		s->host = NULL;
	}
	tp_buffree(&s->s);
	tp_buffree(&s->r);
	return 0;
}

int tp_connection_set(struct tpconnection *s, enum tpopt o, ...)
{
	va_list args;
	va_start(args, o);
	switch (o) {
	case TP_HOST: {
		char *p = strdup(va_arg(args, char*));
		if (p == NULL) {
			va_end(args);
			s->errno_ = ENOMEM;
			return -1;
		}
		free(s->host);
		s->host = p;
		break;
	}
	case TP_PORT:
		s->port = va_arg(args, int);
		break;
	case TP_CONNECTTM:
		s->tmc.tv_sec  = va_arg(args, int);
		s->tmc.tv_usec = 0;
		break;
	case TP_SENDBUF:
		s->sbuf = va_arg(args, int);
		break;
	case TP_READBUF:
		s->rbuf = va_arg(args, int);
		break;
	default:
		va_end(args);
		s->errno_ = EINVAL;
		return -1;
	}
	va_end(args);
	return 0;
}

static int
tp_setbufmax(struct tpconnection *s, int opt, int min)
{
	int max = 128 * 1024 * 1024;
	if (min == 0)
		min = 16384;
	unsigned int avg = 0;
	while (min <= max) {
		avg = ((unsigned int)(min + max)) / 2;
		if (setsockopt(s->fd, SOL_SOCKET, opt, &avg, sizeof(avg)) == 0)
			min = avg + 1;
		else
			max = avg - 1;
	}
	return 0;
}

static int
tp_setopts(struct tpconnection *s)
{
	int opt = 1;
	if (setsockopt(s->fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) == -1) {
		s->errno_ = errno;
		return -1;
	}
	tp_setbufmax(s, SO_SNDBUF, s->sbuf);
	tp_setbufmax(s, SO_RCVBUF, s->rbuf);
	return 0;
}

static int
tp_resolve(struct tpconnection *s, struct sockaddr_in *addr)
{
	memset(addr, 0, sizeof(struct sockaddr_in));
	addr->sin_family = AF_INET;
	addr->sin_port = htons(s->port);
	struct addrinfo *addr_info = NULL;
	if (getaddrinfo(s->host, NULL, NULL, &addr_info) == 0) {
		memcpy(&addr->sin_addr,
		       (void*)&((struct sockaddr_in *)addr_info->ai_addr)->sin_addr,
		       sizeof(addr->sin_addr));
		freeaddrinfo(addr_info);
		return 0;
	}
	s->errno_ = errno;
	if (addr_info)
		freeaddrinfo(addr_info);
	return -1;
}

static int
tp_connectnonblock(struct tpconnection *s, int set)
{
	int flags = fcntl(s->fd, F_GETFL);
	if (flags == -1) {
		s->errno_ = errno;
		return -1;
	}
	if (set)
		flags |= O_NONBLOCK;
	else
		flags &= ~O_NONBLOCK;
	int rc = fcntl(s->fd, F_SETFL, flags);
	if (rc == -1)
		s->errno_ = errno;
	return rc;
}

static int
tp_connectdo(struct tpconnection *s)
{
	/* resolve address */
	struct sockaddr_in addr;
	int rc = tp_resolve(s, &addr);
	if (rc == -1)
		return -1;
	/* set nonblock */
	rc = tp_connectnonblock(s, 1);
	if (rc == -1)
		return -1;

	if (connect(s->fd, (struct sockaddr*)&addr, sizeof(addr)) == -1)
	{
		if (errno == EINPROGRESS) {
			/* wait for connection while handling signal events */
			const int64_t micro = 1000000;
			int64_t tmout_usec = s->tmc.tv_sec * micro;
			/* get start connect time */
			struct timeval start_connect;
			if (gettimeofday(&start_connect, NULL) == -1) {
				s->errno_ = errno;
				return -1;
			}
			/* set initial timer */
			struct timeval tmout;
			memcpy(&tmout, &s->tmc, sizeof(tmout));
			while (1) {
				fd_set fds;
				FD_ZERO(&fds);
				FD_SET(s->fd, &fds);
				int ret = select(s->fd + 1, NULL, &fds, NULL, &tmout);
				if (ret == -1) {
					if (errno == EINTR || errno == EAGAIN) {
						/* get current time */
						struct timeval curr;
						if (gettimeofday(&curr, NULL) == -1) {
							s->errno_ = errno;
							return -1;
						}
						/* calculate timeout last time */
						int64_t passd_usec = (curr.tv_sec - start_connect.tv_sec) * micro +
							(curr.tv_usec - start_connect.tv_usec);
						int64_t curr_tmeout = passd_usec - tmout_usec;
						if (curr_tmeout <= 0) {
							s->errno_ = ETIMEDOUT;
							return -1;
						}
						tmout.tv_sec = curr_tmeout / micro;
						tmout.tv_usec = curr_tmeout % micro;
					} else {
						s->errno_ = errno; 
						return -1;
					}
				} else if (ret == 0) {
					s->errno_ = ETIMEDOUT;
					return -1;
				} else {
					/* we have a event on socket */
					break;
				}
			}
			/* checking error status */
			int opt = 0;
			socklen_t len = sizeof(opt);
			if ((getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &opt, &len) == -1) || opt) {
				s->errno_ = (opt) ? opt: errno;
				return -1;
			}
		} else {
			s->errno_ = errno;
			return -1;
		}
	}

	/* set block */
	return tp_connectnonblock(s, 0);
}

int tp_connect(struct tpconnection *s)
{
	int rc;
	if (s->s.buf == NULL) {
		rc = tp_bufinit(&s->s, s->sbuf);
		if (rc == -1) {
			s->errno_ = ENOMEM;
			return -1;
		}
		rc = tp_bufinit(&s->r, s->rbuf);
		if (rc == -1) {
			tp_buffree(&s->s);
			s->errno_ = ENOMEM;
			return -1;
		}
	}
	s->fd = socket(AF_INET, SOCK_STREAM, 0);
	if (s->fd < 0) {
		s->errno_ = errno;
		return -1;
	}
	rc = tp_setopts(s);
	if (rc == -1)
		return -1;
	rc = tp_connectdo(s);
	if (rc == -1)
		return -1;
	s->connected = 1;
	return 0;
}

int tp_connectclose(struct tpconnection *s)
{
	int rc = 0;
	if (s->fd != -1) {
		rc = close(s->fd);
		if (rc == -1)
			s->errno_ = errno;
		s->fd = -1;
	}
	s->connected = 0;
	return rc;
}

static ssize_t
tp_sendraw(struct tpconnection *s, char *buf, size_t size)
{
	size_t off = 0;
	do {
		ssize_t r;
		do {
			r = send(s->fd, buf + off, size - off, 0);
		} while (r == -1 && (errno == EINTR));
		if (r <= 0) {
			s->errno_ = errno;
			return -1;
		}
		off += r;
	} while (off != size);

	return off;
}

static ssize_t
tp_senddo(struct tpconnection *s, char *buf, size_t size)
{
	if (s->s.buf == NULL)
		return tp_sendraw(s, buf, size);

	if (size > s->s.size) {
		s->errno_ = E2BIG;
		return -1;
	}
	if ((s->s.off + size) <= s->s.size) {
		memcpy(s->s.buf + s->s.off, buf, size);
		s->s.off += size;
		return size;
	}
	ssize_t r = tp_sendraw(s, s->s.buf, s->s.off);
	if (r == -1)
		return -1;

	s->s.off = size;
	memcpy(s->s.buf, buf, size);
	return size;
}

static ssize_t
tp_recvraw(struct tpconnection *s, char *buf, size_t size, int strict)
{
	size_t off = 0;
	do {
		ssize_t r;
		do {
			r = recv(s->fd, buf + off, size - off, 0);
		} while (r == -1 && (errno == EINTR));
		if (r <= 0) {
			s->errno_ = errno;
			return -1;
		}
		off += r;
	} while (off != size && strict);

	return off;
}

static ssize_t
tp_recvdo(struct tpconnection *s, char *buf, size_t size)
{
	if (s->r.buf == NULL)
		return tp_recvraw(s, buf, size, 1);
	
	size_t lv, rv, off = 0, left = size;
	while (1) {
		if ((s->r.off + left) <= s->r.top) {
			memcpy(buf + off, s->r.buf + s->r.off, left);
			s->r.off += left;
			return size;
		}

		lv = s->r.top - s->r.off;
		rv = left - lv;
		if (lv) {
			memcpy(buf + off, s->r.buf + s->r.off, lv);
			off += lv;
		}

		s->r.off = 0;
		ssize_t top = tp_recvraw(s, s->r.buf, s->r.size, 0);
		if (top <= 0) {
			s->errno_ = errno;
			return -1;
		}

		s->r.top = top;
		if (rv <= s->r.top) {
			memcpy(buf + off, s->r.buf, rv);
			s->r.off = rv;
			return size;
		}
		left -= lv;
	}
	return -1;
}

int tp_sync(struct tpconnection *s)
{
	if (s->s.off == 0)
		return 0;
	ssize_t rc = tp_sendraw(s, s->s.buf, s->s.off);
	if (rc == -1)
		return -1;
	s->s.off = 0;
	return rc;
}

ssize_t
tp_connectsend(struct tpconnection *s, char *buf, size_t size) {
	return tp_senddo(s, buf, size);
}

ssize_t
tp_recv(struct tpconnection *s, char *buf, size_t size, int strict)
{
	if (! strict) {
		if (s->r.buf) {
			size_t v = s->r.top - s->r.off;
			if (v > 0) {
				if (size < v)
					v = size;
				memcpy(buf, s->r.buf + s->r.off, v);
				s->r.off += v;
				return v;
			}
		}
		/* todo: make unstricted read with readahead
		 * buffer */
		return tp_recvraw(s, buf, size, 0);
	}
	return tp_recvdo(s, buf, size);
}
