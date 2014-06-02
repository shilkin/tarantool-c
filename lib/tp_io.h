#ifndef TP_IO_H_
#define TP_IO_H_

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

#include <sys/time.h>

struct tpbuf {
	size_t off;
	size_t top;
	size_t size;
	char *buf;
};

struct tpconnection {
	char *host;
	int port;
	int connected;
	struct timeval tmc;
	int sbuf;
	int rbuf;
	int fd;
	int errno_;
	struct tpbuf s, r;
};

enum tpopt {
	TP_HOST,
	TP_PORT,
	TP_CONNECTTM,
	TP_SENDBUF,
	TP_READBUF
};

int tp_connection_init(struct tpconnection*);
int tp_connection_free(struct tpconnection*);
int tp_connection_set(struct tpconnection*, enum tpopt, ...);
int tp_connect(struct tpconnection*);
int tp_close(struct tpconnection*);
int tp_sync(struct tpconnection*);
ssize_t tp_send(struct tpconnection*, char*, size_t);
ssize_t tp_recv(struct tpconnection*, char*, size_t, int strict);

#endif
