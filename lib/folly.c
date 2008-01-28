#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <assert.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "folly.h"

#ifdef linux
#include <sys/socket.h>
int recvfd(int s);
#endif

#define HEADSPACE 1024
#define objzero(var) memset(var, 0, sizeof(*(var)))

#define DEFAULT_INBUFSIZE  (1 << 16)
#define DEFAULT_OUTBUFSIZE DEFAULT_INBUFSIZE

static int
get_fuse_req(struct fvfs *fv)
{
	size_t bytes;

	bytes = read(fv->parm.fuse_fd, fv->inbuf, fv->parm.inbufsize + HEADSPACE);
	if (bytes == -1) {
		if (errno != ENODEV) {
			abort_folly(fv, "fuse device read");
			return -1;
		}
		return 1;
	}
#ifdef VALIDATE_INPUT
	if (bytes < sizeof(finh(fv)) || bytes != finh(fv)->len ||
	    finh(fv)->opcode >= FUSE_OPTABLE_SIZE ||
	    !fv->optable[finh(fv)->opcode]) {
		abort_folly(fv, "fuse protocol error");
		return -1;
	}
	/*
	 * We could do further input validation here
	 * (eg. if finh(fv)->opcode == FUSE_READ, then
	 * bytes == sizeof(finh(fv)) + sizeof(struct fuse_read_in)
	 * should hold).
	 *
	 * However, we don't bother with such checks, as we trust
	 * the client (our own very precious kernel). [FYI: fuselib
	 * neither does...]
	 */
#endif
	DIAG(fv, "%s[%d]: unique %llu, nodeid %llu, len %d\n",
	     fuse_opnames[finh(fv)->opcode], finh(fv)->opcode,
	     finh(fv)->unique, finh(fv)->nodeid, finh(fv)->len);
	return 0;
}

int
write_fuse_answer(struct fvfs *fv, size_t len)
{
	size_t bytes;

	assert(len <= fv->parm.outbufsize + HEADSPACE);
	fouh(fv)->len = sizeof(struct fuse_out_header) + len;
	fouh(fv)->unique = finh(fv)->unique;

	bytes = write(fv->parm.fuse_fd, fv->outbuf, fouh(fv)->len);
	if (bytes < fouh(fv)->len) {
		abort_folly(fv, "fuse protocol error");
		return -1;
	}
	DIAG(fv, "  len %d, error \"%s\" [%d]\n", fouh(fv)->len,
	     strerror(-fouh(fv)->error), -fouh(fv)->error);
	return 0;
}

int
send_fuse_err(struct fvfs *fv, int errn)
{
	int error;

	fouh(fv)->error = -errn;
	error = write_fuse_answer(fv, 0);
	fouh(fv)->error = 0;

	return error;
}

int
send_fuse_data(struct fvfs *fv, size_t len, int errn)
{
	return errn ? send_fuse_err(fv, errn) : write_fuse_answer(fv, len);
}

static int
folly_init0(struct fvfs *fv)
{
	struct fuse_init_in  *fini = fuse_req_body(fv);
	struct fuse_init_out *fino = fuse_ans_body(fv);

	DIAG(fv, " kernel FUSE version %d.%d\n", fini->major, fini->minor);
	if (fini->major != FUSE_KERNEL_VERSION ||
	    fini->minor < FUSE_KERNEL_MINOR_VERSION) {
		char msg[512];

		snprintf(msg, sizeof(msg),
		         "unsupported proto version %d.%d from kernel",
		         fini->major, fini->minor);
		abort_folly(fv, msg);
		return -1;
	}

	memcpy(fino, &fv->parm.finit_out, sizeof(*fino));
	fino->major = FUSE_KERNEL_VERSION;
	fino->minor = FUSE_KERNEL_MINOR_VERSION;
	fino->max_write = fv->parm.outbufsize;
	return send_fuse_obj(fv, fino, 0);
}

int
folly_init(struct fvfs *fv)
{
	abort_folly(fv, "fuse protocol error");

	return -1;
}

int
folly_default_handler(struct fvfs *fv)
{
	return send_fuse_err(fv, ENOSYS);
}

static void
default_abort_folly(struct fvfs *fv, char *msg)
{
	errno ? err(1, msg) : errx(1, msg);
}

int
acquire_fuse_fd(void)
{
#ifdef __FreeBSD__
	char *fdnam, *ep;
	int fd;

	fdnam = getenv("FUSE_DEV_FD");
	if (!fdnam)
		return -1;
	fd = strtol(fdnam, &ep, 10);
	if (*ep != '\0' || fd < 0)
		return -1;

	return fd;
#elif defined(linux)
	int p[2], pid, fd;
	char buf[20];
	char *mtpt;

	mtpt = getenv("FUSE_MOUNTPOINT");
	if (!mtpt)
		return -1;
	if(socketpair(AF_UNIX, SOCK_STREAM, 0, p) < 0)
		return -1;
	pid = fork();
	if(pid < 0)
		return -1;
	if(pid == 0){
		close(p[1]);
		snprintf(buf, sizeof buf, "_FUSE_COMMFD=%d", p[0]);
		putenv(buf);
		execlp("fusermount", "fusermount", "--", mtpt, NULL);
		err(1, "exec fusermount");
	}
	close(p[0]);
	fd = recvfd(p[1]);
	close(p[1]);
	return fd;
#endif
}

void
init_fvfs_param(struct fvfs_param *fvp)
{
	objzero(fvp);

	if (!fvp->inbufsize)
		fvp->inbufsize = DEFAULT_INBUFSIZE;
	if (!fvp->outbufsize)
		fvp->outbufsize = DEFAULT_OUTBUFSIZE;
	if (!fvp->abort_folly)
		fvp->abort_folly = default_abort_folly;
	fvp->fops = &list_fnode_ops;
} 	

int
folly_loop(struct fvfs_param *fvp)
{
	int i, errn = -1;
	struct fvfs fv;
	struct handler_spec *hp;

	errno = 0;

	objzero(&fv);
	memcpy(&fv.parm, fvp, sizeof(*fvp));

	if (fvp->fuse_fd < 0) {
		abort_folly(&fv, "cannot identify fuse device");
		return ENODEV;
	}

	for (i = 0; i < FUSE_OPTABLE_SIZE; i++)
		fv.optable[i] = fuse_opnames[i] ? folly_default_handler : NULL;
	fv.optable[FUSE_INIT] = folly_init;
	fv.optable[FUSE_FORGET] = folly_forget;
	for (hp = fvp->opmap; hp->opcode; hp++)
		fv.optable[hp->opcode] = hp->handler;

	fv.inbuf = malloc(fvp->inbufsize + HEADSPACE);
	if (!fv.inbuf) {
		abort_folly(&fv, "cannot allocate input buffer");
		goto out;
	}
	fv.outbuf = malloc(fvp->outbufsize + HEADSPACE);
	if (!fv.outbuf) {
		abort_folly(&fv, "cannot allocate output buffer");
		goto out;
	}
	fv.root_fnode = make_fnode(&fv, 0);
	if (!fv.root_fnode) {
		abort_folly(&fv, "cannot create root node");
		goto out;
	}
	fv.root_fnode->priv = fvp->root_fnode_priv;

	if (get_fuse_req(&fv)) {
		abort_folly(&fv, "fuse handshake failed");
		goto out;
	}

	if (finh(&fv)->opcode != FUSE_INIT) {
		abort_folly(&fv, "fuse protocol error");
		goto out;
	}
	if (folly_init0(&fv))
		goto out;

	for (;;) {
		errn = get_fuse_req(&fv);
		if (errn) {
			if (errn == 1)
				errn = 0;
			goto out;
		}
		if (fv.optable[finh(&fv)->opcode](&fv))
			goto out;
	}

 out:
	if (fv.root_fnode)
		fops(&fv)->gc(&fv, fv.root_fnode);
	free(fv.inbuf);
	free(fv.outbuf);

	return errn;
}

struct fnode *
make_fnode(struct fvfs *fv, size_t privsize)
{
	struct fnode *fn;

	fn = malloc(sizeof(*fn) + fops(fv)->treedata_size + privsize);
	if (!fn)
		return NULL;

	fn->treedata = fn + 1;
	fn->priv = (char *)fn->treedata + fops(fv)->treedata_size;
	fn->nlookup = 1;

	if (fops(fv)->init)
		fops(fv)->init(fv, fn);

	return fn;
}

struct fnode *
insert_lookup_fnode(struct fvfs *fv, struct fnode *fn, struct fnode *cfn)
{
	struct fnode *xfn;

	xfn = fops(fv)->insert(fn, cfn);
	if (xfn) {
		fops(fv)->gc(fv, cfn);
		return xfn;
	}

	return cfn;
}

int
folly_forget(struct fvfs *fv)
{
	struct fuse_forget_in *ffi = fuse_req_body(fv);
	struct fnode *fn;
#ifdef _DIAG
	int gcrv;
#endif
	fn = fi2fn(fv, finh(fv)->nodeid);

	DIAG(fv, " node %llu: nlookup %llu - %llu",
	     finh(fv)->nodeid, fn->nlookup, ffi->nlookup);

	assert(fn->nlookup >= ffi->nlookup);
	if (fn->nlookup == ffi->nlookup) {
#ifdef _DIAG
		if (fops(fv)->has_children && fops(fv)->has_children(fn))
			DIAG(fv,
			     " !!! disconnection occurs by deleting node #%llu\n",
			     finh(fv)->nodeid);
		gcrv =
#endif
		fops(fv)->gc(fv, fn);
	} else
		fn->nlookup -= ffi->nlookup;

	DIAG(fv, "%s\n", gcrv == 0 ? ", zap!" : "");

	return 0;
}
