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

#define EEOF -2

static int
get_fuse_req(struct fvfs *fv)
{
	size_t bytes;

	bytes = read(fv->parm.fuse_fd, fv->inbuf, fv->parm.inbufsize + HEADSPACE);
	if (bytes == -1) {
		if (errno != ENODEV) {
			warn("fuse device read");
			return errno;
		}
		return EEOF;
	}
#ifdef VALIDATE_INPUT
	if (bytes < sizeof(finh(fv)) || bytes != finh(fv)->len ||
	    finh(fv)->opcode >= FUSE_OPTABLE_SIZE ||
	    !fv->optable[finh(fv)->opcode]) {
		warnx("fuse protocol error");
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

static int
write_fuse_answer(struct fvfs *fv)
{
	size_t bytes;

	bytes = write(fv->parm.fuse_fd, fv->outbuf, fouh(fv)->len);
	if (bytes < fouh(fv)->len) {
		if (bytes == -1) {
			warn("fuse device write");
			return errno;
		} else {
			warnx("fuse protocol error");
			return -1;
		}
	}
	DIAG(fv, "  len %d, error \"%s\" [%d]\n", fouh(fv)->len,
	     strerror(-fouh(fv)->error), -fouh(fv)->error);
	return 0;
}

int
send_fuse_data(struct fvfs *fv, size_t len, int errn)
{
	assert(len <= fv->parm.outbufsize + HEADSPACE);
	fouh(fv)->len = sizeof(struct fuse_out_header) + (errn ? 0 : len);
	fouh(fv)->unique = finh(fv)->unique;
	fouh(fv)->error = -errn;

	return 0;
}

int
send_fuse_err(struct fvfs *fv, int errn)
{
	return send_fuse_data(fv, 0, errn);
}

static int
folly_init0(struct fvfs *fv)
{
	struct fuse_init_in  *fini = fuse_req_body(fv);
	struct fuse_init_out *fino = fuse_ans_body(fv);

	DIAG(fv, " kernel FUSE version %d.%d\n", fini->major, fini->minor);
	if (fini->major != FUSE_KERNEL_VERSION ||
	    fini->minor < FUSE_KERNEL_MINOR_VERSION) {
		warnx("unsupported proto version %d.%d from kernel",
		      fini->major, fini->minor);
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
	warnx("fuse protocol error");

	return -1;
}

int
folly_default_handler(struct fvfs *fv)
{
	return send_fuse_err(fv, ENOSYS);
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

	fvp->fuse_fd = -1;
	if (!fvp->inbufsize)
		fvp->inbufsize = DEFAULT_INBUFSIZE;
	if (!fvp->outbufsize)
		fvp->outbufsize = DEFAULT_OUTBUFSIZE;
	fvp->fops = &list_fnode_ops;
	make_default_optable(fvp->optable);
} 	

void
make_default_optable(folly_handler_t **optable)
{
	int i;

	for (i = 0; i < FUSE_OPTABLE_SIZE; i++)
		optable[i] = fuse_opnames[i] ? folly_default_handler : NULL;
	optable[FUSE_INIT] = folly_init;
	optable[FUSE_FORGET] = folly_forget;
}

static int
event_do_onlyfuse(struct fvfs *fv)
{
	return 1;
}

int
folly_loop(struct fvfs_param *fvp)
{
	int i, errn = -1;
	struct fvfs fv;
	struct handler_spec *hp;
	folly_handler_t *event_handler;
	int do_fuse;

	errno = 0;

	objzero(&fv);
	memcpy(&fv.parm, fvp, sizeof(*fvp));

	if (fv.parm.fuse_fd < 0) {
		warnx("cannot identify fuse device");
		return ENODEV;
	}

	fv.inbuf = malloc(fvp->inbufsize + HEADSPACE);
	if (!fv.inbuf) {
		warnx("cannot allocate input buffer");
		goto out;
	}
	fv.outbuf = malloc(fvp->outbufsize + HEADSPACE);
	if (!fv.outbuf) {
		warnx("cannot allocate output buffer");
		goto out;
	}
	fv.root_fnode = make_fnode(&fv, 0);
	if (!fv.root_fnode) {
		warnx("cannot create root node");
		goto out;
	}
	fv.root_fnode->priv = fvp->root_fnode_priv;
	event_handler = fvp->event_handler;
	if (!event_handler)
		event_handler = event_do_onlyfuse;

	if (get_fuse_req(&fv)) {
		warnx("fuse handshake failed");
		goto out;
	}

	if (finh(&fv)->opcode != FUSE_INIT) {
		warnx("fuse protocol error");
		goto out;
	}
	errn = (folly_init0(&fv) || write_fuse_answer(&fv));
	if (!errn && fvp->prelude)
		errn = fvp->prelude(&fv);
	if (errn)
		goto out;

	for (;;) {
		do_fuse = event_handler(&fv);

		if (do_fuse == 1) {
			errn = get_fuse_req(&fv);
			if (errn) {
				if (errn == EEOF)
					errn = 0;
				goto out;
			}
			errn = (fv.parm.optable[finh(&fv)->opcode](&fv) ||
			        write_fuse_answer(&fv));
		} else if (do_fuse < 0)
			errn = -do_fuse;

		if (errn)
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
#ifdef MARK_FOLLY
	if (fn->mark == FOLLYMARKER)
		warnx("weird: freshly allocated area %p for an fnode is already marked",
		      fn);
	fn->mark = FOLLYMARKER;
#endif

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
