#ifdef linux
#define _XOPEN_SOURCE 500
#define _FILE_OFFSET_BITS 64
#endif

#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <dirent.h>
#include <err.h>
#include <assert.h>
#include <poll.h>
#include <sys/inotify.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "folly.h"

#ifndef MAX
#define MAX(a, b) (((a) < (b)) ? (b) : (a))
#endif

typedef int (nully_handler_t)(struct fvfs *fv, char *path);

static int i_max_watch;
static struct fnode **inotify_table;
static char inval_buf[sizeof(struct fuse_out_header) +
                      MAX(sizeof(struct fuse_notify_inval_inode_out),
                          sizeof(struct fuse_notify_inval_entry_out) + NAME_MAX + 1)];
static int transfer_pipe[2];
struct pollfd pollfd[2];
int inotify_fd;
static char inotbuf[1024];
static char pbuf[PATH_MAX + NAME_MAX + 2];
static nully_handler_t *nully_path_optable[FUSE_OPTABLE_SIZE];
static struct fnode_ops *base_fnodeops;

struct nully_priv {
	char *name;
	struct fnode *par_fn;
	int inotify_wd;
	/* To discard inotify events completely precisely,
	 * we'd need to maintain a counter for each event...
	 * anyway, not a big problem if some discardable
	 * events go through, we just send a few sprurious
	 *invalidations.
	 */
	int inotify_discard;
	uint8_t name_external:1;
	uint8_t negative:1;
};

static inline struct nully_priv *
pri(struct fnode *fn)
{
	return (struct nully_priv *)fn->priv;
}

static void
i_add_watch(struct fvfs *fv, char *path, struct fnode *fn)
{
	int wd;

	wd = inotify_add_watch(inotify_fd, path,
	                       IN_ATTRIB|IN_DELETE|IN_MODIFY|IN_MOVED_FROM|
	                       IN_MOVED_TO|IN_CREATE|IN_DONT_FOLLOW);
	assert(wd != -1);
	assert(wd < i_max_watch);

	inotify_table[wd] = fn;
	pri(fn)->inotify_wd = wd;
}

static void
nully_remove(struct fvfs *fv, struct fnode *fn, struct fnode *cfn)
{
	if (pri(cfn)->inotify_wd) {
		assert( !inotify_rm_watch(inotify_fd, pri(cfn)->inotify_wd) );
		inotify_table[pri(cfn)->inotify_wd] == NULL;
		pri(cfn)->inotify_wd = 0;
	}
	fops(fv)->remove(fn, cfn);
	if (pri(cfn)->negative)
		fops(fv)->gc(fv, cfn);
}

static char *
get_path(struct fvfs *fv, f_ino_t nid, char *buf)
{
	struct fnode *fn = fi2fn(fv, nid);
	char *bc = buf;

	if (fn == fv->root_fnode) {
		bc[0] = '.';
		bc[1] = '\0';

		return bc;
	}

	bc = buf + PATH_MAX - 1;
	bc -= strlen(pri(fn)->name) - 1;
	strcpy(bc, pri(fn)->name);

	for (;;) {
		if (!fops(fv)->connected(fn)) {
			errno = ENOENT;
			return NULL;
		}
		fn = pri(fn)->par_fn;
		assert(fn);
		if (fn == fv->root_fnode)
			return bc;
		if (bc <= buf) {
			errno = ENAMETOOLONG;
			return NULL;
		}
		*(--bc) = '/';
		bc -= strlen(pri(fn)->name);
		memcpy(bc, pri(fn)->name, strlen(pri(fn)->name));
	}
}

static int
pathappend(char *path, char *name)
{
	size_t psiz = strlen(path);

	if (psiz + strlen(name) + 1 >= PATH_MAX)
		return ENAMETOOLONG;

	path[psiz] = '/';
	memcpy(path + psiz + 1, name, strlen(name) + 1);

	return 0;
}

static struct fnode *
make_fnode_nully(struct fvfs *fv, struct fnode *fn, char *name)
{
	struct fnode *cfn;

	assert( strlen(name) <= NAME_MAX );
	cfn = make_fnode(fv, sizeof(struct nully_priv) + strlen(name) + 1);
	if (!cfn)
		return NULL;
	memcpy(pri(cfn) + 1, name, strlen(name) + 1);
	pri(cfn)->name = (char *)(pri(cfn) + 1);
	pri(cfn)->par_fn = fn;
	pri(cfn)->inotify_wd = 0;
	pri(cfn)->inotify_discard = 0;
	pri(cfn)->name_external = 0;
	pri(cfn)->negative = 0;

	return cfn;
}

static int
nully_path_dispatch(struct fvfs *fv)
{
	char *path;

	path = get_path(fv, finh(fv)->nodeid, pbuf);
	DIAG(fv, " #%llu => %s\n", finh(fv)->nodeid, path ? path : "??");

	if (path) {
		errno = 0;
		return nully_path_optable[finh(fv)->opcode](fv, path);
	} else
		return send_fuse_err(fv, errno);
}

static int
nully_statfs(struct fvfs *fv, char *path)
{
	struct fuse_statfs_out *fso = fuse_ans_body(fv);
	struct statvfs svfs;

	if (statvfs(path, &svfs) != -1) {
		fso->st.blocks   = svfs.f_blocks;
		fso->st.bfree    = svfs.f_bfree;
		fso->st.bavail   = svfs.f_bavail;
		fso->st.files    = svfs.f_files;
		fso->st.ffree    = svfs.f_ffree;
		fso->st.bsize    = svfs.f_bsize;
		fso->st.namelen  = svfs.f_namemax;
		fso->st.frsize   = svfs.f_frsize;
	}

	return send_fuse_obj(fv, fso, errno);
}

static void
stat2attr_i(struct stat *st, struct fuse_attr *fa)
{
	/* XXX SUSv4 subsecond times... */

	memset(fa, 0, sizeof(*fa));

	fa->size       = st->st_size;
	fa->blocks     = st->st_blocks;
	fa->atime      = st->st_atime;
	fa->mtime      = st->st_mtime;
	fa->ctime      = st->st_ctime;
/*
	fa->atimensec  = 0;
	fa->mtimensec  = 0;
	fa->ctimensec  = 0;
 */
	fa->mode       = st->st_mode;
	fa->nlink      = st->st_nlink;
	fa->uid        = st->st_uid;
	fa->gid        = st->st_gid;
	fa->rdev       = st->st_rdev;
	fa->blksize    = st->st_blksize;
}

#define stat2attr(st, fx) 		\
do {					\
	stat2attr_i(st, &(fx)->attr);	\
	(fx)->attr.ino = (st)->st_ino;	\
} while (0)

static int
nully_getattr(struct fvfs *fv, char *path)
{
	struct fuse_attr_out *fao = fuse_ans_body(fv);
	struct stat st;

	if (lstat(path, &st) != -1) {
		fao->attr_valid      = (uint64_t)-1;
		fao->attr_valid_nsec = 0;
		stat2attr(&st, fao);
	}

	return send_fuse_obj(fv, fao, errno);
}

static int
nully_lookup(struct fvfs *fv, char *path)
{
	struct fnode *fn = argnode(fv);
	struct fnode *cfn;
	char *name = fuse_req_body(fv);
	struct fuse_entry_out *feo = fuse_ans_body(fv);
	struct stat st;
	int rv;

	rv = pathappend(path, name);
	if (rv)
		return send_fuse_err(fv, rv);

	rv = lstat(path, &st);
	cfn = fops(fv)->lookup(fn, name);
	assert( !(cfn && pri(cfn)->negative) );

	if (rv == -1) {
		if (errno == ENOENT) {
			if (cfn) {
				nully_remove(fv, fn, cfn);

				DIAG(fv, " #%llu/%s => (#%llu) X\n", fn2fi(fv, fn),
				     name, fn2fi(fv, cfn));
			}

			/* add a negative entry both on our side and
		         * on kernel's
			 */
			cfn = make_fnode_nully(fv, fn, name);
			if (!cfn)
				return send_fuse_err(fv, errno);
			pri(cfn)->negative = 1;
			fops(fv)->insert_dirty(fn, cfn);

			DIAG(fv, " #%llu/%s => #%llu -\n", fn2fi(fv, fn), name,
			     fn2fi(fv, cfn));

			errno = 0;
			memset(feo, 0, sizeof(*feo));
			feo->entry_valid = (uint64_t)-1;
		}
	} else {
		if (cfn) {
			cfn->nlookup++;

			DIAG(fv, " #%llu/%s => #%llu\n", fn2fi(fv, fn), name,
			     fn2fi(fv, cfn));
		} else {
			cfn = make_fnode_nully(fv, fn, name);
			if (!cfn)
				return send_fuse_err(fv, errno);
			if (S_ISDIR(st.st_mode))
				i_add_watch(fv, path, cfn);
			fops(fv)->insert_dirty(fn, cfn);

			DIAG(fv, " #%llu/%s => #%llu !\n", fn2fi(fv, fn), name,
			     fn2fi(fv, cfn));
		}
		memset(feo, 0, sizeof(*feo) - sizeof(feo->attr));
		feo->nodeid = fn2fi(fv, cfn);
		feo->entry_valid = (uint64_t)-1;
		feo->attr_valid = (uint64_t)-1;
		stat2attr(&st, feo);
	}

	return send_fuse_obj(fv, feo, errno);
}

static int
nully_opendir(struct fvfs *fv, char *path)
{
	struct fuse_open_out *foo = fuse_ans_body(fv);
	DIR *d;

	d = opendir(path);

	foo->fh = (uintptr_t)d;
	foo->open_flags = FOPEN_KEEP_CACHE;

	return send_fuse_obj(fv, foo, errno);
}

static int
nully_readdir(struct fvfs *fv)
{
	struct fuse_read_in *fri = fuse_req_body(fv);
	DIR *d = (DIR *)(uintptr_t)fri->fh;
	struct fuse_dirent *fde = fuse_ans_body(fv);
	struct dirent *de;
	size_t rem = fri->size;

	errno = 0;

	seekdir(d, fri->offset);

	for (;;) {
		if (rem < sizeof(*fde))
			break;
		de = readdir(d);
		if (!de)
			break;
		fde->namelen = strlen(de->d_name);
		if (rem < FUSE_DIRENT_SIZE(fde))
			break;
#ifdef __FreeBSD__
		fde->ino = de->d_fileno;
#else
		fde->ino = de->d_ino;
#endif
		fde->off = telldir(d);
		fde->type = de->d_type;
		strcpy((char *)fde + FUSE_NAME_OFFSET, de->d_name);
		rem -= FUSE_DIRENT_SIZE(fde);
		fde = (struct fuse_dirent *)((char *)fde + FUSE_DIRENT_SIZE(fde));
	}

	return send_fuse_data(fv, fri->size - rem, errno);
}

static int
nully_open(struct fvfs *fv, char *path)
{
	struct fuse_open_in  *foi = fuse_req_body(fv);
	struct fuse_open_out *foo = fuse_ans_body(fv);
	int fd;

	fd = open(path, foi->flags, foi->mode);

	foo->fh = fd;
	foo->open_flags = 0;

	return send_fuse_obj(fv, foo, errno);
}

static int
link_entry(struct fvfs *fv, struct fnode *fn, struct stat *st, char *name,
           size_t size)
{
	struct fuse_entry_out *feo = fuse_ans_body(fv);
	struct fnode *cfn;

	if (errno)
		return send_fuse_err(fv, errno);

	cfn = make_fnode_nully(fv, fn, name);
	if (!cfn)
		return send_fuse_err(fv, errno);
	cfn = insert_lookup_fnode(fv, fn, cfn);
	pri(cfn)->negative = 0;
	pri(cfn)->inotify_discard |= IN_CREATE;

	DIAG(fv, " #%llu/%s => #%llu !\n", fn2fi(fv, fn), name,
	     fn2fi(fv, cfn));

	memset(feo, sizeof(*feo) - sizeof(feo->attr), 0);
	feo->nodeid = fn2fi(fv, cfn);
	feo->entry_valid = (uint64_t)-1;
	feo->attr_valid = (uint64_t)-1;
	stat2attr(st, feo);

	return send_fuse_data(fv, sizeof(*feo) + size, errno);
}

static int
nully_create(struct fvfs *fv, char *path)
{
	struct fnode *fn = argnode(fv); 
	struct fuse_open_in *foi = fuse_req_body(fv);
	char *name = (char *)(foi + 1);
	struct fuse_open_out *foo =
	  (struct fuse_open_out *)((struct fuse_entry_out *)fuse_ans_body(fv) + 1);
	struct stat st;
	int fd, rv;

	rv = pathappend(path, name);
	if (rv)
		return send_fuse_err(fv, rv);

	fd = open(path, foi->flags | O_CREAT|O_EXCL, foi->mode);
	if (fd == -1)
		return send_fuse_err(fv, errno);
	foo->fh = fd;
	foo->open_flags = 0;
	fstat(fd, &st);

	return link_entry(fv, fn, &st, name, sizeof(*foo));
}

static int
nully_mknod(struct fvfs *fv, char *path)
{
	struct fnode *fn = argnode(fv); 
	struct fuse_mknod_in  *fmi = fuse_req_body(fv);
	char *name = (char *)(fmi + 1);
	struct stat st;
	int rv;

	rv = pathappend(path, name);
	if (rv)
		return send_fuse_err(fv, rv);

	rv = S_ISFIFO(fmi->mode) ?
	     mkfifo(path, fmi->mode) :
	     mknod(path, fmi->mode, fmi->rdev);
	if (rv == -1)
		return send_fuse_err(fv, errno);
	lstat(path, &st);

	return link_entry(fv, fn, &st, name, 0);
}

static int
nully_mkdir(struct fvfs *fv, char *path)
{
	struct fnode *fn = argnode(fv); 
	struct fuse_mknod_in  *fmi = fuse_req_body(fv);
	char *name = (char *)(fmi + 1);
	struct stat st;
	int rv;

	rv = pathappend(path, name);
	if (rv)
		return send_fuse_err(fv, rv);

	rv = mkdir(path, fmi->mode);
	if (rv == -1)
		return send_fuse_err(fv, errno);
	lstat(path, &st);

	return link_entry(fv, fn, &st, name, 0);
}

static int
nully_link(struct fvfs *fv, char *path)
{
	struct fnode *fn = argnode(fv); 
	struct fuse_link_in *fli = fuse_req_body(fv);
	char *name = (char *)(fli + 1);
	char *origpath, origpbuf[PATH_MAX + 1];
	struct stat st;
	int rv;

	origpath = get_path(fv, fli->oldnodeid, origpbuf);
	if (!origpath)
		return send_fuse_err(fv, errno);
	rv = pathappend(path, name);
	if (rv)
		return send_fuse_err(fv, rv);

	rv = link(origpath, path);
	if (rv == -1)
		return send_fuse_err(fv, errno);
	lstat(path, &st);

	return link_entry(fv, fn, &st, name, 0);
}

static int
nully_symlink(struct fvfs *fv, char *path)
{
	struct fnode *fn = argnode(fv); 
	char *target = fuse_req_body(fv);
	char *name = target + strlen(target) + 1;
	struct stat st;
	int rv;

	rv = pathappend(path, target);
	if (rv)
		return send_fuse_err(fv, rv);

	rv = symlink(name, path);
	if (rv == -1)
		return send_fuse_err(fv, errno);
	lstat(path, &st);

	return link_entry(fv, fn, &st, name, 0);
}

static int
nully_unlink_generic(struct fvfs *fv, char *path,
                     int (*unlinklike)(const char *path))
{
	char *name = fuse_req_body(fv);
	struct fnode *cfn, *fn = argnode(fv); 
	int rv;

	rv = pathappend(path, name);
	if (rv)
		return send_fuse_err(fv, rv);

	rv = unlinklike(path);
	if (rv == -1)
		return send_fuse_err(fv, errno);

	cfn = fops(fv)->lookup(fn, name);
	if (cfn) {
		assert( !pri(cfn)->negative );
		nully_remove(fv, fn, cfn);

		DIAG(fv, " #%llu/%s => #%llu X\n", fn2fi(fv, fn), name,
		     fn2fi(fv, cfn));
	}

	return send_fuse_data(fv, 0, errno);
}

static int
nully_unlink(struct fvfs *fv, char *path)
{
	return nully_unlink_generic(fv, path, unlink);
}

static int
nully_rmdir(struct fvfs *fv, char *path)
{
	return nully_unlink_generic(fv, path, rmdir);
}

static int
nully_rename(struct fvfs *fv, char *path)
{
	struct fuse_rename_in *fri = fuse_req_body(fv);
	char *fname = (char *)(fri + 1);
	char *tname = fname + strlen(fname) + 1; 
	struct fnode *fn = argnode(fv);
	struct fnode *cfn, *cfn2, *tfn;
	char *targetpath, targetpbuf[PATH_MAX + NAME_MAX + 2]; 
	int rv;

	targetpath = get_path(fv, fri->newdir, targetpbuf);
	if (!targetpath)
		return send_fuse_err(fv, errno);
	rv = pathappend(path, fname);
	if (rv)
		return send_fuse_err(fv, rv);
	rv = pathappend(targetpath, tname);
	if (rv)
		return send_fuse_err(fv, rv);

	rv = rename(path, targetpath);
	if (rv == -1)
		return send_fuse_err(fv, rv);

	tfn = fi2fn(fv, fri->newdir);
	cfn = fops(fv)->lookup(fn, fname);
	if (cfn) {
		assert( !pri(cfn)->negative );

		/* The hairy operation of doing the
		 * rename in folly's node space...
		 * this is needed to keep being
		 * sync with kernel's entry cache.
		 *
		 * Now it's done properly so eventually
		 * we can discard the induced inotify event.
		 */

		fops(fv)->remove(fn, cfn);

		if (strlen(tname) <= strlen(pri(cfn)->name))
			strcpy(pri(cfn)->name, tname);
		else {
			if (pri(cfn)->name_external)
				free(pri(cfn)->name);
			pri(cfn)->name = strdup(tname);
			if (!pri(cfn)->name)
				return send_fuse_err(fv, errno);
			pri(cfn)->name_external = 1;
		}

		DIAG(fv, " #%llu/%s -> #%llu/%s => #%llu\n", fn2fi(fv, fn),
		     fname, fn2fi(fv, tfn), tname, fn2fi(fv, cfn));
	} else {
		cfn = make_fnode_nully(fv, tfn, tname);
		if (!cfn)
			return send_fuse_err(fv, errno);

		DIAG(fv, " #%llu/%s => #%llu !\n", fn2fi(fv, tfn),
		     tname, fn2fi(fv, cfn));
	}
	pri(cfn)->inotify_discard |= IN_MOVED_TO;

	cfn2 = fops(fv)->insert(tfn, cfn);
	if (cfn2) {
		DIAG(fv, " #%llu/%s => #%llu X\n", fn2fi(fv, tfn),
		     tname, fn2fi(fv, cfn2));

		nully_remove(fv, tfn, cfn2);
		fops(fv)->insert_dirty(tfn, cfn);
	}

	return send_fuse_data(fv, 0, errno);
}

static int
nully_access(struct fvfs *fv, char *path)
{
	struct fuse_access_in *fai = fuse_req_body(fv);

	access(path, fai->mask);

	return send_fuse_data(fv, 0, errno);
}

static int
nully_read(struct fvfs *fv)
{
	struct fuse_read_in *fri = fuse_req_body(fv);
	size_t bytes;

	errno = 0;

	bytes = pread(fri->fh, fuse_ans_body(fv), fri->size, fri->offset);

	return send_fuse_data(fv, bytes, errno);
}

static int
nully_write(struct fvfs *fv)
{
	struct fuse_write_in  *fwi = fuse_req_body(fv);
	struct fuse_write_out *fwo = fuse_ans_body(fv);

	errno = 0;

	fwo->size = pwrite(fwi->fh, fwi + 1, fwi->size, fwi->offset);
	pri(argnode(fv))->inotify_discard |= IN_MODIFY;

	return send_fuse_obj(fv, fwo, errno);
}

static int
nully_flush(struct fvfs *fv)
{
	struct fuse_flush_in *ffi = fuse_req_body(fv);

	errno = 0;

	close(dup(ffi->fh));

	return send_fuse_data(fv, 0, errno);
}

static int
nully_release(struct fvfs *fv)
{
	struct fuse_release_in *fri = fuse_req_body(fv);

	errno = 0;

	close(fri->fh);

	return send_fuse_data(fv, 0, errno);
}

static int
nully_releasedir(struct fvfs *fv)
{
	struct fuse_release_in *fri = fuse_req_body(fv);

	errno = 0;

	closedir((DIR *)(uintptr_t)(fri->fh));

	return send_fuse_data(fv, 0, errno);
}

static int
nully_fsync(struct fvfs *fv)
{
	struct fuse_fsync_in *fsi = fuse_req_body(fv);

	errno = 0;

	fsync(fsi->fh);

	return send_fuse_data(fv, 0, errno);
}

static int
nully_setattr(struct fvfs *fv, char *path)
{
	struct fuse_setattr_in *fsi = fuse_req_body(fv);
	int rv = 0;
	int diev = 0;

	/*
	 * For the sake of simplicity we don't make use of
	 * the filehandle here (the avaliability of which
	 * is flagged via FATTR_FH).
	 */

	if (fsi->valid & FATTR_MODE) {
		rv = chmod(path, fsi->mode);
		if (rv != -1)
			diev |= IN_ATTRIB;
	}
	if (rv != -1 && fsi->valid & (FATTR_UID|FATTR_GID)) {
		rv = chown(path,
		           fsi->valid & FATTR_UID ? fsi->uid : -1,
		           fsi->valid & FATTR_GID ? fsi->gid : -1);
		if (rv != -1)
			diev |= IN_ATTRIB;
	}
	if (rv != -1 && FATTR_SIZE) {
		rv = truncate(path, fsi->size);
		if (rv != -1)
			diev |= IN_MODIFY;
	}
	if (rv != -1 &&
	    (fsi->valid & (FATTR_ATIME|FATTR_MTIME)) == (FATTR_ATIME|FATTR_MTIME)) {
		struct timeval tv[2];

		tv[0].tv_sec  = fsi->atime;
		tv[0].tv_usec = fsi->atimensec;
		tv[1].tv_sec  = fsi->mtime;
		tv[1].tv_usec = fsi->mtimensec;
		rv = utimes(path, tv);
		if (rv != -1)
			diev |= IN_ATTRIB;
	}

	pri(argnode(fv))->inotify_discard |= diev;

	return (rv == -1) ?
	       send_fuse_err(fv, errno) :
	       nully_getattr(fv, path);
}

static int
nully_readlink(struct fvfs *fv, char *path)
{
	ssize_t bytes;

	bytes = readlink(path, fuse_ans_body(fv),
	                 fv->parm.outbufsize - sizeof(struct fuse_out_header) - 1);

	if (bytes >= 0)
		((char *)fuse_ans_body(fv))[bytes] = '\0';

	return send_fuse_data(fv, bytes + 1, errno);
}

static int
nully_node_cmp(struct fnode *fn, void *p)
{
	return strcmp(pri(fn)->name, p);
}

static void *
nully_node_key(struct fnode *fn)
{
	return pri(fn)->name;
}

static unsigned
nully_node_hash(void *p)
{
	char *name = p;
	unsigned hash = *name;

	if (hash)
		for (name++; *name; name++)
			hash = (hash << 5) - hash + *name;

	return hash;
}

static int
nully_gc(struct fvfs *fv, struct fnode *fn)
{
	char *name = NULL;
	int rv;

	if (pri(fn)->name_external)
		name = pri(fn)->name;

	rv = base_fnodeops->gc(fv, fn);
	if (rv == 0 && name)
		free(name);

	return rv;
}

static void
send_inval_async(size_t len)
{
	int rv;

	rv = write(transfer_pipe[1], inval_buf, len);
	if (rv != len && errno == 0)
		errno = EIO;
}

static void
revinval_node(f_ino_t nid, int off)
{
	struct fuse_out_header *fouh = (struct fuse_out_header *)inval_buf;
	struct fuse_notify_inval_inode_out *fniio =
	  (struct fuse_notify_inval_inode_out *)(fouh + 1);

	fouh->error = FUSE_NOTIFY_INVAL_INODE;
	fouh->len = sizeof(*fouh) + sizeof(*fniio);
	fniio->ino = nid;
	fniio->off = off;
	fniio->len = -1;

	send_inval_async(fouh->len);
}

static void
revinval_entry(f_ino_t nid, char *name)
{
	struct fuse_out_header *fouh = (struct fuse_out_header *)inval_buf;
	struct fuse_notify_inval_entry_out *fnieo =
	  (struct fuse_notify_inval_entry_out *)(fouh + 1);
	int nlen;

	nlen = strlen(name);

	fouh->error = FUSE_NOTIFY_INVAL_ENTRY;
	fouh->len = sizeof(*fouh) + sizeof(*fnieo) + nlen + 1;
	fnieo->parent = nid;
	fnieo->namelen = nlen;
	strcpy(inval_buf + sizeof(*fouh) + sizeof(*fnieo), name);

	send_inval_async(fouh->len);
}

static int
nully_inotify_handler(struct fvfs *fv, struct inotify_event *iev)
{
	f_ino_t nid;
	struct fnode *fn, *cfn;
	char *path;
	int md;

	fn = inotify_table[iev->wd];
	assert(fn);
	nid = fn2fi(fv, fn);
	path = get_path(fv, nid, pbuf);

	DIAG(fv, "INOTIFY: wd %d, mask %#x, name %s, len %d\n"
	         " #%llu => %s\n",
	         iev->wd, iev->mask, iev->name, iev->len,
	         nid, path ? path : "??");

	cfn = fops(fv)->lookup(fn, iev->name);
	if (cfn) {
		DIAG(fv, " #%llu/%s => #%llu\n", nid, iev->name,
		     fn2fi(fv, cfn));
		md = iev->mask & ~pri(cfn)->inotify_discard;
		pri(cfn)->inotify_discard &= ~iev->mask;
		if (md != iev->mask)
			DIAG(fv, " discarded events %#x, kept %#x\n",
			     iev->mask & ~md, md);
	} else {
		DIAG(fv, " discarded b/c no node\n");

		return 0;
	}

	errno = 0;
	if (md & IN_ATTRIB) {
		DIAG(fv, " ATTRIB\n");
		revinval_node(fn2fi(fv, cfn), -1);
		if (errno)
			return errno;
	}
	if (md & IN_DELETE) {
		DIAG(fv, " DELETE\n");
		revinval_entry(nid, iev->name);
		if (errno)
			return errno;
		nully_remove(fv, fn, cfn);
	}
	if (md & IN_MODIFY) {
		DIAG(fv, " MODIFY\n");
		revinval_node(fn2fi(fv, cfn), 0);
		if (errno)
			return errno;
	}
	if (md & IN_MOVED_FROM) {
		DIAG(fv, " MOVED_FROM\n");
		revinval_entry(nid, iev->name);
		if (errno)
			return errno;
		nully_remove(fv, fn, cfn);
	}
	if (md & IN_MOVED_TO) {
		DIAG(fv, " MOVED_TO\n");
		revinval_entry(nid, iev->name);
		if (errno)
			return errno;
		if (pri(cfn)->negative)
			nully_remove(fv, fn, cfn);
	}
	if (md & IN_CREATE) {
		assert( pri(cfn)->negative );

		DIAG(fv, " CREATE\n");
		revinval_entry(nid, iev->name);
		if (errno)
			return errno;
		nully_remove(fv, fn, cfn);
	}

	return 0;
}

static int
nully_prelude(struct fvfs *fv)
{
	i_add_watch(fv, ".", fv->root_fnode);

	return 0;
}

static int
nully_event_handler(struct fvfs *fv)
{
	int bytes, rv;
	char *ibx;
	struct inotify_event *iev;

	rv = poll(pollfd, 2, -1);
	if (rv == -1)
		return -errno;
	if (pollfd[0].revents & POLLERR)
		return -EBADF;

	/* got inotify event */
	if (pollfd[1].revents & POLLIN) {
		bytes = read(inotify_fd, inotbuf, sizeof(inotbuf));
		if (bytes == -1)
			return -errno;

		for (ibx = inotbuf; ; ibx += sizeof(*iev) + iev->len) {
			iev = (struct inotify_event *)ibx;
			if (ibx + sizeof(*iev) > inotbuf + bytes ||
			    ibx + sizeof(*iev) + iev->len > inotbuf + bytes)
				break;
			rv = nully_inotify_handler(fv, iev);
			if (rv)
				return -rv;
		}
	}

	/* got FUSE request */
	if (pollfd[0].revents & POLLIN)
		return 1;

	return 0;
}

static void transfer_loop(int infd, int outfd)
{
	struct fuse_out_header *fouh;
	int rv;

	for (;;) {
		rv = read(infd, inval_buf, sizeof(*fouh));
		if (rv != sizeof(*fouh))
			break;
		fouh = (struct fuse_out_header *)inval_buf;
		rv = read(infd, inval_buf + sizeof(*fouh),
		          fouh->len - sizeof(*fouh));
		if (rv != fouh->len - sizeof(*fouh))
			break;
		rv = write(outfd, inval_buf, fouh->len);
		if (rv != fouh->len)
			break;
	}
}

struct nully_handler_spec {
	enum fuse_opcode opcode;
	nully_handler_t *handler;
};

static struct nully_handler_spec nully_path_opmap[] = {
	{ FUSE_STATFS,      nully_statfs   },
	{ FUSE_GETATTR,     nully_getattr  },
	{ FUSE_LOOKUP,      nully_lookup   },
	{ FUSE_OPEN,        nully_open     },
	{ FUSE_OPENDIR,     nully_opendir  },
	{ FUSE_CREATE,      nully_create   },
	{ FUSE_MKNOD,       nully_mknod    },
	{ FUSE_MKDIR,       nully_mkdir    },
	{ FUSE_SETATTR,     nully_setattr  },
	{ FUSE_LINK,        nully_link     },
	{ FUSE_SYMLINK,     nully_symlink  },
	{ FUSE_UNLINK,      nully_unlink   },
	{ FUSE_RMDIR,       nully_rmdir    },
	{ FUSE_RENAME,      nully_rename   },
	{ FUSE_ACCESS,      nully_access   },
	{ FUSE_READLINK,    nully_readlink },
	{0,                 0              }
};

static struct handler_spec nully_opmap[] = {
	{ FUSE_READDIR,     nully_readdir    },
	{ FUSE_READ,        nully_read       },
	{ FUSE_WRITE,       nully_write      },
	{ FUSE_FLUSH,       nully_flush      },
	{ FUSE_RELEASE,     nully_release    },
	{ FUSE_RELEASEDIR,  nully_releasedir },
	{ FUSE_FSYNC,       nully_fsync      },
	{0,                 0                }
};

int
main(int argc, char **argv)
{
	struct nully_handler_spec *nhp = nully_path_opmap;
	struct fvfs_param fvp;
	struct hash_vfs_treedata vdat;
	int i = 1;
	char *null_root = "/";
	char *fnodeops_name;
	int fd;
	char procbuf[32];
	struct nully_priv root_priv;
	int fuse_fd;
	/**/
	pid_t pid;
	char *ibx;
	struct inotify_event *iev;
	struct fnode_ops nully_fnodeops;

	init_fvfs_param(&fvp);

	/* parse cmdline */
	if (argc > i) {
		if (strcmp(argv[i], "-d") == 0) {
			fvp.diag = 1;
			i++;
		}
	}
	if (argc > i) {
		null_root = argv[i];
		i++;
	}
	if (argc > i)
		errx(1, "usage: nully [-d] [path]");
	if (chdir(null_root) == -1)
		err(1, "cannot enter null root");

	fuse_fd = acquire_fuse_fd();
	if (fuse_fd == -1)
		err(1, "cannot connect fuse device");

	if (pipe(transfer_pipe) == -1)
		err(1, "cannot create pipe pair");
	pid = fork();
	if (pid == -1)
		err(1, "cannot fork");
	if (pid)
		close(transfer_pipe[0]);
	else {
		close(transfer_pipe[1]);
		transfer_loop(transfer_pipe[0], fuse_fd);
		exit(0);
	}

	/* assemble the optables */
	add_opmap(nully_opmap, fvp.optable);
	add_opmap_generic(nhp, nully_path_optable);
	for (nhp = nully_path_opmap; nhp->opcode; nhp++)
		fvp.optable[nhp->opcode] = nully_path_dispatch;

	/* set other params */
	inotify_fd = inotify_init();
	if (inotify_fd == -1)
		err(1, "cannot init inotify");
	pollfd[0].fd = fuse_fd;
	pollfd[1].fd = inotify_fd;
	pollfd[0].events = pollfd[1].events = POLLIN;

	vdat.compare = nully_node_cmp;
	vdat.key = nully_node_key;
	fnodeops_name = getenv("FOLLY_FNODEOPS");
	if (fnodeops_name) {
		if (strcmp(fnodeops_name, "list") == 0)
			base_fnodeops = &list_fnode_ops;
		else if (strcmp(fnodeops_name, "rb") == 0)
			base_fnodeops = &rb_fnode_ops;
		else if (strcmp(fnodeops_name, "hash") == 0) {
			base_fnodeops = &hash_fnode_ops;
			vdat.hash_table_size = 14507;
			vdat.hash_table =
			  calloc(vdat.hash_table_size, sizeof(struct fnode));
			if (!vdat.hash_table)
				err(1, "can't allocate hash table");
			vdat.hash = nully_node_hash;
		} else
			errx(1, "unknown fnodeops \"%s\"", fnodeops_name);

		/* closet OO */
		memcpy(&nully_fnodeops, base_fnodeops,
		       sizeof(struct fnode_ops));
		nully_fnodeops.gc = nully_gc;
		fvp.fops = &nully_fnodeops;
	}

	fvp.vfs_treedata = &vdat;
	fvp.fuse_fd = fuse_fd;
	fvp.prelude = nully_prelude;
	fvp.event_handler = &nully_event_handler;
	fvp.root_fnode_priv = &root_priv;
	memset(inval_buf, 0, sizeof(inval_buf));

	fd = open("/proc/sys/fs/inotify/max_user_watches", O_RDONLY);
	if (fd == -1 || read(fd, procbuf, 32) == -1)
		err(1, "cannot read inotify max_user_watches");
	i_max_watch = strtoul(procbuf, NULL, 10);
	inotify_table = calloc(i_max_watch, sizeof(struct fnode *));
	if (inotify_table == NULL)
		err(1, "cannot allocate inotify table");

	/* go! */
	folly_loop(&fvp);

	return 0;
}
