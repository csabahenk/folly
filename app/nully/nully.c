#ifdef linux
#define _XOPEN_SOURCE 700
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
#ifdef linux
#include <attr/xattr.h>
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "folly.h"

typedef int (nully_handler_t)(struct fvfs *fv, char *path);

static char pbuf[PATH_MAX + NAME_MAX + 2];
static nully_handler_t *nully_path_optable[FUSE_OPTABLE_SIZE];

struct nully_priv {
	char *name;
	struct fnode *par_fn;
};

static inline struct nully_priv *
pri(struct fnode *fn)
{
	return (struct nully_priv *)fn->priv;
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

	cfn = make_fnode(fv, sizeof(struct nully_priv) + strlen(name) + 1);
	if (!cfn)
		return NULL;
	memcpy(pri(cfn) + 1, name, strlen(name) + 1);
	pri(cfn)->name = (char *)(pri(cfn) + 1);
	pri(cfn)->par_fn = fn;

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
		fao->attr_valid      = 0;
		fao->attr_valid_nsec = 0;
		stat2attr(&st, fao);
	}

	return send_fuse_obj(fv, fao, errno);
}

struct fnode *
nully_lookup_i(struct fvfs *fv, struct stat *st, int rv,
	       char *name, struct fuse_entry_out *feo)
{
	struct fnode *fn = argnode(fv);
	struct fnode *cfn;

	cfn = fops(fv)->lookup(fn, name);

	if (rv == -1) {
		if (errno == ENOENT && cfn) {
			fops(fv)->remove(fn, cfn);

			DIAG(fv, " #%llu/%s => (#%llu) X\n", fn2fi(fv, fn),
			     name, fn2fi(fv, cfn));
		} else
			DIAG(fv, " #%llu/%s => ??\n", fn2fi(fv, fn), name);
		return NULL;
	} else {
		if (cfn) {
			cfn->nlookup++;

			DIAG(fv, " #%llu/%s => #%llu\n", fn2fi(fv, fn), name,
			     fn2fi(fv, cfn));
		} else {
			cfn = make_fnode_nully(fv, fn, name);
			if (!cfn)
				return NULL;
			fops(fv)->insert_dirty(fn, cfn);

			DIAG(fv, " #%llu/%s => #%llu !\n", fn2fi(fv, fn), name,
			     fn2fi(fv, cfn));
		}
		memset(feo, 0, sizeof(*feo) - sizeof(feo->attr));
		feo->nodeid = fn2fi(fv, cfn);
		stat2attr(st, feo);
	}

	return cfn;
}

static int
nully_lookup(struct fvfs *fv, char *path)
{
	char *name = fuse_req_body(fv);
	struct fuse_entry_out *feo = fuse_ans_body(fv);
	struct stat st;
	int rv;

	rv = pathappend(path, name);
	if (rv)
		return send_fuse_err(fv, rv);

	rv = lstat(path, &st);
	nully_lookup_i(fv, &st, rv, name, feo);
	return send_fuse_obj(fv, feo, errno);
}

static int
nully_opendir(struct fvfs *fv, char *path)
{
	struct fuse_open_out *foo = fuse_ans_body(fv);
	DIR *d;

	d = opendir(path);

	foo->fh = (uintptr_t)d;
	foo->open_flags = 0;

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
		if ((long)fde->off == -1)
			return send_fuse_err(fv, errno);
		fde->type = de->d_type;
		strcpy((char *)fde + FUSE_NAME_OFFSET, de->d_name);
		rem -= FUSE_DIRENT_SIZE(fde);
		fde = (struct fuse_dirent *)((char *)fde + FUSE_DIRENT_SIZE(fde));
	}

	return send_fuse_data(fv, fri->size - rem, errno);
}

static int
nully_readdirplus(struct fvfs *fv)
{
	struct fuse_read_in *fri = fuse_req_body(fv);
	DIR *d = (DIR *)(uintptr_t)fri->fh;
	struct fuse_direntplus *fdep = fuse_ans_body(fv);
	struct dirent *de;
	size_t rem = fri->size;

	errno = 0;

	seekdir(d, fri->offset);

	for (;;) {
		struct fnode *cfn;
		struct stat st;
		int rv;

		if (rem < sizeof(*fdep))
			break;
		de = readdir(d);
		if (!de)
			break;
		fdep->dirent.namelen = strlen(de->d_name);
		if (rem < FUSE_DIRENTPLUS_SIZE(fdep))
			break;
#ifdef __FreeBSD__
		fdep->dirent.ino = de->d_fileno;
#else
		fdep->dirent.ino = de->d_ino;
#endif
		fdep->dirent.off = telldir(d);
		if ((long)fdep->dirent.off == -1)
			return send_fuse_err(fv, errno);
		fdep->dirent.type = de->d_type;

		rv = fstatat(dirfd(d), de->d_name, &st, AT_SYMLINK_NOFOLLOW);
		if (!nully_lookup_i(fv, &st, rv, de->d_name, &fdep->entry_out))
			memset(&fdep->entry_out, 0, sizeof(fdep->entry_out));

		strcpy((char *)fdep + FUSE_NAME_OFFSET_DIRENTPLUS, de->d_name);
		rem -= FUSE_DIRENTPLUS_SIZE(fdep);
		fdep = (struct fuse_direntplus *)((char *)fdep + FUSE_DIRENTPLUS_SIZE(fdep));
	}

	return send_fuse_data(fv, fri->size - rem, errno);
}

static int
nully_open(struct fvfs *fv, char *path)
{
	struct fuse_open_in  *foi = fuse_req_body(fv);
	struct fuse_open_out *foo = fuse_ans_body(fv);
	int fd;

	fd = open(path, foi->flags);

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

	DIAG(fv, " #%llu/%s => #%llu !\n", fn2fi(fv, fn), name,
	     fn2fi(fv, cfn));

	memset(feo, sizeof(*feo) - sizeof(feo->attr), 0);
	feo->nodeid = fn2fi(fv, cfn);
	stat2attr(st, feo);

	return send_fuse_data(fv, sizeof(*feo) + size, errno);
}

static int
nully_create(struct fvfs *fv, char *path)
{
	struct fnode *fn = argnode(fv); 
	struct fuse_create_in *fci = fuse_req_body(fv);
	char *name = (char *)(fci + 1);
	struct fuse_open_out *foo =
	  (struct fuse_open_out *)((struct fuse_entry_out *)fuse_ans_body(fv) + 1);
	struct stat st;
	int fd, rv;

	rv = pathappend(path, name);
	if (rv)
		return send_fuse_err(fv, rv);

	fd = open(path, fci->flags | O_CREAT|O_EXCL, fci->mode);
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
	struct fuse_mkdir_in  *fmi = fuse_req_body(fv);
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
		fops(fv)->remove(fn, cfn);

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
	struct fnode *cfn, *tfn;
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
	cfn = fops(fv)->lookup(tfn, tname);
	if (!cfn) {
		cfn = make_fnode_nully(fv, tfn, tname);
		if (!cfn)
			return send_fuse_err(fv, errno);
		fops(fv)->insert_dirty(tfn, cfn);

		DIAG(fv, " #%llu/%s => #%llu !\n", fn2fi(fv, tfn), tname,
		     fn2fi(fv, cfn));
	}
	cfn = fops(fv)->lookup(fn, fname);
	if (cfn) {
		fops(fv)->remove(fn, cfn);

		DIAG(fv, " #%llu/%s => #%llu X\n", fn2fi(fv, fn), fname,
		     fn2fi(fv, cfn));
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
	ssize_t bytes;

	errno = 0;

	bytes = pread(fri->fh, fuse_ans_body(fv), fri->size, fri->offset);

	return send_fuse_data(fv, bytes == -1 ? 0 : bytes, errno);
}

static int
nully_write(struct fvfs *fv)
{
	struct fuse_write_in  *fwi = fuse_req_body(fv);
	struct fuse_write_out *fwo = fuse_ans_body(fv);

	errno = 0;

	fwo->size = pwrite(fwi->fh, fwi + 1, fwi->size, fwi->offset);

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

	/*
	 * For the sake of simplicity we don't make use of
	 * the filehandle here (the avaliability of which
	 * is flagged via FATTR_FH).
	 */

	if (fsi->valid & FATTR_MODE)
		rv = chmod(path, fsi->mode);
	if (rv != -1 && fsi->valid & (FATTR_UID|FATTR_GID))
		rv = chown(path,
		           fsi->valid & FATTR_UID ? fsi->uid : -1,
		           fsi->valid & FATTR_GID ? fsi->gid : -1);
	if (rv != -1 && fsi->valid & FATTR_SIZE)
		rv = truncate(path, fsi->size);
	if (rv != -1 &&
	    (fsi->valid & (FATTR_ATIME|FATTR_MTIME)) == (FATTR_ATIME|FATTR_MTIME)) {
		struct timeval tv[2];

		tv[0].tv_sec  = fsi->atime;
		tv[0].tv_usec = fsi->atimensec;
		tv[1].tv_sec  = fsi->mtime;
		tv[1].tv_usec = fsi->mtimensec;
		rv = utimes(path, tv);
	}

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

#ifdef linux
static int
nully_getxattr_generic(struct fvfs *fv, char *path,
                       ssize_t (getxattrlike)(const char *path, const char *name,
                                              void *buf, size_t size))
{
	struct fuse_getxattr_in *fgxi = fuse_req_body(fv);
	char *name = (char *)(fgxi + 1);
	struct fuse_getxattr_out *fgxo = fuse_ans_body(fv);
	ssize_t size;

	if (sizeof(struct fuse_out_header) + fgxi->size > fv->parm.outbufsize)
		return send_fuse_err(fv, E2BIG);

	size = getxattrlike(path, name, size ? fuse_ans_body(fv) : NULL, fgxi->size);
	if (size == -1)
		return send_fuse_err(fv, errno);
	if (fgxi->size)
		return send_fuse_data(fv, size, size > fgxi->size ? ERANGE : 0);
	fgxo->size = size;
	return send_fuse_obj(fv, fgxo, 0);
}

static ssize_t
llistxattr_wrap(const char *path, const char *name, void *buf, size_t size)
{
	return llistxattr(path, buf, size);
}

static int
nully_listxattr(struct fvfs *fv, char *path)
{
	return nully_getxattr_generic(fv, path, llistxattr_wrap);
}


static int
nully_getxattr(struct fvfs *fv, char *path)
{
	return nully_getxattr_generic(fv, path, lgetxattr);
}

static int
nully_removexattr(struct fvfs *fv, char *path)
{
	char *name = fuse_req_body(fv);

	errno = 0;

	lremovexattr(path, name);

	return send_fuse_err(fv, errno);
}

static int
nully_setxattr(struct fvfs *fv, char *path)
{
	struct fuse_setxattr_in *fsi = fuse_req_body(fv);
	char *name = (char *)(fsi + 1);
	char *value = name + strlen (name) + 1;

	errno = 0;

	lsetxattr(path, name, value, fsi->size, fsi->flags);

	return send_fuse_err(fv, errno);
}
#endif

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
#ifdef linux
	{ FUSE_LISTXATTR,   nully_listxattr },
	{ FUSE_GETXATTR,    nully_getxattr },
	{ FUSE_SETXATTR,    nully_setxattr },
	{ FUSE_REMOVEXATTR, nully_removexattr },
#endif
	{0,                 0              }
};

static struct handler_spec nully_opmap[] = {
	{ FUSE_READDIR,     nully_readdir    },
	{ FUSE_READDIRPLUS, nully_readdirplus},
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
		err(1, "can't enter null root");

	/* assemble the optables */
	add_opmap(nully_opmap, fvp.optable);
	add_opmap_generic(nhp, nully_path_optable);
	for (nhp = nully_path_opmap; nhp->opcode; nhp++)
		fvp.optable[nhp->opcode] = nully_path_dispatch;

	/* set other params */
	vdat.compare = nully_node_cmp;
	vdat.key = nully_node_key;
	fnodeops_name = getenv("FOLLY_FNODEOPS");
	if (fnodeops_name) {
		if (strcmp(fnodeops_name, "list") == 0)
			fvp.fops = &list_fnode_ops;
		else if (strcmp(fnodeops_name, "rb") == 0)
			fvp.fops = &rb_fnode_ops;
		else if (strcmp(fnodeops_name, "hash") == 0) {
			fvp.fops = &hash_fnode_ops;
			vdat.hash_table_size = 14507;
			vdat.hash_table =
			  calloc(1, vdat.hash_table_size * sizeof(struct fnode));
			if (!vdat.hash_table)
				err(1, "can't allocate hash table");
			vdat.hash = nully_node_hash;
		} else
			errx(1, "unknown fnodeops \"%s\"", fnodeops_name);
	}

	fvp.vfs_treedata = &vdat;
	fvp.fuse_fd = acquire_fuse_fd();
	fvp.finit_out.flags |= FUSE_DO_READDIRPLUS;

	/* go! */
	folly_loop(&fvp);

	return 0;
}
