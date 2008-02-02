#ifndef FOLLY_H
#define FOLLY_H 1

#include <stdint.h>

#include "fuse_kernel.h"
#include "fuse_opnames.h"

#define FOLLY_MAJOR 0
#define FOLLY_MINOR 1

#define FOLLYMARKER 0xf0111101

typedef uint64_t f_ino_t;

struct fnode {
	uint64_t nlookup;
	void *treedata;
	void *priv;
#ifdef MARK_FOLLY
	uint32_t mark;
#endif
};

struct fvfs;

static inline struct fnode *fi2fn(struct fvfs *fv, f_ino_t nid);
static inline f_ino_t fn2fi(struct fvfs *fv, struct fnode *fnode);
typedef int (folly_handler_t)(struct fvfs *fv);

struct handler_spec {
	enum fuse_opcode opcode;
	folly_handler_t *handler;
};

struct fnode_ops {
	struct fnode     *(*insert)(struct fnode *fn, struct fnode *cfn);
	void        (*insert_dirty)(struct fnode *fn, struct fnode *cfn);
	void              (*remove)(struct fnode *fn, struct fnode *cfn);
	struct fnode *    (*lookup)(struct fnode *fn, void *p);
	void                (*init)(struct fvfs *fv,  struct fnode *fn);
	int                   (*gc)(struct fvfs *fv,  struct fnode *fn);
	struct fnode *(*next_child)(struct fnode *fn, struct fnode *cfn);
	int         (*has_children)(struct fnode *fn);
	int            (*connected)(struct fnode *fn);
	size_t treedata_size;
};

struct fvfs_param {
	folly_handler_t *optable[FUSE_OPTABLE_SIZE];
	size_t inbufsize;
	size_t outbufsize;
	struct fuse_init_out finit_out;
	struct fnode_ops *fops;
	int fuse_fd;
	void *root_fnode_priv;
	void *vfs_treedata;
	void *vfs_priv;
	uint8_t diag:1;
};

void init_fvfs_param(struct fvfs_param *fvp);

struct fvfs {
	struct fvfs_param parm;
	char *inbuf;
	char *outbuf;
	struct fnode *root_fnode;
};

static inline struct fnode_ops *
fops(struct fvfs *fv) { return fv->parm.fops; }

static inline struct fuse_in_header *
finh(struct fvfs *fv) { return (struct fuse_in_header *)fv->inbuf; }

static inline struct fuse_out_header *
fouh(struct fvfs *fv) { return (struct fuse_out_header *)fv->outbuf; }

static inline void *
fuse_req_body(struct fvfs *fv)
{
	return (void *)(fv->inbuf + sizeof(struct fuse_in_header));
}

static inline void *
fuse_ans_body(struct fvfs *fv)
{
	return (void *)(fv->outbuf + sizeof(struct fuse_out_header));
}

int acquire_fuse_fd(void);

int folly_loop(struct fvfs_param *fvp);

int send_fuse_err(struct fvfs *fv, int errn);
int send_fuse_data(struct fvfs *fv, size_t len, int errn);
#define send_fuse_obj(fv, ans_struct, errn)		\
	send_fuse_data(fv, sizeof(*(ans_struct)), errn)

struct fnode *make_fnode(struct fvfs *fv, size_t privsize);
struct fnode *insert_lookup_fnode(struct fvfs *fv, struct fnode *fn,
                                  struct fnode *cfn);

struct iterables_vfs_treedata {
	int   (*compare)(struct fnode *fn, void *p);
	void *(*key)(struct fnode *fn);
};

struct hash_vfs_treedata {
	int      (*compare)(struct fnode *fn, void *p);
	void *   (*key)(struct fnode *fn);
	unsigned (*hash)(void *p);
	struct fnode **hash_table;
	unsigned hash_table_size;
};

extern struct fnode_ops list_fnode_ops;
extern struct fnode_ops rb_fnode_ops;
extern struct fnode_ops hash_fnode_ops;

folly_handler_t folly_default_handler;
folly_handler_t folly_init;
folly_handler_t folly_forget;

static inline struct fnode *
fi2fn(struct fvfs *fv, f_ino_t nid)
{
	struct fnode *fn;

	fn = (struct fnode *)
          ((uintptr_t)(nid - FUSE_ROOT_ID) + (uintptr_t)fv->root_fnode);

#ifdef MARK_FOLLY
	assert(fn->mark == FOLLYMARKER);
#endif

	return fn;
}

static inline f_ino_t
fn2fi(struct fvfs *fv, struct fnode *fn)
{
	return (f_ino_t)
          ((uintptr_t)(fn) - (uintptr_t)fv->root_fnode + FUSE_ROOT_ID);
}

static inline struct fnode *
argnode(struct fvfs *fv)
{
	return fi2fn(fv, finh(fv)->nodeid);
}

static inline void
free_fnode(struct fnode *fn)
{
#ifdef MARK_FOLLY
	assert(fn->mark == FOLLYMARKER);
	fn->mark = 0;
#endif
	free(fn);
}

void make_default_optable(folly_handler_t **optable);

#define add_opmap_generic(hspec, optable)			\
{								\
	for(; (hspec)->opcode; (hspec)++)			\
		optable[(hspec)->opcode] = (hspec)->handler;	\
}

static inline void
add_opmap(struct handler_spec *hp, folly_handler_t **optable)
{
	add_opmap_generic(hp, optable);
}

#ifdef _DIAG
#define DIAG(fv, args, ...)			\
	if (fv->parm.diag)			\
		printf(args, ## __VA_ARGS__)
#else
#define DIAG(args ...)
#endif

#endif /* !FOLLY_H */
