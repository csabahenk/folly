#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>

#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#else
#include "queue.h"
#endif
#include "tree_xd.h"
#include "folly.h"

struct iterables_treedata {
	struct fnode *par_fnode;
};

static int
fnode_iterables_gc(struct fvfs *fv, struct fnode *fn)
{
	struct fnode *cfn = NULL;

	while ((cfn = fops(fv)->next_child(fn, NULL)))
		 fops(fv)->remove(fn, cfn);

	if (fops(fv)->connected(fn))
		fops(fv)->remove(
		  ((struct iterables_treedata *)fn->treedata)->par_fnode,
		  fn);

	free_fnode(fn);
	if (fn == fv->root_fnode)
		fv->root_fnode = NULL;

	return 0;
}

struct list_treedata {
	struct iterables_treedata itd;
	struct fvfs *fvfs;
	struct fnode *fnode;
	LIST_HEAD(folly_child_list, list_treedata) children;
	LIST_ENTRY(list_treedata) siblings;
};

static void
list_init(struct fvfs *fv, struct fnode *fn)
{
	struct list_treedata *ltd = fn->treedata;

	ltd->fvfs = fv;
	ltd->fnode = fn;
	LIST_INIT(&ltd->children);
	ltd->itd.par_fnode = NULL;
}

static void
list_insert_dirty(struct fnode *fn, struct fnode *cfn)
{
	struct list_treedata *ltd = fn->treedata;
	struct list_treedata *cltd = cfn->treedata;

	assert(!cltd->itd.par_fnode);
	LIST_INSERT_HEAD(&ltd->children, cltd, siblings);
	cltd->itd.par_fnode = fn;
}

static struct fnode *list_lookup(struct fnode *fn, void *p);

static struct fnode * 
list_insert(struct fnode *fn, struct fnode *cfn)
{
	struct list_treedata *ltd = fn->treedata;
	struct iterables_vfs_treedata *vfstd = ltd->fvfs->parm.vfs_treedata;
	struct fnode *xfn;

	xfn = list_lookup(fn, vfstd->key(cfn));
	if (xfn)
		return xfn;

	list_insert_dirty(fn, cfn);
	return NULL; 
}

static void
list_remove(struct fnode *fn, struct fnode *cfn)
{
	struct list_treedata *cltd = cfn->treedata;

	assert(fn && cltd->itd.par_fnode == fn);
	LIST_REMOVE(cltd, siblings);
	cltd->itd.par_fnode = NULL;
}

static struct fnode *
list_next_child(struct fnode *fn, struct fnode *cfn)
{
	struct list_treedata *cltd, *ltd = fn->treedata;

	if (!cfn)
		cltd = LIST_FIRST(&ltd->children);
	else {
		cltd = cfn->treedata;
		cltd = LIST_NEXT(cltd, siblings);
	}

	return cltd ? cltd->fnode: NULL;
}

static struct fnode *
list_lookup(struct fnode *fn, void *p)
{
	struct list_treedata *xltd, *ltd = fn->treedata;

	LIST_FOREACH(xltd, &ltd->children, siblings) {
		if (!((struct iterables_vfs_treedata *)
		      (ltd->fvfs->parm.vfs_treedata))
		       ->compare(xltd->fnode, p))
			break;
	}

	return xltd ? xltd->fnode : NULL;
}

static int
list_has_children(struct fnode *fn)
{
	struct list_treedata *ltd = fn->treedata;

	return !LIST_EMPTY(&ltd->children);
}

static int
list_connected(struct fnode *fn)
{
	struct list_treedata *ltd = fn->treedata;

	return ltd->itd.par_fnode ? 1 : 0;
}

struct fnode_ops list_fnode_ops = {
	.insert		= list_insert,
	.insert_dirty	= list_insert_dirty,
	.remove		= list_remove,
	.lookup		= list_lookup,
	.init		= list_init,
	.gc		= fnode_iterables_gc,
	.next_child	= list_next_child,
	.has_children	= list_has_children,
	.connected	= list_connected,
	.treedata_size	= sizeof(struct list_treedata)
};

struct rb_treedata {
	struct iterables_treedata itd; 
	struct fvfs *fvfs;
	struct fnode *fnode;
	RB_HEAD(folly_rb_tree, rb_treedata) children;
	RB_ENTRY(rb_treedata) rb_linkage;
};

static int
rb_cmp(void *p, struct rb_treedata *rtd)
{
	struct iterables_vfs_treedata *vfstd = rtd->fvfs->parm.vfs_treedata;

	return vfstd->compare(rtd->fnode, p);
}

static void *
rb_key(struct rb_treedata *rtd)
{
	struct iterables_vfs_treedata *vfstd = rtd->fvfs->parm.vfs_treedata;

	return vfstd->key(rtd->fnode);
}

RB_GENERATE_STATIC(folly_rb_tree, rb_treedata, rb_linkage, rb_cmp, rb_key)

static void
rb_init(struct fvfs *fv, struct fnode *fn)
{
	struct rb_treedata *rtd = fn->treedata;

	rtd->fvfs = fv;
	rtd->fnode = fn;
	RB_INIT(&rtd->children);
	rtd->itd.par_fnode = NULL;
}

static struct fnode *
rb_insert(struct fnode *fn, struct fnode *cfn)
{
	struct rb_treedata *rtd = fn->treedata;
	struct rb_treedata *crtd = cfn->treedata;
	struct rb_treedata *xrtd;

	assert(!crtd->itd.par_fnode);
	xrtd = RB_INSERT(folly_rb_tree, &rtd->children, crtd);
	if (xrtd)
		return xrtd->fnode;

	crtd->itd.par_fnode = fn;

	return NULL;
}

static void
rb_insert_dirty(struct fnode *fn, struct fnode *cfn)
{
	rb_insert(fn, cfn);
}

static void 
rb_remove(struct fnode *fn, struct fnode *cfn)
{
	struct rb_treedata *rtd = fn->treedata;
	struct rb_treedata *crtd = cfn->treedata;

	assert(crtd->itd.par_fnode == fn);
	RB_REMOVE(folly_rb_tree, &rtd->children, crtd);
	crtd->itd.par_fnode = NULL;
}

static struct fnode *
rb_next_child(struct fnode *fn, struct fnode *cfn)
{
	struct rb_treedata *crtd, *rtd = fn->treedata;

	if (!cfn)
		crtd = RB_MIN(folly_rb_tree, &rtd->children);
	else {
		crtd = cfn->treedata;
		crtd = RB_NEXT(folly_rb_tree, &rtd->children, crtd);
	}

	return crtd ? crtd->fnode : NULL;
}

static struct fnode *
rb_lookup(struct fnode *fn, void *p)
{
	struct rb_treedata *rtd = fn->treedata;
	struct rb_treedata *res_rtd;

	res_rtd = RB_FIND(folly_rb_tree, &rtd->children, p);

	return res_rtd ? res_rtd->fnode : NULL;
}

static int
rb_has_children(struct fnode *fn)
{
	struct rb_treedata *rtd = fn->treedata;

	return !RB_EMPTY(&rtd->children);
}

static int
rb_connected(struct fnode *fn)
{
	struct rb_treedata *rtd = fn->treedata;

	return rtd->itd.par_fnode ? 1 : 0;
}

struct fnode_ops rb_fnode_ops = {
	.insert		= rb_insert,
	.insert_dirty	= rb_insert_dirty,
	.remove		= rb_remove,
	.lookup		= rb_lookup,
	.init		= rb_init,
	.gc		= fnode_iterables_gc,
	.next_child	= rb_next_child,
	.has_children	= rb_has_children,
	.connected	= rb_connected,
	.treedata_size	= sizeof(struct rb_treedata)
};

struct hash_treedata {
	struct fvfs *fvfs;
	struct fnode *next_fnode;
	struct fnode *par_fnode;
	int childcnt;
};

static unsigned
hash_hash_key(struct fnode *fn, void *ckey)
{
	struct hash_treedata *htd = fn->treedata;
	struct hash_vfs_treedata *vfstd = htd->fvfs->parm.vfs_treedata;

	return (fn2fi(htd->fvfs, fn) + vfstd->hash(ckey)) %
	         vfstd->hash_table_size;
}

static inline unsigned
hash_hash(struct fnode *fn, struct fnode *cfn)
{
	struct hash_treedata *chtd = cfn->treedata;
	struct hash_vfs_treedata *vfstd = chtd->fvfs->parm.vfs_treedata;

	return hash_hash_key(fn, vfstd->key(cfn));
}

static void
hash_init(struct fvfs *fv, struct fnode *fn)
{
	struct hash_treedata *htd = fn->treedata;

	htd->fvfs = fv;
	htd->next_fnode = NULL;
	htd->par_fnode = NULL;
	htd->childcnt = 0;
}

static inline void
hash_insert_dirty_hash(struct fnode *fn, struct fnode *cfn, unsigned hash)
{
	struct hash_treedata *htd = fn->treedata;
	struct hash_treedata *chtd = cfn->treedata;
	struct hash_vfs_treedata *vfstd = htd->fvfs->parm.vfs_treedata;

	assert(!chtd->par_fnode && !chtd->next_fnode);
	chtd->next_fnode = vfstd->hash_table[hash];
	vfstd->hash_table[hash] = cfn;
	chtd->par_fnode = fn;
	htd->childcnt++;
}

static inline struct fnode *
hash_lookup_hash(struct fnode *fn, void *ckey, unsigned hash)
{
	struct hash_treedata *htd = fn->treedata;
	struct hash_vfs_treedata *vfstd = htd->fvfs->parm.vfs_treedata;
	struct fnode *xfn = vfstd->hash_table[hash];
	struct hash_treedata *xhtd;

	for (; xfn;) {
		xhtd = xfn->treedata;

		if (fn == xhtd->par_fnode && vfstd->compare(xfn, ckey) == 0)
			return xfn;

		xfn = xhtd->next_fnode;
	}

	return NULL;
}

static void
hash_insert_dirty(struct fnode *fn, struct fnode *cfn)
{
	hash_insert_dirty_hash(fn, cfn, hash_hash(fn, cfn));
}

static struct fnode *
hash_insert(struct fnode *fn, struct fnode *cfn)
{
	struct hash_treedata *htd = fn->treedata;
	struct hash_vfs_treedata *vfstd = htd->fvfs->parm.vfs_treedata;
	struct fnode *xfn;
	unsigned hash = hash_hash(fn, cfn);

	xfn = hash_lookup_hash(fn, vfstd->key(cfn), hash);
	if (!xfn)
		hash_insert_dirty_hash(fn, cfn, hash);

	return xfn;
}

static struct fnode *
hash_lookup(struct fnode *fn, void *ckey)
{
	return hash_lookup_hash(fn, ckey, hash_hash_key(fn, ckey));
}

static void
hash_remove(struct fnode *fn, struct fnode *cfn)
{
	struct hash_treedata *htd = fn->treedata;
	struct hash_treedata *chtd = cfn->treedata;
	struct hash_vfs_treedata *vfstd = htd->fvfs->parm.vfs_treedata;
	struct fnode **xfnp = &vfstd->hash_table[hash_hash(fn, cfn)];

	assert(chtd->par_fnode);
	for (;;) {
		if (*xfnp == cfn) {
			*xfnp = chtd->next_fnode;
			chtd->next_fnode = NULL;
			assert(chtd->par_fnode == fn);
			chtd->par_fnode = NULL;
			assert(htd->childcnt > 0);
			htd->childcnt--;

			return;
		}

		xfnp = &((struct hash_treedata *)(*xfnp)->treedata)->next_fnode;
		assert(*xfnp);
	}
}

static int
hash_has_children(struct fnode *fn)
{
	struct hash_treedata *htd = fn->treedata;

	return htd->childcnt ? 1 : 0;
}

static int
hash_connected(struct fnode *fn)
{
	struct hash_treedata *htd = fn->treedata;

	return htd->par_fnode ? 1 : 0;
}

static int
hash_gc(struct fvfs *fv, struct fnode *fn)
{
	struct hash_treedata *htd = fn->treedata;

	if (fops(fv)->connected(fn)) {
		struct fnode *pfn = htd->par_fnode;

		fops(fv)->remove(pfn, fn);
		if (pfn->nlookup == 0)
			/*
			 * no deep recursion here, b/c when pfn's nlookup
			 * has dropped to zero, it was already gc'd thus
			 * removed
			 */
			hash_gc(fv, pfn);
	}

	if (htd->childcnt > 0)
		return 1;

	free_fnode(fn);
	if (fn == fv->root_fnode)
		fv->root_fnode = NULL;

	return 0;
}

struct fnode_ops hash_fnode_ops = {
	.insert		= hash_insert,
	.insert_dirty	= hash_insert_dirty,
	.remove		= hash_remove,
	.lookup		= hash_lookup,
	.init		= hash_init,
	.gc		= hash_gc,
	.next_child	= NULL,
	.has_children	= hash_has_children,
	.connected	= hash_connected,
	.treedata_size	= sizeof(struct hash_treedata)
};
