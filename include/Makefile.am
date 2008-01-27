follyincludedir=$(includedir)/folly

follyinclude_HEADERS =	\
	folly.h		\
	fuse_kernel.h	\
	fuse_opnames.h

fuse_opnames.h: fuse_kernel.h
	env OUTF=fuse_opnames.h awk -f ../tools/genopnames.awk fuse_kernel.h

fuse_kernel.h:
	@echo "****************************************************************************************"
	@echo "*"
	@echo "* fuse_kernel.h is to be manually copied here from the FUSE project (http://fuse.sf.net)"
	@echo "* see eg. http://fuse.cvs.sourceforge.net/*checkout*/fuse/fuse/kernel/fuse_kernel.h"
	@echo "*"
	@echo "****************************************************************************************"
	@exit 1

CLEANFILES= fuse_opnames.h
