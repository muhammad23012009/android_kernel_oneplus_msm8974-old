#ifndef _COMPAT_LINUX_FS_H
#define _COMPAT_LINUX_FS_H
#include_next <linux/fs.h>
#include <linux/version.h>
/*
 * some versions don't have this and thus don't
 * include it from the original fs.h
 */
#include <linux/uidgid.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0))
#define simple_open LINUX_BACKPORT(simple_open)
extern int simple_open(struct inode *inode, struct file *file);
#endif

#ifndef replace_fops
/*
 * This one is to be used *ONLY* from ->open() instances.
 * fops must be non-NULL, pinned down *and* module dependencies
 * should be sufficient to pin the caller down as well.
 */
#define replace_fops(f, fops) \
	do {	\
		struct file *__file = (f); \
		fops_put(__file->f_op); \
		BUG_ON(!(__file->f_op = (fops))); \
	} while(0)
#endif /* replace_fops */

#endif	/* _COMPAT_LINUX_FS_H */
