/*
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation, version 2 of the
 *  License.
 */

#include <linux/export.h>
#include <linux/nsproxy.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>
#include <linux/proc_fs.h>
#include <linux/highuid.h>
#include <linux/cred.h>
#include <linux/proc_fs.h>

static struct kmem_cache *user_ns_cachep __read_mostly;

static bool new_idmap_permitted(struct user_namespace *ns, int cap_setid,
				struct uid_gid_map *map);

static void set_cred_user_ns(struct cred *cred, struct user_namespace *user_ns)
{
	/* Start with the same capabilities as init but useless for doing
	 * anything as the capabilities are bound to the new user namespace.
	 */
	cred->securebits = SECUREBITS_DEFAULT;
	cred->cap_inheritable = CAP_EMPTY_SET;
	cred->cap_permitted = CAP_FULL_SET;
	cred->cap_effective = CAP_FULL_SET;
	cred->cap_bset = CAP_FULL_SET;
#ifdef CONFIG_KEYS
	key_put(cred->request_key_auth);
	cred->request_key_auth = NULL;
#endif
	/* tgcred will be cleared in our caller bc CLONE_THREAD won't be set */
	cred->user_ns = user_ns;
}

/*
 * Create a new user namespace, deriving the creator from the user in the
 * passed credentials, and replacing that user with the new root user for the
 * new namespace.
 *
 * This is called by copy_creds(), which will finish setting the target task's
 * credentials.
 */
int create_user_ns(struct cred *new)
{
	struct user_namespace *ns, *parent_ns = new->user_ns;
	struct user_struct *root_user;
	int n;
	int ret;
	kuid_t owner = make_kuid(new->user_ns, new->euid);
	kgid_t group = make_kgid(new->user_ns, new->egid);

	/* The creator needs a mapping in the parent user namespace
	 * or else we won't be able to reasonably tell userspace who
	 * created a user_namespace.
	 */
	if (!kuid_has_mapping(parent_ns, owner) ||
	    !kgid_has_mapping(parent_ns, group))
		return -EPERM;

	ns = kmem_cache_alloc(user_ns_cachep, GFP_KERNEL);
	if (!ns)
		return -ENOMEM;

	ret = proc_alloc_inum(&ns->proc_inum);
	if (ret) {
		kmem_cache_free(user_ns_cachep, ns);
		return ret;
	}

	kref_init(&ns->kref);
	/* Leave the new->user_ns reference with the new user namespace. */
	ns->parent = parent_ns;
	ns->owner = owner;
	ns->group = group;

	set_cred_user_ns(new, ns);

	return 0;
}

void free_user_ns(struct kref *kref)
{
	struct user_namespace *parent, *ns =
		container_of(kref, struct user_namespace, kref);

	parent = ns->parent;
	proc_free_inum(ns->proc_inum);
	put_user_ns(parent);
}
EXPORT_SYMBOL(free_user_ns);

uid_t user_ns_map_uid(struct user_namespace *to, const struct cred *cred, uid_t uid)
{
	struct user_namespace *tmp;

	if (likely(to == cred->user_ns))
		return uid;

	/* Is cred->user the creator of the target user_ns
	 * or the creator of one of it's parents?
	 */
	for ( tmp = to; tmp != &init_user_ns; tmp = tmp->parent ) {
		if (uid_eq(cred->user->uid, tmp->owner)) {
			return (uid_t)0;
		}
	}

	/* No useful relationship so no mapping */
	return overflowuid;
}

gid_t user_ns_map_gid(struct user_namespace *to, const struct cred *cred, gid_t gid)
{
	struct user_namespace *tmp;

	if (likely(to == cred->user_ns))
		return gid;

	/* Is cred->user the creator of the target user_ns
	 * or the creator of one of it's parents?
	 */
	for ( tmp = to; tmp != &init_user_ns; tmp = tmp->parent ) {
		if (uid_eq(cred->user->uid, tmp->owner)) {
			return (gid_t)0;
		}
	}

	/* No useful relationship so no mapping */
	return overflowgid;
}

static void *userns_get(struct task_struct *task)
{
	struct user_namespace *user_ns;

	rcu_read_lock();
	user_ns = get_user_ns(__task_cred(task)->user_ns);
	rcu_read_unlock();

	return user_ns;
}

static void userns_put(void *ns)
{
	put_user_ns(ns);
}

static int userns_install(struct nsproxy *nsproxy, void *ns)
{
	struct user_namespace *user_ns = ns;
	struct cred *cred;

	/* Don't allow gaining capabilities by reentering
	 * the same user namespace.
	 */
	if (user_ns == current_user_ns())
		return -EINVAL;

	/* Threaded many not enter a different user namespace */
	if (atomic_read(&current->mm->mm_users) > 1)
		return -EINVAL;

	if (!ns_capable(user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	cred = prepare_creds();
	if (!cred)
		return -ENOMEM;

	put_user_ns(cred->user_ns);
	set_cred_user_ns(cred, get_user_ns(user_ns));

	return commit_creds(cred);
}

const struct proc_ns_operations userns_operations = {
	.name		= "user",
	.type		= CLONE_NEWUSER,
	.get		= userns_get,
	.put		= userns_put,
	.install	= userns_install,
};

static __init int user_namespaces_init(void)
{
	user_ns_cachep = KMEM_CACHE(user_namespace, SLAB_PANIC);
	return 0;
}
module_init(user_namespaces_init);
