#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/string.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <asm/errno.h>
#include <asm/unaligned.h>
#include <linux/jhash.h>
#include <linux/spinlock.h>
#include <linux/proc_fs.h>

#include "xt_tlslist.h"

#define TLSLIST_MODULE_VERSION "0.2"
#define BUFSIZE 4000

static unsigned int hashsize __read_mostly = 10000;
static struct proc_dir_entry *procentry;

static DEFINE_MUTEX(tlslist_mutex); /* htable lists management */

struct domains_match {
	char *domain;
#ifdef XT_TLSLIST_STAT
	unsigned int counter;
#endif
	struct hlist_node node;
};

struct tlslist_htable {
	spinlock_t lock;		/* write access to hash */
	unsigned int size;		/* hash array size, set from hashsize */
	unsigned int ent_count;		/* currently entities */
	struct hlist_head hash[0];	/* rcu lists array[size] of domain_match'es */
};

struct tlslist_htable *htable;

static inline u_int32_t hash_addr(const struct tlslist_htable *ht, const char *string)
{
    return reciprocal_scale(jhash(string, strlen(string), 0), ht->size);
}

static int htable_create(struct tlslist_htable **htable)
	/* rule insertion chain, under tlslist_mutex */
{
	struct tlslist_htable *ht;
        unsigned int hsize = hashsize; /* (entities) */
	unsigned int sz; /* (bytes) */
	int i;

	if (hsize > 1000000)
		hsize = 8192;

	sz = sizeof(struct tlslist_htable) + sizeof(struct hlist_head) * hsize;
	if (sz <= PAGE_SIZE)
		ht = kzalloc(sz, GFP_KERNEL);
	else
		ht = vzalloc(sz);
	if (ht == NULL)
		return -ENOMEM;

	for (i = 0; i < hsize; i++)
		INIT_HLIST_HEAD(&ht->hash[i]);

	ht->size = hsize;
	ht->ent_count = 0;
	spin_lock_init(&ht->lock);
	*htable = ht;
	return 0;
}

static void htable_add(struct tlslist_htable *ht, const char *domain)
{
        const u_int32_t hash = hash_addr(ht, domain);
	struct domains_match *dm = kzalloc(sizeof(struct domains_match), GFP_KERNEL);
	char *str = kmalloc(strlen(domain) + 1, GFP_KERNEL);
	strcpy(str, domain);
        dm->domain = str;
        hlist_add_head_rcu(&dm->node, &ht->hash[hash]);
	ht->ent_count++;
}

static struct domains_match* htable_get(struct tlslist_htable *ht, const char *domain)
{
        const u_int32_t hash = hash_addr(ht, domain);
	struct domains_match *dm;
        hlist_for_each_entry_rcu(dm, &ht->hash[hash], node) {
                if (strcmp(domain, dm->domain) == 0)
                        return dm;
        }
        return NULL;
}

static void htable_del(struct tlslist_htable *ht, const char *domain)
{
        const u_int32_t hash = hash_addr(ht, domain);
	struct domains_match *dm;
        hlist_for_each_entry_rcu(dm, &ht->hash[hash], node) {
                if (strcmp(domain, dm->domain) == 0) {
                        hlist_del_rcu(&dm->node);
                        kfree(dm->domain);
                        kfree(dm);
                        ht->ent_count--;
                }
        }
}

static void htable_cleanup(struct tlslist_htable *ht)
	/* under tlslist_mutex */
{
	unsigned int i;

	for (i = 0; i < ht->size; i++) {
		struct domains_match *dm;

		spin_lock(&ht->lock);
		hlist_for_each_entry_rcu(dm, &ht->hash[i], node) {
			hlist_del_rcu(&dm->node);
			kfree(dm->domain);
			kfree(dm);
                        ht->ent_count--;
		}
		spin_unlock(&ht->lock);
		cond_resched();
	}
}

static void htable_flush(struct tlslist_htable *ht)
{
	mutex_lock(&tlslist_mutex);
	htable_cleanup(ht);
	mutex_unlock(&tlslist_mutex);
}

static void htable_destroy(struct tlslist_htable *htable)
	/* caller htable_put, iptables rule deletion chain */
{
	htable_flush(htable);
	BUG_ON(htable->ent_count != 0);
	kvfree(htable);
}

/*
 * Searches through skb->data and looks for a
 * client or server handshake. A client
 * handshake is preferred as the SNI
 * field tells us what domain the client
 * wants to connect to.
 */
static int get_tls_hostname(const struct sk_buff *skb, char **dest)
{
	struct tcphdr *tcp_header;
	u_int8_t *data, *firstbyte;
	size_t data_len;
	u_int16_t tls_header_len;
	u_int8_t handshake_protocol;

	tcp_header = (struct tcphdr *)skb_transport_header(skb);
	// I'm not completely sure how this works (courtesy of StackOverflow), but it works
	data = (u_int8_t *)((unsigned char *)tcp_header + (tcp_header->doff * 4));
	// Calculate packet data length
	data_len = (uintptr_t)skb_tail_pointer(skb)- (uintptr_t)data;
	// Abort on zero data length
	if (data_len + skb->data_len == 0)
		return EPROTO;

	firstbyte = skb_header_pointer(skb, skb_transport_offset(skb) + (tcp_header->doff * 4), 1, &handshake_protocol);
	if (!firstbyte)
		return EPROTO;
	// If this isn't an TLS handshake, abort
	if (*firstbyte != 0x16)
		return EPROTO;

	if (skb_is_nonlinear(skb)) {
		data_len = skb->len - skb_headlen(skb);
		data = kmalloc(data_len, GFP_ATOMIC);
		if (data == NULL)
			return EPROTO;
		if (skb_copy_bits(skb, skb_headlen(skb), data, data_len))
			goto nomatch;
	}

	tls_header_len = (data[3] << 8) + data[4] + 5;
	handshake_protocol = data[5];

	// Even if we don't have all the data, try matching anyway
	if (tls_header_len > data_len)
		tls_header_len = data_len;

	if (tls_header_len > 4) {
		// Check only client hellos for now
		if (handshake_protocol == 0x01) {
			u_int offset, base_offset = 43, extension_offset = 2;
			u_int16_t session_id_len, cipher_len, compression_len, extensions_len;

			if (base_offset + 2 > data_len) {
#ifdef XT_TLSLIST_DEBUG
				printk("[xt_tlslist] Data length is to small (%d)\n", (int)data_len);
#endif
				goto nomatch;
			}

			// Get the length of the session ID
			session_id_len = data[base_offset];

#ifdef XT_TLSLIST_DEBUG
			printk("[xt_tlslist] Session ID length: %d\n", session_id_len);
#endif
			if ((session_id_len + base_offset + 2) > tls_header_len) {
#ifdef XT_TLSLIST_DEBUG
				printk("[xt_tlslist] TLS header length is smaller than session_id_len + base_offset +2 (%d > %d)\n", (session_id_len + base_offset + 2), tls_header_len);
#endif
				goto nomatch;
			}

			// Get the length of the ciphers
			cipher_len = get_unaligned_be16(data + base_offset + session_id_len + 1);
			offset = base_offset + session_id_len + cipher_len + 2;
#ifdef XT_TLSLIST_DEBUG
			printk("[xt_tlslist] Cipher len: %d\n", cipher_len);
			printk("[xt_tlslist] Offset (1): %d\n", offset);
#endif
			if (offset > tls_header_len) {
#ifdef XT_TLSLIST_DEBUG
				printk("[xt_tlslist] TLS header length is smaller than offset (%d > %d)\n", offset, tls_header_len);
#endif
				goto nomatch;
			}

			// Get the length of the compression types
			compression_len = data[offset + 1];
			offset += compression_len + 2;
#ifdef XT_TLSLIST_DEBUG
			printk("[xt_tlslist] Compression length: %d\n", compression_len);
			printk("[xt_tlslist] Offset (2): %d\n", offset);
#endif
			if (offset > tls_header_len) {
#ifdef XT_TLSLIST_DEBUG
				printk("[xt_tlslist] TLS header length is smaller than offset w/compression (%d > %d)\n", offset, tls_header_len);
#endif
				goto nomatch;
			}

			// Get the length of all the extensions
			extensions_len = get_unaligned_be16(data + offset);
#ifdef XT_TLSLIST_DEBUG
			printk("[xt_tlslist] Extensions length: %d\n", extensions_len);
#endif

			if ((extensions_len + offset) > tls_header_len) {
#ifdef XT_TLSLIST_DEBUG
				printk("[xt_tlslist] TLS header length is smaller than offset w/extensions (%d > %d)\n", (extensions_len + offset), tls_header_len);
#endif
				goto nomatch;
			}

			// Loop through all the extensions to find the SNI extension
			while (extension_offset < extensions_len)
			{
				u_int16_t extension_id, extension_len;

				extension_id = get_unaligned_be16(data + offset + extension_offset);
				extension_offset += 2;

				extension_len = get_unaligned_be16(data + offset + extension_offset);
				extension_offset += 2;

#ifdef XT_TLSLIST_DEBUG
				printk("[xt_tlslist] Extension ID: %d\n", extension_id);
				printk("[xt_tlslist] Extension length: %d\n", extension_len);
#endif

				if (extension_id == 0) {
					u_int16_t name_length, name_type;

					// We don't need the server name list length, so skip that
					extension_offset += 2;
					// We don't really need name_type at the moment
					// as there's only one type in the RFC-spec.
					// However I'm leaving it in here for
					// debugging purposes.
					name_type = data[offset + extension_offset];
					extension_offset += 1;

					name_length = get_unaligned_be16(data + offset + extension_offset);
					extension_offset += 2;

#ifdef XT_TLSLIST_DEBUG
					printk("[xt_tlslist] Name type: %d\n", name_type);
					printk("[xt_tlslist] Name length: %d\n", name_length);
#endif
					// Allocate an extra 2 byte for first dot and the null-terminator
					*dest = kmalloc(name_length + 2, GFP_ATOMIC);
					strncpy(*dest + 1, &data[offset + extension_offset], name_length);
					// Make sure the string is always null-terminated.
					(*dest)[name_length + 1] = 0;
					if (skb_is_nonlinear(skb))
						kfree(data);
					return 0;
				}
				extension_offset += extension_len;
			}
		}
	}
nomatch:
	if (skb_is_nonlinear(skb))
		kfree(data);
	return EPROTO;
}

static bool tls_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	char *parsed_host;
	const struct xt_tlslist_info *info = par->matchinfo;
	struct domains_match *dm;
	int result;
	bool subdomains = (info->flags & XT_TLSLIST_SUBDOMAINS);
	bool match;

	if ((result = get_tls_hostname(skb, &parsed_host)) != 0)
		return false;
	// first char reserved for dot
	dm = htable_get(htable, parsed_host + 1);
	match = (dm != NULL);
#ifdef XT_TLSLIST_STAT
	if (match)
		dm->counter++;
#endif

#ifdef XT_TLSLIST_DEBUG
	printk("[xt_tlslist] Parsed domain: %s\n", parsed_host + 1);
	printk("[xt_tlslist] Domain matches: %s\n", match ? "true" : "false");
#endif
	if (!match && subdomains) {
		char *p = parsed_host;
		parsed_host[0] = '.';
		while (*p) {
			if (*p == '.') {
				dm = htable_get(htable, p);
				match = (dm != NULL);
				if (match) {
#ifdef XT_TLSLIST_STAT
					dm->counter++;
#endif
					break;
				}
			}
			p++;
		}
#ifdef XT_TLSLIST_DEBUG
	printk("[xt_tlslist] Subdomain matches: %s\n", match ? "true" : "false");
#endif
	}

	kfree(parsed_host);

	return match;
}

static int tls_mt_check (const struct xt_mtchk_param *par)
{
	__u16 proto;

	if (par->family == NFPROTO_IPV4) {
		proto = ((const struct ipt_ip *) par->entryinfo)->proto;
	} else if (par->family == NFPROTO_IPV6) {
		proto = ((const struct ip6t_ip6 *) par->entryinfo)->proto;
	} else {
		return -EINVAL;
	}

	if (proto != IPPROTO_TCP) {
		pr_info("Can be used only in combination with "
			"-p tcp\n");
		return -EINVAL;
	}

	return 0;
}

static struct xt_match tls_mt_regs[] __read_mostly = {
	{
		.name       = "tlslist",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.checkentry = tls_mt_check,
		.match      = tls_mt,
		.matchsize  = sizeof(struct xt_tlslist_info),
		.me         = THIS_MODULE,
	},
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
	{
		.name       = "tlslist",
		.revision   = 0,
		.family     = NFPROTO_IPV6,
		.checkentry = tls_mt_check,
		.match      = tls_mt,
		.matchsize  = sizeof(struct xt_tlslist_info),
		.me         = THIS_MODULE,
	},
#endif
};

static char proc_buf[BUFSIZE];

static void *tlslist_seq_start(struct seq_file *s, loff_t *pos)
{
        unsigned int *curpos;

	spin_lock(&htable->lock);
        if (*pos >= htable->size)
                return NULL;

        curpos = kmalloc(sizeof(curpos), GFP_ATOMIC);
        if (!curpos)
                return ERR_PTR(-ENOMEM);

        *curpos = *pos;
        return curpos;
}

static void *tlslist_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
        unsigned int *curpos = (unsigned int *) v;

	*pos = ++(*curpos);
        if (*pos >= htable->size) {
		kfree(v);
                return NULL;
	}
        return curpos;
}

static void tlslist_seq_stop(struct seq_file *s, void *v)
{
	unsigned int *curpos;
	curpos = (unsigned int *)v;

	if (!IS_ERR(curpos))
		kfree(curpos);
	spin_unlock(&htable->lock);
}

static int tlslist_seq_show(struct seq_file *s, void *v)
{
	unsigned int *curpos;
	struct domains_match *dm;

	curpos = (unsigned int *)v;

	/* print everything from the bucket at once */
	if (!hlist_empty(&htable->hash[*curpos])) {
		hlist_for_each_entry(dm, &htable->hash[*curpos], node) {
#ifdef XT_TLSLIST_STAT
			seq_printf(s, "%s %u\n", dm->domain, dm->counter);
#else
			seq_printf(s, "%s\n", dm->domain);
#endif
		}
	}
        return 0;
}

static const struct seq_operations tlslist_seq_ops = {
        .start      = tlslist_seq_start,
        .show       = tlslist_seq_show,
        .next       = tlslist_seq_next,
        .stop       = tlslist_seq_stop,
};

static int tlslist_proc_open(struct inode *inode, struct file *file)
{
        int ret = seq_open(file, &tlslist_seq_ops);
        return ret;
}

static int parse_rule(struct tlslist_htable *ht, char *str, size_t size)
{
	int add;

	/* make sure that size is enough for two decrements */
	if (size < 2 || !str || !ht)
		return -EINVAL;

	/* strip trailing newline for better formatting of error messages */
	str[--size] = '\0';

	if (size < 1)
		return -EINVAL;
	switch (*str) {
		case '\n':
		case '#':
			return 0;
		case '/': /* flush table */
			htable_flush(ht);
			return 0;
		case '-':
			add = 0;
			break;
		case '+':
			add = 1;
			break;
		case ':':
			add = 2;
			break;
		default:
			pr_err("Rule should start with '+', '-', or '/'\n");
			return -EINVAL;
	}
	++str;
	--size;
	spin_lock(&ht->lock);
	if (add == 1) {
		htable_add(ht, str);
	}
	else if (add == 0) {
		htable_del(ht, str);
	}
	else if (add == 2) {
		struct domains_match *dm = htable_get(ht, str);
		pr_info("search domain %s", str);
		if (dm == NULL) {
			pr_info("domain not found!");
		}
		else {
			pr_info("found domain %s",dm->domain);
		}
	}
	spin_unlock(&ht->lock);
	return 0;
}

static ssize_t tlslist_proc_write(struct file *file, const char __user *ubuf, size_t count, loff_t *pos) 
{
        char *p;

        if (!count || !ubuf)
                return 0;

        if (count > sizeof(proc_buf))
                count = sizeof(proc_buf);

        if (copy_from_user(proc_buf, ubuf, count) != 0)
                return -EFAULT;

        for (p = proc_buf; p < &proc_buf[count]; ) {
                char *str = p;

                while (p < &proc_buf[count] && *p != '\n')
                        ++p;
                if (p == &proc_buf[count] || *p != '\n') {
                        /* unterminated command */
                        if (str == proc_buf) {
                                pr_err("Rule should end with '\\n'\n");
                                return -EINVAL;
                        } else {
                                /* Rewind to the beginning of incomplete
                                 * command for smarter writers, this doesn't
                                 * help for `cat`, though. */
                                p = str;
                                break;
                        }
                }
                *p = '\0';
                ++p;
                        if (parse_rule(htable, str, p - str))
                            return -EINVAL;
        }
        *pos += p - proc_buf;
        return p - proc_buf;
}
 
static struct file_operations proc_ops = 
{
        .owner = THIS_MODULE,
        .open = tlslist_proc_open,
        .read = seq_read,
        .write = tlslist_proc_write,
        .llseek = seq_lseek,
        .release = seq_release,
};
 
static int __init tls_mt_init (void)
{
        procentry = proc_create("tlsdomains",0660,NULL,&proc_ops);
	htable_create(&htable);
	return xt_register_matches(tls_mt_regs, ARRAY_SIZE(tls_mt_regs));
}

static void __exit tls_mt_exit (void)
{
        proc_remove(procentry);
	htable_destroy(htable);
	xt_unregister_matches(tls_mt_regs, ARRAY_SIZE(tls_mt_regs));
}

module_init(tls_mt_init);
module_exit(tls_mt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Igor Golubev <gibbon4ik@gmail.com>");
MODULE_DESCRIPTION("Xtables: TLS (SNI) matching");
MODULE_VERSION(TLSLIST_MODULE_VERSION);
MODULE_ALIAS("ipt_tlslist");
module_param(hashsize, uint, 0400);
MODULE_PARM_DESC(hashsize, "default size of hash table used to look up domains");

