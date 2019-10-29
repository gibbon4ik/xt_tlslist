#include <stdlib.h>
#include <xtables.h>
#include <stdio.h>
#include <string.h>

#include "xt_tlslist.h"

enum {
	O_TLSLIST_SUBDOMAINS = 0,
};

static void tlslist_help(void)
{
	printf(
"tls match options:\n --tls-subdomains      Allow domain and subdomains matching as .domain.com\n"
	);
}

static const struct xt_option_entry tlslist_opts[] = {
	{
		.name = "tls-subdomains",
		.id = O_TLSLIST_SUBDOMAINS,
		.type = XTTYPE_NONE,
	},
	XTOPT_TABLEEND,
};

static void tlslist_parse(struct xt_option_call *cb)
{
	struct xt_tlslist_info *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
		case O_TLSLIST_SUBDOMAINS:
			info->flags |= XT_TLSLIST_SUBDOMAINS;
			break;
	}
}

static void tlslist_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct xt_tlslist_info *info = (const struct xt_tlslist_info *)match->data;

	printf(" TLS match");
	printf("%s", (info->flags & XT_TLSLIST_SUBDOMAINS) ? " --tls-subdomains":"");
}

static void tlslist_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_tlslist_info *info = (const struct xt_tlslist_info *)match->data;

	printf(" %s", (info->flags & XT_TLSLIST_SUBDOMAINS) ? " --tls-subdomains":"");
}

static struct xtables_match tlslist_match = {
	.family		= NFPROTO_UNSPEC,
	.name		= "tlslist",
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_tlslist_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_tlslist_info)),
	.help		= tlslist_help,
	.print		= tlslist_print,
	.save		= tlslist_save,
	.x6_parse	= tlslist_parse,
	.x6_options	= tlslist_opts,
};

void _init(void)
{
	xtables_register_match(&tlslist_match);
}
