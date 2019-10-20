#include <stdlib.h>
#include <xtables.h>
#include <stdio.h>
#include <string.h>

#include "xt_tlslist.h"

enum {
	O_TLS_LIST = 0,
};

static void tlslist_help(void)
{
	printf(
"tls match options:\n[!] --tls-list listname\n"
	);
}

static const struct xt_option_entry tlslist_opts[] = {
	{
		.name = "tls-list",
		.id = O_TLS_LIST,
		.type = XTTYPE_STRING,
		.flags = XTOPT_INVERT | XTOPT_PUT, XTOPT_POINTER(struct xt_tlslist_info, tls_list),
	},
	XTOPT_TABLEEND,
};

static void tlslist_parse(struct xt_option_call *cb)
{
	struct xt_tlslist_info *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
		case O_TLS_LIST:
			if (cb->invert)
				info->invert |= XT_TLS_OP_LIST;
			break;
	}
}

static void tlslist_check(struct xt_fcheck_call *cb)
{
	if (cb->xflags == 0)
		xtables_error(PARAMETER_PROBLEM, "TLS: no tls-list option specified");
}

static void tlslist_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct xt_tlslist_info *info = (const struct xt_tlslist_info *)match->data;

	printf(" TLS match");
	printf("%s --tls-list %s",
				 (info->invert & XT_TLS_OP_LIST) ? " !":"", info->tls_list);
}

static void tlslist_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_tlslist_info *info = (const struct xt_tlslist_info *)match->data;

	printf(" %s --tls-list %s",
				 (info->invert & XT_TLS_OP_LIST) ? " !":"", info->tls_list);
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
	.x6_fcheck	= tlslist_check,
	.x6_options	= tlslist_opts,
};

void _init(void)
{
	xtables_register_match(&tlslist_match);
}
