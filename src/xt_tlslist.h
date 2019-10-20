#ifndef _XT_TLSLIST_TARGET_H
#define _XT_TLSLIST_TARGET_H

#define XT_TLS_OP_LIST	0x01

/* target info */
struct xt_tlslist_info {
	__u8 invert;
	char tls_list[255];
};

#endif /* _XT_TLSLIST_TARGET_H */
