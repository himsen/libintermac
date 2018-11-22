/*
 * chacha-merged.c version 20080118
 * D. J. Bernstein
 * Public domain.
 */

/*
 * @file im_chacha.h
 *
 * @author D. J. Bernstein
 */

#ifndef IM_CHACHA_H
#define IM_CHACHA_H

#include <sys/types.h>
#include <stdlib.h>

struct im_chacha_ctx {
	u_int input[16];
};

#define IM_CHACHA_MINKEYLEN 	16
#define IM_CHACHA_NONCELEN		12
#define IM_CHACHA_CTRLEN		4
#define IM_CHACHA_STATELEN		(IM_CHACHA_NONCELEN+IM_CHACHA_CTRLEN)
#define IM_CHACHA_BLOCKLEN		64

void im_chacha_keysetup(struct im_chacha_ctx*, const u_char*, u_int);
void im_chacha_noncesetup(struct im_chacha_ctx*, u_char*, const u_char*);
void im_chacha_encrypt_bytes(struct im_chacha_ctx*, const u_char*, u_char*,
	u_int);

#endif	/* IM_CHACHA_H */
