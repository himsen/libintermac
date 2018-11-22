/*
 * @file im_chacha_poly.h
 *
 * @author anonymous
 */

#ifndef IM_CHACHA_POLY_H
#define IM_CHACHA_POLY_H

#include <sys/types.h>

#include "im_cipher_includes.h"

int im_chacha_poly_init(struct im_cipher_st_ctx*, const u_char*, u_int, u_char*, int);
int im_chacha_poly_cipher(struct im_cipher_st_ctx*, u_char*, u_char*, const u_char*, u_int);
void im_chacha_poly_cleanup(struct im_cipher_st_ctx*);

#endif /* IM_CHACHA_POLY_H */
