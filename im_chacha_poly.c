/*
 * Copyright (c) 2013 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * @file im_chacha_poly.c
 *
 * @author Damien Miller <djm@mindrot.org>
 * Minor modifications by
 * anonymous
 */

#include <stddef.h>
#include <string.h>

#include "im_common.h"
#include "im_chacha_poly.h"

/*
 * @brief Initialises ChaCha20-Poly1305 internal cipher
 *
 * @param im_cs_ctx Cipher context
 * @param key Encryption/decryption key
 * @param key_len Length of key
 * @param nonce Nonce
 * @param crypt_type Initialise cipher to either
 * encrypt mode (IM_CIPHER_ENCRYPT)
 * or decrypt mode (IM_CIPHER_DECRYPT)
 * @return IM_OK on success, IM_ERR on failure
 */
int im_chacha_poly_init(struct im_cipher_st_ctx *im_cs_ctx, const u_char *key,
	u_int key_len, u_char *nonce, int crypt_type) {

	/* Only key length supported */
	if (key_len != 256) {
		return IM_ERR;
	}

	im_chacha_keysetup(&im_cs_ctx->im_cc_ctx, key, 256);

	im_cs_ctx->crypt_type = crypt_type;

	return IM_OK;
}

/*
 * @brief ChaCha20-poly1305 encrypt/decrypt a message/ciphertext
 *
 * @param im_cs_ctx Cipher context
 * @param nonce Nonce
 * @param dst The address to which the encrypted/decrypted data is written
 * @param src The data that is encrypted/decrypted
 * @param src_length Length of data that is encrypted/decrypted
 * @return IM_OK on success, IM_ERR on failure
 */
int im_chacha_poly_cipher(struct im_cipher_st_ctx *im_cs_ctx, u_char *nonce,
	u_char *dst, const u_char *src, u_int src_length) {

	int crypt_type = -1;
	const u_char one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 }; /* NB little-endian */
	u_char expected_tag[IM_POLY1305_TAGLEN], poly_key[IM_POLY1305_KEYLEN];

	crypt_type = im_cs_ctx->crypt_type;

	memset(poly_key, 0, sizeof(poly_key));
	im_chacha_noncesetup(&im_cs_ctx->im_cc_ctx, nonce, NULL);
	im_chacha_encrypt_bytes(&im_cs_ctx->im_cc_ctx, poly_key, poly_key,
		sizeof(poly_key));

	if (IM_CIPHER_DECRYPT == crypt_type) {

		const u_char *tag = src + src_length;

		im_poly1305_auth(expected_tag, src, src_length, poly_key);
		if (im_timingsafe_bcmp(expected_tag, tag, IM_POLY1305_TAGLEN) != 0) {
			return IM_ERR;
		}
	}

	im_chacha_noncesetup(&im_cs_ctx->im_cc_ctx, nonce, one);
	im_chacha_encrypt_bytes(&im_cs_ctx->im_cc_ctx, src, dst, src_length);

	if (IM_CIPHER_ENCRYPT == crypt_type) {
		im_poly1305_auth(dst + src_length, dst, src_length, poly_key);
	}

	return IM_OK;
}

/*
 * @brief Clean up ChaCha20-poly1305 context
 *
 * @param im_cs_ctx Cipher context
 * @return VOID
 */
void im_chacha_poly_cleanup(struct im_cipher_st_ctx *im_cs_ctx) {

	if (im_cs_ctx != NULL && &im_cs_ctx->im_cc_ctx != NULL) {
		im_explicit_bzero(&im_cs_ctx->im_cc_ctx, sizeof(im_cs_ctx->im_cc_ctx));
	}
}
