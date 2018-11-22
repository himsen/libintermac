/* 
 * @file im_aes_gcm.c
 * @brief Simple AES-GCM 128 bit cipher, which sets a new nonce for every call
 *
 * @author Torben Hansen <Torben.Hansen.2015@rhul.ac.uk>
 */

#include "im_common.h"
#include "im_aes_gcm.h"

/*
 * @brief
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
int im_aes_gcm_init(struct im_cipher_st_ctx *im_cs_ctx, const u_char *key,
	u_int key_len, u_char *nonce, int crypt_type) {

	EVP_CIPHER_CTX *_evp = NULL;
	int r = IM_ERR;

	if (key_len != 128) {
		goto out;
	}

	if ((_evp = EVP_CIPHER_CTX_new()) == NULL) {
		goto out;
	}

	/* Pick cipher (EVP_aes_128_gcm) and set key */
	if (EVP_CipherInit(_evp, EVP_aes_128_gcm(), key, NULL, crypt_type) == 0) {
		goto out;
	}

	im_cs_ctx->evp = _evp;
	_evp = NULL;
	im_cs_ctx->crypt_type = crypt_type;

	r = IM_OK;

out:
	if (_evp != NULL) {
		EVP_CIPHER_CTX_free(_evp);
	}
	
	return r;
}

/*
 * @brief
 *
 * @param im_cs_ctx Cipher context
 * @param nonce Nonce
 * @param dst The address to which the encrypted/decrypted data is written
 * @param src The data that is encrypted/decrypted
 * @param src_length Length of data that is encrypted/decrypted
 * @return IM_OK on success, IM_ERR on failure
 */
int im_aes_gcm_cipher(struct im_cipher_st_ctx *im_cs_ctx, u_char *nonce,
	u_char *dst, const u_char *src, u_int src_length) {

	int crypt_type = im_cs_ctx->crypt_type;

	if (IM_CIPHER_DECRYPT == crypt_type) {

		/* Sets the MAC tag */
		if(EVP_CIPHER_CTX_ctrl(im_cs_ctx->evp, EVP_CTRL_GCM_SET_TAG, 16,
			(u_char *) src + src_length) == 0) {
			return IM_ERR;
		}
	}

	/* Set new nonce */
	if (EVP_CipherInit_ex(im_cs_ctx->evp, NULL, NULL, NULL, nonce, crypt_type) == 0) {
		return IM_ERR;
	}

	/* Encrypt/decrypt */
	if (EVP_Cipher(im_cs_ctx->evp, dst, src, src_length) < 0) {
		return IM_ERR;
	}

	/* Verify (on derypt) or compute (on encrypt) MAC tag */
	if (EVP_Cipher(im_cs_ctx->evp, NULL, NULL, 0) < 0) {
		return IM_ERR;
	}
	
	if (IM_CIPHER_ENCRYPT == crypt_type) {

		/* Set tag */
		if (EVP_CIPHER_CTX_ctrl(im_cs_ctx->evp, EVP_CTRL_GCM_GET_TAG, 16,
			dst + src_length) == 0) {
			return IM_ERR;
		}
	}

	return IM_OK;
}

/*
 * @brief
 *
 * @param
 * @return Void
 */
void im_aes_gcm_cleanup(struct im_cipher_st_ctx *im_cs_ctx) {

	if (im_cs_ctx != NULL && im_cs_ctx->evp != NULL) {
		EVP_CIPHER_CTX_free(im_cs_ctx->evp);
		im_cs_ctx->evp = NULL;
	}
}
