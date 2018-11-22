/*
 * @file im_cipher.c
 *
 * @author anonymous
 */

#include <stdio.h>
#include <string.h>

#include "im_cipher.h"

/* Cipher specific constants */
/* aes-gcm */
#define IM_AES_GCM_KEY_LENGTH 128
#define IM_AES_GCM_TAG_LENGTH 16
#define IM_AES_GCM_CT_EXPANSION 0
/* chacha20-poly1305 */
#define IM_CHACHA_POLY_KEY_LENGTH 256
#define IM_CHACHA_POLY_TAG_LENGTH 16
#define IM_CHACHA_POLY_CT_EXPANSION 0

/* Cipher specific limits */
/*
 * chacha20-poly1305:
 * MAX chunk length < 2^{70}
 * Actual MAX used 2^{32} - 1
 */
#define IM_CIPHER_CHACHA_POLY_CHUNK_LENGTH 0xFFFFFFFF
/*
 * aes-gcm:
 * MAX chunk length < 2^{36} - 2^5
 * Actual MAX used 2^{32} - 1
 *
 * Invocation limit (maximal number of encrypted chunks) = 2^{48 - k}
 * where 2^k is the chunk length
 */
#define IM_CIPHER_AES_GCM_CHUNK_LENGTH 0xFFFFFFFF
#define IM_CIPHER_AES_GCM_INV_LIMIT_BASE 0xFFFFFFFFFFFFFFFF

/* Register available internal InterMAC ciphers */
static const struct im_cipher ciphers[] = {
	{"im-aes128-gcm",
	IM_AES_GCM_KEY_LENGTH, IM_AES_GCM_TAG_LENGTH, IM_AES_GCM_CT_EXPANSION,
	im_aes_gcm_init, im_aes_gcm_cipher, im_aes_gcm_cleanup,
	IM_CIPHER_AES_GCM},
	{"im-chacha-poly",
	IM_CHACHA_POLY_KEY_LENGTH, IM_CHACHA_POLY_TAG_LENGTH,
	IM_CHACHA_POLY_CT_EXPANSION,
	im_chacha_poly_init, im_chacha_poly_cipher, im_chacha_poly_cleanup,
	IM_CIPHER_CHACHA_POLY}
};

const int tabel32[32] = {
     0,  9,  1, 10, 13, 21,  2, 29,
    11, 14, 16, 18, 22, 25,  3, 30,
     8, 12, 20, 28, 15, 17, 24,  7,
    19, 27, 23,  6, 26,  5,  4, 31
};

/*
 * @brief Computes the highest order bit set in n
 * @param 32-bit number
 * @return The highest order bit set in n
 */
static inline uint32_t hbit32(uint32_t n) {

    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;

    return tabel32[(uint32_t) (n * 0x07C4ACDD) >> 27];
}

const int tabel64[64] = {
    63,  0, 58,  1, 59, 47, 53,  2,
    60, 39, 48, 27, 54, 33, 42,  3,
    61, 51, 37, 40, 49, 18, 28, 20,
    55, 30, 34, 11, 43, 14, 22,  4,
    62, 57, 46, 52, 38, 26, 32, 41,
    50, 36, 17, 19, 29, 10, 13, 21,
    56, 45, 25, 31, 35, 16,  9, 12,
    44, 24, 15,  8, 23,  7,  6,  5
};

/*
 * @brief Computes the highest order bit set in n
 * @param 64-bit number
 * @return The highest order bit set in n
 */
static inline uint64_t hbit64(uint64_t n)
{
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    n |= n >> 32;

    return tabel64[((uint64_t) ( (n - (n >> 1)) * 0x07EDD5E59A4E28C2 )) >> 58];
}

/*
 * @brief Returns internal InterMAC cipher from name
 * @param name The name of the internal InterMAC cipher
 * @return Interal cipher or NULL if no cipher wiht _name_ exists
 */
const struct im_cipher * im_get_cipher(const char *name) {

	const struct im_cipher *c;

	for (c = ciphers; c->name != NULL; c++) {
		if (strcmp(c->name, name) == 0) {
			return c;
		}
	}
	
	return NULL;
}

/*
 * @brief Checks if requested cipher and requested chunk length are allowed
 * 
 * @param chunk_length The InterMAC chunk lenght parameter
 * @param cipher The internal cipher requested by user
 * @return 0 if chunk length and cipher combination is allowed, 1 if
 * combination is not allowed. Returns 0 if cipher is not recognised.
 */
int check_chunk_length_limit(u_int chunk_length,
	const struct im_cipher *cipher) {

	switch(cipher->flags) {
		case IM_CIPHER_CHACHA_POLY:
			if (chunk_length > IM_CIPHER_CHACHA_POLY_CHUNK_LENGTH) {
				return -1;
			}
			return 0;
		case IM_CIPHER_AES_GCM:
			if (chunk_length > IM_CIPHER_AES_GCM_CHUNK_LENGTH) {
				return -1;
			}
			return 0;
		default:
			return 0;
	}
}

/*
 * @brief Computes encryption limit (in bytes)
 * for a specific internal cipher for a specific chunk length
 *
 * NOT implemented (TODO)
 *
 * @param chunk_length The InterMAC chunk lenght parameter
 * @param cipher The internal cipher requested by user
 * @return Encryption limit (in bytes) or 0 if no limit
 */
uint64_t get_encryption_limit(u_int chunk_length,
	const struct im_cipher *cipher) {

	switch(cipher->flags) {
		case IM_CIPHER_CHACHA_POLY:
			return 0;
		case IM_CIPHER_AES_GCM:
			return 0;
		default:
			return 0;
	}
}

/*
 * @brief Computes the encryption invocation limit
 * for a specific internal cipher for a specific chunk length
 *
 * @param chunk_length The InterMAC chunk lenght parameter
 * @param cipher The internal cipher requested by user
 * @return Encryption invocation limit (in bytes) or 0 if no limit
 */
uint64_t get_encryption_inv_limit(u_int chunk_length,
	const struct im_cipher *cipher) {

	uint64_t mask = 0;
	uint32_t exp = 0;

	switch(cipher->flags) {
		case IM_CIPHER_CHACHA_POLY:
			return 0;
		case IM_CIPHER_AES_GCM:
			/* 2^{48 - k}, where 2^k is the chunk length */
			exp = hbit32((uint32_t) chunk_length);
			mask |= 1ULL << (48 - exp);
			return IM_CIPHER_AES_GCM_INV_LIMIT_BASE & mask;
		default:
			return 0;
	}
}

/*
 * @brief Computes the authentication limit
 * for a specific internal cipher for a specific chunk length
 *
 * NOT implemented (TODO)
 *
 * @param chunk_length The InterMAC chunk lenght parameter
 * @param cipher The internal cipher requested by user
 * @return Authentication limit (in bytes) or 0 if no limit
 */
uint64_t get_authentication_limit(u_int chunk_length,
	const struct im_cipher *cipher) {

	switch(cipher->flags) {
		case IM_CIPHER_CHACHA_POLY:
			return 0;
		case IM_CIPHER_AES_GCM:
			return 0;
		default:
			return 0;
	}
}

/*
 * @brief Computes the authentication invocation limit
 * for a specific internal cipher for a specific chunk length
 *
 * NOT implemented (TODO)
 *
 * @param chunk_length The InterMAC chunk lenght parameter
 * @param cipher The internal cipher requested by user
 * @return Authentication invocation limit (in bytes) or 0 if no limit
 */
uint64_t get_authentication_inv_limit(u_int chunk_length,
	const struct im_cipher *cipher) {

	switch(cipher->flags) {
		case IM_CIPHER_CHACHA_POLY:
			return 0;
		case IM_CIPHER_AES_GCM:
			return 0;
		default:
			return 0;
	}
}
