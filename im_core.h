/*
 * @file im_core.h
 *
 * @author Torben Hansen <Torben.Hansen.2015@rhul.ac.uk>
 */

#ifndef IM_CORE_H
#define IM_CORE_H

#include <sys/types.h>
#include <stdint.h>
#include <ctype.h>
#include <stdio.h>

#include "im_cipher.h"
#include "im_common.h"

/* Constants */

#define IM_DECRYPTION_BUFFER_LENGTH (1024*1024) /* 1 mb */
#define IM_NONCE_LENGTH 12
/* Maximum chunk counter 2^{32} - 1 */
#define IM_NONCE_CHUNK_CTR_LEN 0xFFFFFFFF
/* Maximum message counter 2^{64} - 1 */
#define IM_NONCE_MESSAGE_CTR_LEN 0xFFFFFFFFFFFFFFFF
/* TODO below constants does not align with the InterMAC in practice paper */
#define IM_CHUNK_DELIMITER_NOT_FINAL 0x00
#define IM_CHUNK_DELIMITER_FINAL 0x02
#define IM_CHUNK_DELIMITER_FINAL_NO_PADDING 0x1
#define IM_CHUNK_DELIMITER_MAX IM_CHUNK_DELIMITER_FINAL
#define IM_MAX_MSG_SIZES_BUFFERED 50

/* Macro's */

#define IM_U32ENCODE(p, v) \
	do { \
		const u_int32_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 24) & 0xff; \
		((u_char *)(p))[1] = (__v >> 16) & 0xff; \
		((u_char *)(p))[2] = (__v >> 8) & 0xff; \
		((u_char *)(p))[3] = __v & 0xff; \
	} while (0)

#define IM_U64ENCODE(p, v) \
	do { \
		const u_int64_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 56) & 0xff; \
		((u_char *)(p))[1] = (__v >> 48) & 0xff; \
		((u_char *)(p))[2] = (__v >> 40) & 0xff; \
		((u_char *)(p))[3] = (__v >> 32) & 0xff; \
		((u_char *)(p))[4] = (__v >> 24) & 0xff; \
		((u_char *)(p))[5] = (__v >> 16) & 0xff; \
		((u_char *)(p))[6] = (__v >> 8) & 0xff; \
		((u_char *)(p))[7] = __v & 0xff; \
	} while (0)

/*
 * libIntermac state context declaration
 * We do this to avoid user manipulation of the state.
 * The downside is that users can't statically allocate
 * the state.
 */
struct intermac_ctx;

/*
 * Public libIntermac API
 */

/*
 * @brief Allocates and initialises intermac context and 
 * initialises internal InterMAC cipher.
 *
 * Caller must call im_cleaup to free _im_ctx_ and
 * im_cleanup() must be called if this function fails.
 *
 * @param im_ctx The addres to which the InterMAC context is written
 * @param key The symmetric key the internal cipher is initialised with
 * @param chunk_length The InterMAC chunk_length parameter
 * @param cipher The internal cipher InterMAC should use
 * @param crypt_type Initialises the internal InterMAC cipher
 * in either encrypt mode (IM_CIPHER_ENCRYPT)
 * or decrypt mode (IM_CIPHER_DECRYPT)
 * @return IM_OK on success, IM_ERR on failure
 */
int im_initialise(struct intermac_ctx**, const u_char*, u_int, const char*,
	int);

/*
 * @brief InterMAC encrypts a message
 *
 * Caller must free _dst_.
 *  
 *
 * @param im_ctx The InterMAC context
 * @param dst The address to which the encrypted message is written
 * @param dst_length The address to which the length of the 
 * encrypted message is written
 * @param src The message that is InterMAC encrypted
 * @param src_length The length of the message that is InterMAC encrypted
 * @return IM_OK on success, IM_ERR on failure
 */
int im_encrypt(struct intermac_ctx*, u_char**, u_int*, const u_char*, u_int);

/*
 * @brief Intermac decrypt
 */
int im_decrypt(struct intermac_ctx*, const u_char*, u_int , u_char*,
	u_int, u_int*, u_int*, u_int*);

/* 
 * @breif Clean ups InterMAC state internals
 * 
 * Cycles throughs the InterMAC context components and makes
 * sure to call appropriate clean up functions. In addition,
 * zeroises any data tied to the InterMAC state.
 *
 * @param im_ctx The InterMAC contect to clean up
 * @return IM_OK on success, IM_ERR on failure
 */
int im_cleanup(struct intermac_ctx*);

/*
 * @brief Simple dequeue implementation
 */
int im_dequeue_msg_size(struct intermac_ctx*, u_int*);

#endif /* IM_CORE_H */
