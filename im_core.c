/*
 * @file im_core.c
 * @brief Implements core InterMAC API: 
 * im_initialise()
 * im_encrypt()
 * im_decrypt()
 * im_cleanup()
 * 
 * @author Torben Hansen <Torben.Hansen.2015@rhul.ac.uk>
 */

#include <string.h>
#include <stdio.h>

#include "im_common.h"
#include "im_core.h"
#include "im_cipher.h"
#include <inttypes.h>

/* Only works for x,y > 0 */
#define im_div_roundup(x,y) ( 1 + ( ((x) - 1) / (y) ) )

/* Internal im_core.c functions */
static inline void im_padding_length_encrypt(u_int length, u_int chunk_length, 
	u_int number_of_chunks, u_int *res);
static inline int im_get_length(struct intermac_ctx *im_ctx, u_int length,
	u_int *res);
static inline int im_add_alternating_padding(u_char *chunk, u_char last_byte,
	u_int padding_length, u_int chunk_length);
static inline int im_encode_nonce(u_char *nonce, uint32_t chunk_counter,
	uint64_t message_counter);
static int im_padding_length_decrypt(u_char *decrypted_chunk,
	u_int chunk_length, u_char chunk_delimiter, u_int *padding_length);
static int im_decrypt_internal(struct intermac_ctx *im_ctx, const u_char *src,
	u_int src_length, u_int *this_src_processed,
	u_int *size_decrypted_ciphertext);

/*
 * @brief Computes the number of padding bytes needed to hit a multiple of
 * the chunk length.
 *
 * Because we want to avoid padding a whole chunk the
 * number of padding bytes can be zero.
 *
 * @param length The length of message to be encrypted
 * @param chunk_length The InterMAC chunk length parameter
 * @param number_of_chunks The number of chunks when _length_
 * bytes are InterMAC encoded
 * @param res Address to which the result is written
 * @return IM_OK on success, IM_ERR on failure
 */
static inline void im_padding_length_encrypt(u_int length, u_int chunk_length, 
	u_int number_of_chunks, u_int *res) {

	/* Compute how many bytes away from chunk boundary */
	*res = chunk_length - (length % chunk_length);
}

/*
 * @brief Computes the length of padding, in a decrypted chunk, in constant
 * time.
 * @param decrypted_chunk The decrypted chunk
 * @param chunk_length The InterMAC chunk length parameter
 * @param padding_length Address to which the result is written
 * @return IM_OK on success, IM_ERR on failure
 */
static int im_padding_length_decrypt(u_char *decrypted_chunk,
	u_int chunk_length, u_char chunk_delimiter, u_int *padding_length) {

	u_int i = 0;
	u_int padding_counter = 1;
	u_char type_width = 0;
	u_char padding_flag = 0;
	u_char padding_lsb = 0;
	u_char padding_add = 0;
	u_char padding_byte = 0;
	u_char padding_mult = 0;

	/* If this is the case, there is something wrong! */
	if (chunk_length < 3) {
		return IM_ERR;
	}

	/* 
	 * Retrieve padding byte
	 * decrypted_chunk[chunk_length - 1] is the chunk delimiter
	 */
	padding_byte = decrypted_chunk[chunk_length - 1];

	/*
	 * Width (in bits) of padding byte type
	 */
	type_width = 8 * sizeof(u_char);

	/* 
	 * Run through decrypted chunk one byte at a time. Flag when a byte
	 * different from the padding byte is encountered.  
	 */
	for (i = 1; i < chunk_length; i++) {

		padding_flag |= padding_byte ^ decrypted_chunk[(chunk_length - 1) - i];
		padding_lsb = (padding_flag | ((u_char)-padding_flag)) >> (type_width - 1);
		padding_add = padding_lsb ^ 0x01;
		padding_counter = padding_counter + padding_add;
	}

	/*
	 * Return a padding length of zero if we are not processing the final chunk.
	 */
	padding_mult = (chunk_delimiter * (chunk_delimiter - 1)) >> 1;
	*padding_length = padding_counter * padding_mult;

	return IM_OK;
}


/*
 * @brief Adds aternating padding to a chunk.
 * 
 * The padding byte used depends on the last byte in the parameter chunk:
 * If the last byte is '0' the padding byte is '1', otherwise the padding byte
 * is '0'.
 *
 * @param chunk The chunk on which padding is applied
 * @param last_byte The last byte of parameter chunk
 * @param padding_length Amount of padding that needs to be applied (counted in bytes)
 * @param chunk_length The InterMAC chunk_length parameter
 * @return IM_OK on success, IM_ERR on failure
 */
static inline int im_add_alternating_padding(u_char *chunk, u_char last_byte,
	u_int padding_length, u_int chunk_length) {

	if (padding_length == 0) {
		return IM_OK;
	}

	if (padding_length > (chunk_length - 1)) {
		return IM_ERR;
	}

	if (last_byte == 0x00) {
		if (!memset(chunk, 0x01, padding_length)) {
			return IM_ERR;
		}
	}
	else {
		if (!memset(chunk, 0x00, padding_length)) {
			return IM_ERR;
		}
	}

	return IM_OK;
}

/*
 * @brief Computes the resulting length of the ciphertext of an InterMAC
 * encrytion of a plaintext.
 *
 * Also computes the resulting number of chunks of InterMAC encoding the 
 * plaintext. This number if saved in the InterMAC context. 
 *
 * @param im_ctx InterMAC context
 * @param length The length of plaintext
 * @param res Address to which the result is written
 * @return IM_OK on success, IM_ERR on failure
 */
static inline int im_get_length(struct intermac_ctx *im_ctx, u_int length,
	u_int *res) {

	int noc = 0;

	/* im_div_roundup computation cannot handle these specific values */
	if ((length == 0) || (im_ctx->chunk_length == 1)) {
		return IM_ERR;
	}

	/* 
	 * Computes the number of chunks in an InterMAC encoding of a message
	 * of length _length_
	 */
	noc = im_div_roundup(length, im_ctx->chunk_length); 

	/* 
	 * Intermac ciphetext consists of:
	 * _noc_ number of encrypted encoded chunks of size ciphertext_length 
	 * (counted in bytes)
	 * _noc_ number of MAC tags of size mactag_length (counted in bytes)
	 */
	*res = (im_ctx->ciphertext_length * noc) + (im_ctx->mactag_length * noc);

	/* Save number of chunks for later */
	im_ctx->number_of_chunks = noc; 

	return IM_OK;
}

/*
 * @brief Encodes nonce
 *
 * The nonce is encoded as
 * nonce = chunk_counter || message_counter
 * where both counters are treated as 32 bit strings.
 *
 * @param nonce The address to which the result is written
 * @param chunk_counter The InterMAC chunk_counter
 * @param message_counter The InterMAC message_counter
 * @return IM_OK on success, IM_ERR on failure
 */
static inline int im_encode_nonce(u_char *nonce, uint32_t chunk_counter,
	uint64_t message_counter) {

	if ((uint32_t) chunk_counter > (uint32_t) IM_NONCE_CHUNK_CTR_LEN) {
		return IM_ERR;
	}
	if ((uint64_t) message_counter > (uint64_t) IM_NONCE_MESSAGE_CTR_LEN) {
		return IM_ERR;
	}

	IM_U32ENCODE(nonce, chunk_counter);
	IM_U64ENCODE(nonce + 4, message_counter);

	return IM_OK;
}

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
int im_initialise(struct intermac_ctx **im_ctx, const u_char *key, 
	u_int chunk_length, const char *cipher, int crypt_type) {

	const struct im_cipher *chosen_cipher = NULL;
	struct im_cipher_ctx *_im_c_ctx = NULL;
	struct intermac_ctx *_im_ctx = NULL;
	struct im_cipher_st_ctx _im_cs_ctx;
	u_char nonce[IM_NONCE_LENGTH];
	int r = IM_OK;

	/* Quickly abort if input cannot be parsed */
	if (key == NULL || chunk_length < 1 || cipher == NULL) {
		return IM_ERR;
	}

	/* Retrieves the chosen cipher */
	if ((chosen_cipher = im_get_cipher(cipher)) == NULL) {
		return IM_ERR;
	}

	/* Check chunk length restrictions */
	if (check_chunk_length_limit(chunk_length, chosen_cipher) == -1) {
		return IM_ERR;
	}

	/* Allocate new contexts */
	if ((_im_ctx = (struct intermac_ctx *) calloc(1, sizeof(*_im_ctx)))
		== NULL) {
		r = IM_ERR;
		goto out;
	}
	if ((_im_c_ctx = (struct im_cipher_ctx *) calloc(1, sizeof(*_im_c_ctx)))
		== NULL) {
		r = IM_ERR;
		goto out;
	}

	/* 
	 * Encodes initial nonce with counters set to 0. 
	 * The nonce might not be used by the chosen cipher
	 */
	if ((r = im_encode_nonce(nonce, 0, 0)) == IM_ERR) {
		goto out;
	}

	/* 
	 * Initialises cipher with key, nonce and encrypt/decrypt mode
	 * The cipher context is written to _im_cs_ctx
	 */
	if ((r = chosen_cipher->init(&_im_cs_ctx, key, chosen_cipher->key_len,
		nonce, crypt_type)) != IM_OK) {
		goto out;
	}

	/* The following sets the initial InterMAC state */
	_im_ctx->im_c_ctx = _im_c_ctx;
	_im_ctx->chunk_length = chunk_length;
	_im_ctx->ciphertext_length = chunk_length + 1 + chosen_cipher->ciphertext_expansion;
	_im_ctx->mactag_length = chosen_cipher->tag_len;
	_im_ctx->chunk_counter = 0;
	_im_ctx->message_counter = 0;
	_im_ctx->src_processed = 0;
	_im_ctx->number_of_chunks = 0;
	_im_ctx->total_encrypted_chunks = 0;
	_im_ctx->encryption_inv_limit = get_encryption_inv_limit(chunk_length,
		chosen_cipher);
	/* Limits NOT yet implemented (TODO) */
	_im_ctx->encryption_limit = get_encryption_limit(chunk_length,
		chosen_cipher);
	_im_ctx->authentication_limit = get_authentication_limit(chunk_length,
		chosen_cipher);
	_im_ctx->authentication_inv_limit = get_authentication_inv_limit(
		chunk_length,chosen_cipher);

	_im_ctx->decrypt_buffer_offset = 0;
	_im_ctx->decrypt_buffer_allocated = IM_DECRYPTION_BUFFER_LENGTH;
	_im_ctx->decryption_buffer = (u_char *) calloc(IM_DECRYPTION_BUFFER_LENGTH,
		sizeof(u_char));

	_im_ctx->fail = 0;

	memset(_im_ctx->queue_msg_size, 0, sizeof(u_int) * IM_MAX_MSG_SIZES_BUFFERED);
	_im_ctx->queue_front = 0;
	_im_ctx->queue_rear = 0;

	_im_c_ctx->cipher = chosen_cipher;
	_im_c_ctx->im_cs_ctx = _im_cs_ctx;
	*(im_ctx) = _im_ctx;

	/* The following memory is now owned by *im_ctx */
	_im_c_ctx = NULL;
	_im_ctx = NULL;

out:
	if (_im_c_ctx != NULL) {
		free(_im_c_ctx);
	}
	if (r != IM_OK) {
		chosen_cipher->cleanup(&_im_cs_ctx);
	}
	if (_im_ctx != NULL) {
		free(_im_ctx);
	}
	return r;
}

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
int im_encrypt(struct intermac_ctx *im_ctx, u_char **dst, u_int *dst_length, 
	const u_char *src, u_int src_length) {

	u_int padding_length = 0;
	u_int padding_offset = 0;
	/* Counter for processing the (k+1)th chunk of the unencoded message */
	u_int k = 0;
	/* Offset to current chunk being processed */
	u_int current_chunk = 0; 
	/* Offset to current destination for ciphertext */
	u_int ciphertext_buffer_offset = 0;
	u_int number_of_chunks = 0;
	u_int chunk_length = 0;
	u_int ciphertext_length = 0;
	u_int mactag_length = 0;
	uint32_t chunk_counter = 0;
	uint64_t message_counter = 0;

	u_char *chunk_buf = NULL;
	u_char chunk_delimiter_not_final = IM_CHUNK_DELIMITER_NOT_FINAL;
	u_char chunk_delimiter_final = IM_CHUNK_DELIMITER_FINAL;
	u_char chunk_delimiter_final_no_padding = IM_CHUNK_DELIMITER_FINAL_NO_PADDING;
	u_char nonce[IM_NONCE_LENGTH];
	u_char *ciphertext = NULL;

	int r = IM_OK;

	if (im_ctx == NULL) {
		return IM_ERR;
	}

	/*
	 * Check if we should fail.
	 * This happens if a nonce restriction is vioalated or
	 * if the internal cipher usage restriction is violated.
	 */
	if (im_ctx->fail == 1) {
		return IM_ERR;
	}

	/* Verify that we are in encryption mode */
	if (IM_CIPHER_ENCRYPT != im_ctx->im_c_ctx->im_cs_ctx.crypt_type) {
		return IM_ERR;
	}

	chunk_length = im_ctx->chunk_length;
	ciphertext_length = im_ctx->ciphertext_length;
	mactag_length = im_ctx->mactag_length;
	chunk_counter = im_ctx->chunk_counter;
	message_counter = im_ctx->message_counter;

	/* 
	 * Computes the size (in bytes) of final ciphertext 
	 * as well as the number of chunks needed
	 * (saved to im_ctx->number_of_chunks)
	 */
	if (im_get_length(im_ctx, src_length, dst_length) != 0) {
		return IM_ERR;
	}

	number_of_chunks = im_ctx->number_of_chunks;

	/*
	 * Check whether we would exceed the limit on the number of
	 * invocation we can make of the chosen cipher.
	 */
	if (im_ctx->encryption_inv_limit > 0 &&
		(uint64_t) (im_ctx->total_encrypted_chunks + number_of_chunks) >
		(uint64_t) im_ctx->encryption_inv_limit) {
		return IM_ERR;
	}

	/* Allocates memory for final ciphertext */
	ciphertext = NULL;
	ciphertext = (u_char *) calloc(1, *dst_length);
	if (ciphertext == NULL) {
		return IM_ERR;
	}

	/* Computes the size (in bytes) of padding needed */
	im_padding_length_encrypt(src_length, chunk_length, number_of_chunks,
		&padding_length);
	padding_offset = chunk_length - padding_length;

	chunk_buf = calloc(1, chunk_length + 1);
	if (chunk_buf == NULL) {

		r = IM_ERR;
		goto fail_clean;
	}

	/* 
	 * Loop that encrypts each chunk, computes MAC tag and append the MAC tag
	 * to the resulting chunk ciphertext.
	 * Writes result to address ciphertext.. 
	 */
	for (k = 0; k < number_of_chunks; k++) {

		current_chunk = k * chunk_length;
		ciphertext_buffer_offset = k * (ciphertext_length + mactag_length);

		/* Adds chunk delimiter */
		if (k < (number_of_chunks - 1)) {
			/* Not yet processing the final chunk */

			memcpy(chunk_buf, src + current_chunk, chunk_length);
			memcpy(chunk_buf + chunk_length,
				&chunk_delimiter_not_final, 1);
		}
		else {
			/* Now processing the final chunk */

			im_add_alternating_padding(chunk_buf + padding_offset,
				src[src_length - 1], padding_length, chunk_length);

			memcpy(chunk_buf, src + current_chunk,
				chunk_length - padding_length);

			if (padding_length == 0) {
				/* Padding not needed */
				memcpy(chunk_buf + chunk_length,
					&chunk_delimiter_final_no_padding, 1);
			}
			else {
				/* Padding needed */
				memcpy(chunk_buf + chunk_length,
					&chunk_delimiter_final, 1);
			}
		}

		if ((r = im_encode_nonce(nonce, chunk_counter,
			message_counter)) != IM_OK) {
			goto fail_clean;
		}

		/*
		 * Encrypts chunk and computes MAC tag using chosen internal InterMAC
		 * cipher. Writes result to address dst + ciphertext_buffer_offset
		 */
		if (im_ctx->im_c_ctx->cipher->do_cipher(&im_ctx->im_c_ctx->im_cs_ctx,
			nonce, ciphertext + ciphertext_buffer_offset, chunk_buf,
			chunk_length + 1) != 0) {

			r = IM_ERR;
			goto fail_clean;
		}

		/*
		 * If chunk counter overflows and we have more chunks to processs
		 * then error.
		 */
		if ((uint32_t) (chunk_counter + 1) < (uint32_t) chunk_counter
			&& k < (number_of_chunks + 1)) {
			
			goto fail_clean;
			r = IM_ERR;
		}
		chunk_counter = chunk_counter + 1;
	}

	/*
	 * Check if message counter overflows.
	 * Error if encryption function is called again.
	 */
	if ((uint64_t) (message_counter + 1) < (uint64_t) message_counter) {
		im_ctx->fail = 1;
	}

	im_ctx->message_counter = message_counter + 1;
	im_ctx->chunk_counter = 0;
	im_ctx->number_of_chunks = 0;

	/* Save to output buffer */
	*dst = ciphertext;
	ciphertext = NULL;

fail_clean:
	if (r != IM_OK && ciphertext != NULL) {
		free(ciphertext);
	}
	if (chunk_buf != NULL) {
		memset(chunk_buf, 0, chunk_length + 1);
		free(chunk_buf);
	}

	return r;
}

/*
 * @brief Simple queue implementation
 */
static int im_enqueue_msg_size(struct intermac_ctx *im_ctx, u_int msg_size) {

	size_t queue_rear = 0;

	if (im_ctx->queue_size + 1 > IM_MAX_MSG_SIZES_BUFFERED) {
		return IM_ERR;
	}

	queue_rear = im_ctx->queue_rear;

	im_ctx->queue_msg_size[queue_rear] = msg_size;

	if (queue_rear + 1 > IM_MAX_MSG_SIZES_BUFFERED - 1) {
		queue_rear = 0;
	}
	else {
		queue_rear = queue_rear + 1;
	}

	im_ctx->queue_rear = queue_rear;
	im_ctx->queue_size = im_ctx->queue_size + 1;

	return IM_OK;
}

/*
 * @brief Simple dequeue implementation
 */
int im_dequeue_msg_size(struct intermac_ctx *im_ctx, u_int *msg_size) {

	size_t queue_front = 0;

	if (im_ctx->queue_size < 1) {
		return IM_ERR;
	}

	queue_front = im_ctx->queue_front;

	*msg_size = im_ctx->queue_msg_size[queue_front];
	im_ctx->queue_msg_size[queue_front] = 0;

	im_ctx->queue_size = im_ctx->queue_size - 1;

	if (queue_front + 1 > IM_MAX_MSG_SIZES_BUFFERED - 1) {
		im_ctx->queue_front = 0;
	}
	else {
		im_ctx->queue_front = queue_front + 1;
	}

	return IM_OK;
}

/*
 * @brief Intermac decrypt
 */
int im_decrypt(struct intermac_ctx *im_ctx, const u_char *src, u_int src_length,
	u_char *dst, u_int dst_length, u_int *total_src_processed,
	u_int *total_cts_decrypted, u_int *total_length_cts_decrypted) {

	u_int cts_decrypted = 0;
	u_int this_src_processed = 0;
	u_int src_processed = 0;
	u_int size_decrypted_ciphertext = 0;
	u_int this_total_pt_size = 0;

	*total_cts_decrypted = 0;
	*total_src_processed = 0;
	*total_length_cts_decrypted = 0;

	while(1) {

		src_processed = 0;
		size_decrypted_ciphertext = 0;

		if (im_decrypt_internal(im_ctx, src + this_src_processed,
			src_length - this_src_processed,
			&src_processed, &size_decrypted_ciphertext) == IM_ERR) {

			return IM_ERR;
		}
		else if (size_decrypted_ciphertext > 0) {

			if (dst_length > this_total_pt_size + size_decrypted_ciphertext) {
				memcpy(dst + this_total_pt_size, im_ctx->decryption_buffer,
					size_decrypted_ciphertext);
				im_enqueue_msg_size(im_ctx, size_decrypted_ciphertext);
				this_total_pt_size = this_total_pt_size + size_decrypted_ciphertext;
				this_src_processed = this_src_processed + src_processed;
				cts_decrypted = cts_decrypted + 1;
			}
			else {
				return IM_ERR;
			}
		}
		else {
			goto out;
		}
	}

out:
	*total_cts_decrypted = cts_decrypted;
	*total_src_processed = this_src_processed;
	*total_length_cts_decrypted = this_total_pt_size;

	return IM_OK;
}

/*
 * @brief InterMAC decrypts a ciphertext fragment. The function will
 * return when ONE ciphertext has been fully decrypted and will not
 * attempt to decrypt further ciphertets (or ciphertext parts) that
 * might be contained in a ciphertext fragment.
 *
 * The caller must NOT free the return pointer _*dst_. We are aware
 * that this functions borders to insanity...
 *
 * @param im_ctc The InterMAC context
 * @param src The ciphertext fragment to be InterMAC decrypted
 * @param src_length The length of the ciphertext fragment to be InterMAC
 * decrypted
 * @param dst The address to which the a decrypted ciphertext is written, note
 * that this will only happen when the full ciphertext has been decrypted
 * @param size_decrypted_ciphertext The address to which the size of the
 * decrypted ciphertext is written
 * @param total_allocated The amout of memory (counted in bytes) allocated at
 * the address dst
 * @return IM_OK && *dst == NULL if waiting for more data, IM_OK && *dst
 * != NULL if a ciphertext has been fully decrypted, IM_ERR on failure
 */
static int im_decrypt_internal(struct intermac_ctx *im_ctx, const u_char *src,
	u_int src_length, u_int *ct_length,
	u_int *size_decrypted_ciphertext) {

	/* TODO add ref
	 * WARNING This function could leak timing information becasue
	 * execution time atm depends on the length of the message being decrypted
	 * and not the length of the ciphertext fragment. To counter this, a dummy
	 * decryption must be implemented that performs a fake decryption of the
	 * remaining ciphertext fragments (i.e as long as there is enough data for
	 * a chunk ciphertext + mac tag). This is only relevant for active
	 * boundary hiding. This poperty is impossible to meet in general in
	 * real world systems cf. REF. Bacause of this fact, we have not
	 * implemented the dummy decryption feature.
	 */

	u_char *decryption_buffer = NULL;
	u_char chunk_delimiter = 0;

	u_int chunk_length = 0;
	u_int ciphertext_length = 0;
	u_int mactag_length = 0;
	/*
	 * Saves how many ciphertect bytes hat has been
	 * processed in previous calls
	 */
	u_int src_processed = 0; 
	u_int padding_length = 0;
	uint32_t chunk_counter = 0;
	uint64_t message_counter = 0;
	u_int counter_fail = 0;
	u_int decrypt_buffer_offset = 0;

	u_char *decrypted_chunk = NULL;
	u_char *expected_tag = NULL;
	u_char nonce[IM_NONCE_LENGTH];

	u_int this_src_processed = 0;
	int r = IM_OK;

	if (im_ctx == NULL) {
		return IM_ERR;
	}

	/*
	 * Check if we should fail.
	 * This can occur if a nonce restriction is vioalated or
	 * when an internal encryption scheme usage restriction is violated.
	 */
	if (im_ctx->fail == 1) {
		return IM_ERR;
	}

	/* Verify that we are in decryption mode */
	if (IM_CIPHER_DECRYPT != im_ctx->im_c_ctx->im_cs_ctx.crypt_type) {
		return IM_ERR;
	}

	decryption_buffer = im_ctx->decryption_buffer;
	chunk_length = im_ctx->chunk_length;
	ciphertext_length = im_ctx->ciphertext_length;
	mactag_length = im_ctx->mactag_length;
	src_processed = im_ctx->src_processed;

	/* Verify that the decryption buffer is available */
	if (decryption_buffer == NULL) {
		return IM_ERR;
	}

	decrypted_chunk = calloc(1, chunk_length + 1);
	if (decrypted_chunk == NULL) {
		return IM_ERR;
	}

	expected_tag = calloc(1, mactag_length);
	if (expected_tag == NULL) {

		free(decrypted_chunk);
		return IM_ERR;
	}

	/*
	 * Saves how many bytes that has been processed in *this* call at
	 * any given time
	 */
	*ct_length = 0;
	*size_decrypted_ciphertext = 0;

	for (;;) {

		/*
		 * Fail if chunk counter overflows. Would be set in previous iteratn.
		 */
		if (counter_fail != 0) {

			r = IM_ERR;
			goto fail_clean;
		}
		/*
		 * Because this loop runs until a final chunk of a message has been
		 * decrypted or until we don't have an entire chunk, we must make sure
		 * to update local variables
		 */
		chunk_counter = im_ctx->chunk_counter;
		message_counter = im_ctx->message_counter;
		decrypt_buffer_offset = im_ctx->decrypt_buffer_offset;

		/* Checks if there are enough bytes to decrypt a chunk */
		if ((src_length - src_processed - this_src_processed) <
			(ciphertext_length + mactag_length)) {

			/* Return IM_OK: wait for more bytes */
			r = IM_OK;
			/* This is not a fail but we abuse the goto */
			goto fail_clean;
		}

		/* Extracts the MAC tag from ciphertext chunk */
		memcpy(expected_tag, src + (src_processed + this_src_processed +
			ciphertext_length), mactag_length);

		if ((r = im_encode_nonce(nonce, chunk_counter,
			message_counter)) != IM_OK) {
			goto fail_clean;
		}

		/*
		 * Apply internal cipher on chunk.
		 * Returning from do_cipher implies that the chunk MAC has been verified
		 * and that the chunk has been decrypted.
		 * The decrypted chunk is written to the address decrypted_chunk.
		 */
		if (im_ctx->im_c_ctx->cipher->do_cipher(&im_ctx->im_c_ctx->im_cs_ctx,
			nonce, decrypted_chunk,
			src + (src_processed + this_src_processed),
			ciphertext_length) != 0) {

			r = IM_ERR;
			goto fail_clean;
		}

		/* Extract the chunk delimiter */
		chunk_delimiter = decrypted_chunk[chunk_length];

		/* Check whether we understand the chunk delimiter */
		if (chunk_delimiter > IM_CHUNK_DELIMITER_MAX) {

			r = IM_ERR;
			goto fail_clean;
		}

		/*
		 * Computes the padding length even though this might not be the
		 * final chunk in a message or there might not be any padding. This
		 * serves as a precaution to not leaking timing information.
		 * If this is not the final chunk, the padding length is 0.
		 */
		if (im_padding_length_decrypt(decrypted_chunk, chunk_length,
			chunk_delimiter, &padding_length) == IM_ERR) {

			r = IM_ERR;
			goto fail_clean;
		}

		/*
		 * Updates decryption state variables to reflect we have decrypted
		 * another chunk
		 */
		im_ctx->src_processed = im_ctx->src_processed + (ciphertext_length + mactag_length);
		this_src_processed = this_src_processed + (ciphertext_length + mactag_length);

		/* Checks if the decryption buffer can store another chunk */
		if ((decrypt_buffer_offset + chunk_length - padding_length) >
			IM_DECRYPTION_BUFFER_LENGTH) {

			r = IM_ERR;
			goto fail_clean;
		}

		/* Copies the decrypted chunk to the decryption_buffer */
		memcpy(decryption_buffer + decrypt_buffer_offset, decrypted_chunk,
			chunk_length - padding_length);
		im_ctx->decrypt_buffer_offset = decrypt_buffer_offset
				+ chunk_length - padding_length;

		/*
		 * If chunk counter overflows make sure to fail. If we reach this
		 * point we have more chunks to process.
		 */
		if ((uint32_t) (chunk_counter + 1) < (uint32_t) chunk_counter) {

			counter_fail = 1;
		}
		im_ctx->chunk_counter = chunk_counter + 1;

		/*
		 * If chunk delimiter is greater than 0x00 then we have processed the
		 * final chunk.
		 */
		if (chunk_delimiter > 0x00) {
			break;
		}
	}

	/*
	 * Check if message counter overflows.
	 * Error if encryption function is called again.
	 */
	if ((uint64_t) (message_counter + 1) < (uint64_t) message_counter) {
		im_ctx->fail = 1;
	}

	/* 
	 * Message decrypted.
	 * Set result pointer to point to the message decrypted, 
	 * communicate its length, update counters and reset for next message.
	 */
	*ct_length = im_ctx->src_processed;
	*size_decrypted_ciphertext = im_ctx->decrypt_buffer_offset;
	im_ctx->message_counter = message_counter + 1;
	im_ctx->decrypt_buffer_offset = 0;
	im_ctx->chunk_counter = 0;
	im_ctx->src_processed = 0;

fail_clean:
	if (decrypted_chunk != NULL) {
		memset(decrypted_chunk, 0, chunk_length + 1);
		free(decrypted_chunk);
	}
	if (expected_tag != NULL) {
		free(expected_tag);
	}
	/* TODO: Should clean already decrypted ciphertext if fail */

	return r;
}

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
int im_cleanup(struct intermac_ctx *im_ctx) {

	if (im_ctx == NULL) {
		return IM_ERR;
	}

	/* Clean ups internal InterMAC cipher contect  */
	if (im_ctx->im_c_ctx != NULL) {

		/* Clean ups chosen cipher context */
		if (im_ctx->im_c_ctx->cipher != NULL) {
			im_ctx->im_c_ctx->cipher->cleanup(&im_ctx->im_c_ctx->im_cs_ctx);
			/* TODO Should NULL const pointer? */
			im_ctx->im_c_ctx->cipher = NULL;
		}

		/* Zeroises any chosen cipher internals */
		if (&im_ctx->im_c_ctx->im_cs_ctx != NULL) {
			im_explicit_bzero(&im_ctx->im_c_ctx->im_cs_ctx,
				sizeof(im_ctx->im_c_ctx->im_cs_ctx));
		}

		/* Zeroises and clean ups the InterMAC cipher context */
		im_explicit_bzero(im_ctx->im_c_ctx, sizeof(*im_ctx->im_c_ctx));
		free(im_ctx->im_c_ctx);
		im_ctx->im_c_ctx = NULL;
	}

	/* Zeroises and clean ups decryption buffer */
	if (im_ctx->decryption_buffer != NULL) {
		im_explicit_bzero(im_ctx->decryption_buffer,
			IM_DECRYPTION_BUFFER_LENGTH * sizeof(u_char));
		free(im_ctx->decryption_buffer);
		im_ctx->decryption_buffer = NULL;
	}

	im_explicit_bzero(im_ctx->queue_msg_size,
		sizeof(u_char) * IM_MAX_MSG_SIZES_BUFFERED);

	/* Zeroises and clean ups the InterMAC context */
	im_explicit_bzero(im_ctx, sizeof(*im_ctx));
	free(im_ctx);
	im_ctx = NULL;

	return IM_OK;
}

/* TODO move to unit tests */
void im_dump_data(const void *s, size_t len, FILE *f) {

	size_t i, j;
	const u_char *p = (const u_char *)s;

	for (i = 0; i < len; i += 16) {
		fprintf(f, "%.4zu: ", i);
		for (j = i; j < i + 16; j++) {
			if (j < len)
				fprintf(f, "%02x ", p[j]);
			else
				fprintf(f, "   ");
		}
		fprintf(f, " ");
		for (j = i; j < i + 16; j++) {
			if (j < len) {
				if  (isascii(p[j]) && isprint(p[j]))
					fprintf(f, "%c", p[j]);
				else
					fprintf(f, ".");
			}
		}
		fprintf(f, "\n");
	}
}
