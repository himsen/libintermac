/* Unit tests */

#include <stdio.h>
#include <string.h>

#include "../im_core.h"

#define FREESAFE(x) if (x != NULL) free(x);

int im_test1(u_int key_length, u_int chunk_length, char *cipher) {

	struct intermac_ctx *im_encrypt_ctx = NULL;
	struct intermac_ctx *im_decrypt_ctx = NULL;
	u_char *enckey = NULL;
	u_char *dst = NULL;
	u_char *src = NULL;
	u_int src_length = 0;
	u_int dst_length = 0;
	u_char decrypted_packet[1024 * 1024];
	u_int total_src_processed = 0;
	u_int total_cts_decrypted = 0;
	u_int length_decrypted_packet = 0;

	int r = 0;

	fprintf(stderr, "\nTrying %s\n\n", cipher);

	/* Use static key of zero's */
	enckey = calloc(1, sizeof(u_char)*key_length);
	src = (u_char *) "abcdefghijklmno";
	src_length = strlen((const char *)src);
	dst_length = 0;

	fprintf(stderr, "***ENCRYPTING\n");

	fprintf(stderr, "key:\n");
	im_dump_data(enckey, key_length, stderr);
	fprintf(stderr, "src buffer:\n");
	im_dump_data(src, src_length, stderr);

	if (im_initialise(&im_encrypt_ctx, enckey, chunk_length, cipher,
		IM_CIPHER_ENCRYPT) != 0) {
		fprintf(stderr, "Encryption: im_initialise() failed\n");
		goto fail;
	}

	if (im_encrypt(im_encrypt_ctx, &dst, &dst_length, src, src_length) != 0) {
		fprintf(stderr, "Encryption: im_encrypt() failed\n");
		goto fail;
	}

	fprintf(stderr, "dst buffer:\n");
	im_dump_data(dst, dst_length, stderr);

	im_cleanup(im_encrypt_ctx);

	fprintf(stderr, "***DECRYPTING\n");

	if (im_initialise(&im_decrypt_ctx, enckey, chunk_length, cipher,
		IM_CIPHER_DECRYPT) != 0) {
		fprintf(stderr, "Decryption: im_initialise() failed\n");
		goto fail;
	}

	if (im_decrypt(im_decrypt_ctx, (const u_char *) dst, dst_length,
		decrypted_packet, 1024 * 1024, &total_src_processed, &total_cts_decrypted) != 0) {
		fprintf(stderr, "Decryption: im_decrypt() failed\n");
		goto fail;
	}

	if (im_dequeue_msg_size(im_decrypt_ctx, &length_decrypted_packet) != 0) {
		fprintf(stderr, "Decryption: im_dequeue_msg_size() failed\n");
		goto fail;
	}

	fprintf(stderr, "decrypted_packet:\n");
	im_dump_data(decrypted_packet, length_decrypted_packet, stderr);

	if (src_length != length_decrypted_packet) {
		fprintf(stderr, "Length check failsrc length not the same as decrypted length\n");
		goto fail;
	}
	if (memcmp(src, decrypted_packet, src_length) != 0) {
		fprintf(stderr, "Comparison check failed src data not the same as decrypted data\n");
		goto fail;
	}
	
	im_cleanup(im_decrypt_ctx);

	r = 1;

fail:
	FREESAFE(dst)
	FREESAFE(enckey)

	return r;
}

int im_test2(u_int key_length, u_int chunk_length, char *cipher) {

	struct intermac_ctx *im_encrypt_ctx = NULL;
	struct intermac_ctx *im_decrypt_ctx = NULL;
	u_char *enckey = NULL;
	u_char *dst = NULL;
	u_char *src = NULL;
	u_int src_length = 0;
	u_int dst_length = 0;
	u_char decrypted_packet[1024 * 1024];
	u_int total_src_processed = 0;
	u_int total_cts_decrypted = 0;
	u_int length_decrypted_packet = 0;

	int r = 0;

	fprintf(stderr, "\nTrying %s\n\n", cipher);

	#define TEST2_SRC_LENGTH 200
	/* Use static key of zero's */
	enckey = calloc(1, sizeof(u_char)*key_length);
	src = calloc(1, sizeof(u_char) * TEST2_SRC_LENGTH);
	int i = 0;
	for(; i < TEST2_SRC_LENGTH; i += 10) {
		memcpy(src + i, "abcdefghij", 10);
	}
	src_length = TEST2_SRC_LENGTH;
	dst_length = 0;

	fprintf(stderr, "***ENCRYPTING\n");

	fprintf(stderr, "key:\n");
	im_dump_data(enckey, key_length, stderr);
	fprintf(stderr, "src buffer:\n");
	im_dump_data(src, src_length, stderr);

	if (im_initialise(&im_encrypt_ctx, enckey, chunk_length, cipher,
		IM_CIPHER_ENCRYPT) != 0) {
		fprintf(stderr, "Encryption: im_initialise() failed\n");
		goto fail;
	}

	if (im_encrypt(im_encrypt_ctx, &dst, &dst_length, src, src_length) != 0) {
		fprintf(stderr, "Encryption: im_encrypt() failed\n");
		goto fail;
	}

	fprintf(stderr, "dst buffer:\n");
	im_dump_data(dst, dst_length, stderr);

	im_cleanup(im_encrypt_ctx);

	fprintf(stderr, "***DECRYPTING\n");

	if (im_initialise(&im_decrypt_ctx, enckey, chunk_length, cipher,
		IM_CIPHER_DECRYPT) != 0) {
		fprintf(stderr, "Decryption: im_initialise() failed\n");
		goto fail;
	}

	if (im_decrypt(im_decrypt_ctx, (const u_char *) dst, dst_length,
		decrypted_packet, 1024 * 1024, &total_src_processed, &total_cts_decrypted) != 0) {
		fprintf(stderr, "Decryption: im_decrypt() failed\n");
		goto fail;
	}

	if (im_dequeue_msg_size(im_decrypt_ctx, &length_decrypted_packet) != 0) {
		fprintf(stderr, "Decryption: im_dequeue_msg_size() failed\n");
		goto fail;
	}

	fprintf(stderr, "decrypted_packet:\n");
	im_dump_data(decrypted_packet, length_decrypted_packet, stderr);

	if (src_length != length_decrypted_packet) {
		fprintf(stderr, "Length check failsrc length not the same as decrypted length\n");
		goto fail;
	}
	if (memcmp(src, decrypted_packet, src_length) != 0) {
		fprintf(stderr, "Comparison check failed src data not the same as decrypted data\n");
		goto fail;
	}

	im_cleanup(im_decrypt_ctx);

	r = 1;

fail:
	FREESAFE(src)
	FREESAFE(dst)
	FREESAFE(enckey)

	return r;
}

int im_test3(u_int key_length, u_int chunk_length, char *cipher) {

	struct intermac_ctx *im_encrypt_ctx = NULL;
	struct intermac_ctx *im_decrypt_ctx = NULL;
	u_char *enckey = NULL;
	u_char *dst = NULL;
	u_char *src = NULL;
	u_int src_length = 0;
	u_int dst_length = 0;
	u_char decrypted_packet[1024 * 1024];
	u_int total_src_processed = 0;
	u_int total_cts_decrypted = 0;
	u_int length_decrypted_packet = 0;

	int r = 0;

	fprintf(stderr, "\nTrying %s\n\n", cipher);

	#define TEST3_SRC_LENGTH 200
	/* Use static key of zero's */
	enckey = calloc(1, sizeof(u_char)*key_length);
	src = calloc(1, sizeof(u_char) * TEST3_SRC_LENGTH);
	int i = 0;
	for(; i < TEST3_SRC_LENGTH; i += 10) {
		memcpy(src + i, "abcdefghij", 10);
	}
	src_length = TEST3_SRC_LENGTH;
	dst_length = 0;

	fprintf(stderr, "***ENCRYPTING\n");

	fprintf(stderr, "key:\n");
	im_dump_data(enckey, key_length, stderr);
	fprintf(stderr, "src buffer:\n");
	im_dump_data(src, src_length, stderr);

	if (im_initialise(&im_encrypt_ctx, enckey, chunk_length, cipher,
		IM_CIPHER_ENCRYPT) != 0) {
		fprintf(stderr, "Encryption: im_initialise() failed\n");
		goto fail;
	}

	if (im_encrypt(im_encrypt_ctx, &dst, &dst_length, src, src_length) != 0) {
		fprintf(stderr, "Encryption: im_encrypt() failed\n");
		goto fail;
	}

	fprintf(stderr, "dst buffer:\n");
	im_dump_data(dst, dst_length, stderr);

	im_cleanup(im_encrypt_ctx);

	fprintf(stderr, "***DECRYPTING\n");

	if (im_initialise(&im_decrypt_ctx, enckey, chunk_length, cipher,
		IM_CIPHER_DECRYPT) != 0) {
		fprintf(stderr, "Decryption: im_initialise() failed\n");
		goto fail;
	}

	if (im_decrypt(im_decrypt_ctx, (const u_char *) dst, 100,
		decrypted_packet, 1024 * 1024, &total_src_processed, &total_cts_decrypted) != 0) {
		fprintf(stderr, "Decryption: im_decrypt() failed\n");
		goto fail;		
	}

	if (im_decrypt(im_decrypt_ctx, (const u_char *) dst, dst_length,
		decrypted_packet, 1024 * 1024, &total_src_processed, &total_cts_decrypted) != 0) {
		fprintf(stderr, "Decryption: im_decrypt() failed\n");
		goto fail;		
	}

	if (im_dequeue_msg_size(im_decrypt_ctx, &length_decrypted_packet) != 0) {
		fprintf(stderr, "Decryption: im_dequeue_msg_size() failed\n");
		goto fail;
	}

	fprintf(stderr, "decrypted_packet:\n");
	im_dump_data(decrypted_packet, length_decrypted_packet, stderr);

	if (src_length != length_decrypted_packet) {
		fprintf(stderr, "Length check failsrc length not the same as decrypted length\n");
		goto fail;
	}
	if (memcmp(src, decrypted_packet, src_length) != 0) {
		fprintf(stderr, "Comparison check failed src data not the same as decrypted data\n");
		goto fail;
	}

	im_cleanup(im_decrypt_ctx);

	r = 1;

fail:
	FREESAFE(src)
	FREESAFE(dst)
	FREESAFE(enckey)

	return r;
}

int im_test4(u_int key_length, u_int chunk_length, char *cipher) {

	struct intermac_ctx *im_encrypt_ctx = NULL;
	struct intermac_ctx *im_decrypt_ctx = NULL;
	u_char *enckey = NULL;
	u_char *dst = NULL;
	u_char *_dst = NULL;
	u_char *src = NULL;
	u_char *_src = NULL;
	u_int src_length = 0;
	u_int _src_length = 0;
	u_int dst_length = 0;
	u_int _dst_length = 0;
	u_char decrypted_packet[1024 * 1024];
	u_int total_src_processed = 0;
	u_int total_cts_decrypted = 0;
	u_int length_decrypted_packet = 0;
	u_int _length_decrypted_packet = 0;
	u_char *ct_combined = NULL;

	int r = 0;

	fprintf(stderr, "\nTrying %s\n\n", cipher);

	#define TEST4_SRC_LENGTH 200
	#define TEST4__SRC_LENGTH 100
	/* Use static key of zero's */
	enckey = calloc(1, sizeof(u_char)*key_length);
	src = calloc(1, sizeof(u_char) * TEST4_SRC_LENGTH);
	_src = calloc(1, sizeof(u_char) * TEST4__SRC_LENGTH);
	int i = 0;
	for(i = 0; i < TEST3_SRC_LENGTH; i += 10) {
		memcpy(src + i, "abcdefghij", 10);
	}
	src_length = TEST4_SRC_LENGTH;
	for(i = 0; i < TEST4__SRC_LENGTH; i += 10) {
		memcpy(_src + i, "abcdefghij", 10);
	}
	_src_length = TEST4__SRC_LENGTH;
	dst_length = 0;

	fprintf(stderr, "***ENCRYPTING\n");

	fprintf(stderr, "key:\n");
	im_dump_data(enckey, key_length, stderr);
	fprintf(stderr, "src buffer:\n");
	im_dump_data(src, src_length, stderr);
	fprintf(stderr, "_src buffer:\n");
	im_dump_data(_src, _src_length, stderr);

	if (im_initialise(&im_encrypt_ctx, enckey, chunk_length, cipher,
		IM_CIPHER_ENCRYPT) != 0) {
		fprintf(stderr, "Encryption: im_initialise() failed\n");
		goto fail;
	}

	if (im_encrypt(im_encrypt_ctx, &dst, &dst_length, src, src_length) != 0) {
		fprintf(stderr, "Encryption: im_encrypt() failed\n");
		goto fail;
	}

	if (im_encrypt(im_encrypt_ctx, &_dst, &_dst_length, _src, _src_length) != 0) {
		fprintf(stderr, "Encryption: im_encrypt() failed\n");
		goto fail;
	}


	fprintf(stderr, "dst buffer:\n");
	im_dump_data(dst, dst_length, stderr);
	fprintf(stderr, "_dst buffer:\n");
	im_dump_data(_dst, _dst_length, stderr);

	im_cleanup(im_encrypt_ctx);

	ct_combined = calloc(1, sizeof(u_char) * (_dst_length + dst_length));
	memcpy(ct_combined, dst, dst_length);
	memcpy(ct_combined + dst_length, _dst, _dst_length);

	fprintf(stderr, "ct_combined:\n");
	im_dump_data(ct_combined, dst_length + _dst_length, stderr);

	fprintf(stderr, "***DECRYPTING\n");

	if (im_initialise(&im_decrypt_ctx, enckey, chunk_length, cipher,
		IM_CIPHER_DECRYPT) != 0) {
		fprintf(stderr, "Decryption: im_initialise() failed\n");
		goto fail;
	}

	if (im_decrypt(im_decrypt_ctx, (const u_char *) ct_combined, 150,
		decrypted_packet, 1024 * 1024, &total_src_processed, &total_cts_decrypted) != 0) {
		fprintf(stderr, "Decryption 1: im_decrypt() failed\n");
		goto fail;		
	}

	if (total_cts_decrypted > 0 && total_src_processed > 0) {
		fprintf(stderr, "Should not happen...\n");
		goto fail;
	}

	if (im_decrypt(im_decrypt_ctx, (const u_char *) ct_combined + total_src_processed, dst_length + _dst_length,
		decrypted_packet, 1024 * 1024, &total_src_processed, &total_cts_decrypted) != 0) {
		fprintf(stderr, "Decryption 2: im_decrypt() failed\n");
		goto fail;		
	}

	if (im_dequeue_msg_size(im_decrypt_ctx, &length_decrypted_packet) != 0) {
		fprintf(stderr, "Decryption 1: im_dequeue_msg_size() failed\n");
		goto fail;
	}

	if (im_dequeue_msg_size(im_decrypt_ctx, &_length_decrypted_packet) != 0) {
		fprintf(stderr, "Decryption 2: im_dequeue_msg_size() failed\n");
		goto fail;
	}

	fprintf(stderr, "decrypted_packet:\n");
	im_dump_data(decrypted_packet, length_decrypted_packet, stderr);

	fprintf(stderr, " next decrypted_packet:\n");
	im_dump_data(decrypted_packet + length_decrypted_packet, _length_decrypted_packet, stderr);

	if (src_length != length_decrypted_packet) {
		fprintf(stderr, "Length check failsrc length not the same as decrypted length\n");
		goto fail;
	}
	if (memcmp(src, decrypted_packet, src_length) != 0) {
		fprintf(stderr, "Comparison check failed src data not the same as decrypted data\n");
		goto fail;
	}

	if (_src_length != _length_decrypted_packet) {
		fprintf(stderr, "Length check fail _src length not the same as decrypted length\n");
		goto fail;
	}
	if (memcmp(_src, decrypted_packet + length_decrypted_packet, _src_length) != 0) {
		fprintf(stderr, "Comparison check failed _src data not the same as decrypted data\n");
		goto fail;
	}

	im_cleanup(im_decrypt_ctx);

	r = 1;

fail:
	FREESAFE(src)
	FREESAFE(_src)
	FREESAFE(dst)
	FREESAFE(_dst)
	FREESAFE(enckey)

	return r;
}

int main(void) {

	u_int chunk_length = 64;
	u_int key_length_aesgcm = 16;
	u_int key_length_chachapoly = 32;
	
	fprintf(stderr, "Intermac unit tests start\n");

	//fprintf(stderr, "\n-----ChaCha20-Poly1305 one_enc_one_dec()-----\n\n");

	fprintf(stderr, "\n---Test 1---\n");

	if (im_test1(key_length_aesgcm, chunk_length, "im-aes128-gcm") != 1) {
		fprintf(stderr, "||||FAIL|||| im_test1() with im-aes128-gcm\n");
		return 0;
	}

	if (im_test1(key_length_chachapoly, chunk_length, "im-chacha-poly") != 1) {
		fprintf(stderr, "||||FAIL|||| im_test1 with im-chacha-poly\n");
		return 0;
	}

	fprintf(stderr, "\n---Test 2---\n");

	if (im_test2(key_length_aesgcm, chunk_length, "im-aes128-gcm") != 1) {
		fprintf(stderr, "||||FAIL|||| im_test2() with im-aes128-gcm\n");
		return 0;
	}

	if (im_test2(key_length_chachapoly, chunk_length, "im-chacha-poly") != 1) {
		fprintf(stderr, "||||FAIL|||| im_test2() with im-chacha-poly\n");
		return 0;
	}

	fprintf(stderr, "\n---Test 3---\n");

	if (im_test3(key_length_aesgcm, chunk_length, "im-aes128-gcm") != 1) {
		fprintf(stderr, "||||FAIL|||| im_test3() with im-aes128-gcm\n");
		return 0;
	}

	if (im_test3(key_length_chachapoly, chunk_length, "im-chacha-poly") != 1) {
		fprintf(stderr, "||||FAIL|||| im_test3() with im-chacha-poly\n");
		return 0;
	}

	fprintf(stderr, "\n---Test 4---\n");

	if (im_test4(key_length_aesgcm, chunk_length, "im-aes128-gcm") != 1) {
		fprintf(stderr, "||||FAIL|||| im_test4() with im-aes128-gcm\n");
		return 0;
	}

	if (im_test4(key_length_chachapoly, chunk_length, "im-chacha-poly") != 1) {
		fprintf(stderr, "||||FAIL|||| im_test4() with im-chacha-poly\n");
		return 0;
	}
	printf("Intermac unit tests done\n");

	return 0;
}