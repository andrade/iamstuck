// Commented out all (f)printf calls because of SGX

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <time.h> // prevent `error: unknown type name ‘time_t’` in ssl.h
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/sha256.h>

// #include "km.h"
#include "km_fixed.h"

// TODO Assume signed object. Want to 1) verify chain, 2) compare match root certificate (with hardcoded/buffer certificate or public key), 3) hash object, 4) verify signature and if hashes match


// Computes the hash of `data` and stores the encoded signature in `output`.
// Returns zero on success, or non-zero otherwise.
int compute_hash(byte *output, const void *data, size_t size)
{
	uint8_t hash[WC_SHA256_DIGEST_SIZE] = {0};
	wc_Sha256 sha256;

	if (wc_InitSha256(&sha256)) {
		return 11;
	}

	if (wc_Sha256Update(&sha256, data, size)) {
		return 12;
	}

	if (wc_Sha256Final(&sha256, hash)) {
		return 13;
	}

	// byte encodedSig[MAX_ENCODED_SIG_SZ] = {0};
	// int r = wc_EncodeSignature(encodedSig, hash, sizeof hash, SHA256h);
	int r = wc_EncodeSignature(output, hash, sizeof hash, SHA256h);
	if (r <= 0) {
		return 14;
	}

	return 0;
}

// Extracts the RSA public key from a PEM certificate and stores it in `key`.
// Caller allocates and frees the `key` object.
// The PEM certificate is in `cert` with size `size`.
// Returns zero on success, or non-zero otherwise.
int get_rsa_pubkey_from_pem_cert(RsaKey *key, const void *cert, size_t size)
{
	int r;

	unsigned char cert_der[16384] = {0};
	struct DecodedCert decoded_cert = {0};
	byte key_der[8192] = {0};
	word32 key_der_size = sizeof(key_der);

	// convert certificate from PEM to DER
	int cert_der_size = wc_CertPemToDer(cert, size, cert_der, sizeof cert_der, CERT_TYPE);
	if (cert_der_size <= 0) {
		// fprintf(stderr, "Failure: wc_CertPemToDer\n");
		return 1;
	}

	wc_InitDecodedCert(&decoded_cert, cert_der, cert_der_size, NULL);
	r = wc_ParseCert(&decoded_cert, SSL_FILETYPE_ASN1, NO_VERIFY, NULL);
	if (r) {
		// fprintf(stderr, "Failure: wc_ParseCert\n");
		return 2;
	}

	// certificate to DER public key buffer
	r = wc_GetPubKeyDerFromCert(&decoded_cert, key_der, &key_der_size);
	if (r) {
		// fprintf(stderr, "Failure: wc_GetPubKeyDerFromCert\n");
		return 3;
	}

	// DER public key buffer to RSA key structure
	word32 inOutIdx = 0;
	r = wc_RsaPublicKeyDecode(key_der, &inOutIdx, key, key_der_size);
	if (r) {
		// fprintf(stderr, "Failure: wc_RsaPublicKeyDecode\n");
		return 4;
	}

	wc_FreeDecodedCert(&decoded_cert);

	return 0;
}

int verify_signature()
{
	int r;

	// 1. compute hash
	byte computed_sig[MAX_ENCODED_SIG_SZ] = {0};
	r = compute_hash(computed_sig, msg, strlen(msg));
	// printf("compute_hash, r = %d\n", r);
	if (r) {
		// fprintf(stderr, "Failure: compute_hash\n");
		return 1;
	}

	// 2. retrieve public key from leaf (signing) certificate
	RsaKey key;
	r = wc_InitRsaKey(&key, NULL);
	if (r) {
		// fprintf(stderr, "Failure: RSA key init\n");
		return 21;
	}
	r = get_rsa_pubkey_from_pem_cert(&key, inter2_buf, sizeof inter2_buf);
	// printf("get_rsa_pubkey_from_pem_cert, r = %d\n", r);
	if (r) {
		// fprintf(stderr, "Failure: get_rsa_pubkey_from_pem_cert\n");
		return 2;
	}

	// 3. verify signature with public key and hash
	byte decrypted_sig[MAX_ENCODED_SIG_SZ] = {0};
	int decsiglen = wc_RsaSSL_Verify(original_sig, sizeof original_sig,
			decrypted_sig, sizeof decrypted_sig, &key);
	if (decsiglen < 0) {
		// fprintf(stderr, "Failure: wc_RsaSSL_VerifyInline (%d)\n", r);
		return 3;
	}

	// for (int i = 0; i < decsiglen; i++) {
	// 	printf("%02x ", decrypted_sig[i]);
	// }
	// printf("\n");

	wc_FreeRsaKey(&key);

	// 4. compare computed signature with received signature
	return memcmp(computed_sig, decrypted_sig, decsiglen);

	return 0;
}

void dump_last_wc_error()
{
	unsigned long e = wolfSSL_ERR_peek_last_error();
	char buf[WOLFSSL_MAX_ERROR_SZ] = {0};
	char *error = wolfSSL_ERR_error_string(e, buf);
	// fprintf(stderr, "wolfSSL last error: %s (%ld)\n", error, e);
}

// Returns zero on success, or non-zero otherwise.
int validate_cert_chain()
{
	int r;


	// load the root certificate
	WOLFSSL_X509 *root_cert = wolfSSL_X509_load_certificate_buffer(
			ca_buf, sizeof ca_buf, WOLFSSL_FILETYPE_PEM);
	if (root_cert == NULL) {
		// fprintf(stderr, "peek: %ld\n", wolfSSL_ERR_peek_last_error());
		// fprintf(stderr, "Failure: wolfSSL_X509_load_certificate_buffer\n");
		dump_last_wc_error();
		return 1;
	}

	// add the root certificate to the store
	WOLFSSL_X509_STORE *store = wolfSSL_X509_STORE_new();
	r = wolfSSL_X509_STORE_add_cert(store, root_cert);
	if (r != WOLFSSL_SUCCESS) {
		// fprintf(stderr, "Failure: wolfSSL_X509_STORE_add_cert\n");
		// TODO release resources: root certificate, and store
		return 2;
	}


	// load intermediate certificate 1
	WOLFSSL_X509 *inter1 = wolfSSL_X509_load_certificate_buffer(
			inter1_buf, sizeof inter1_buf, WOLFSSL_FILETYPE_PEM);
	if (inter1 == NULL) {
		// fprintf(stderr, "Failure: wolfSSL_X509_load_certificate_buffer\n");
		// TODO release resources
		return 3;
	}

	// add intermediate certificate to stack of intermediate certificates
	STACK_OF(WOLFSSL_X509) *chain = wolfSSL_sk_X509_new_null();
	wolfSSL_sk_X509_push(chain, inter1);

	// load more intermediate certificates... (only have one in this example)


	// load leaf certificate
	WOLFSSL_X509 *leaf = wolfSSL_X509_load_certificate_buffer(
			inter2_buf, sizeof inter2_buf, WOLFSSL_FILETYPE_PEM);
	if (leaf == NULL) {
		// fprintf(stderr, "Failure: wolfSSL_X509_load_certificate_buffer\n");
		// TODO release resources
		return 4;
	}


	WOLFSSL_X509_STORE_CTX *ctx = wolfSSL_X509_STORE_CTX_new();
	if (ctx == NULL) {
		// fprintf(stderr, "Failure: wolfSSL_X509_STORE_CTX_new\n");
		// TODO release resources
		return 5;
	}

	// Explaining `wolfSSL_X509_STORE_CTX_init` (no docs!?):
	// - the store holds the trusted certificates,
	// - the x509/leaf is the leaf certificate to verify,
	// - the stack/chain holds the intermediate certificates.
	// In addition (from what I tried):
	// - The stack can be NULL when verifying only one or two certificates.
	// - The leaf argument could be a root certificate in the store.
	// - The leaf argument could be an intermediate certificate signed by
	//   a root certificate that is added to the store. This intermediate
	//   certificate, when there are 3+ certificates, is stored in the chain.
	//
	// Prepare to verify root. (What's the point? maybe check if well-formed?)
	// r = wolfSSL_X509_STORE_CTX_init(ctx, store, root_cert, NULL);
	// Prepare to verify only intermediate.
	// r = wolfSSL_X509_STORE_CTX_init(ctx, store, inter1, NULL);
	// Prepare to verify the full chain from root to leaf.
	r = wolfSSL_X509_STORE_CTX_init(ctx, store, leaf, chain);
	// This one fails because attempting to verify leaf with intermediates.
	// r = wolfSSL_X509_STORE_CTX_init(ctx, store, leaf, NULL);
	if (r != WOLFSSL_SUCCESS) {
		// fprintf(stderr, "Failure: wolfSSL_X509_STORE_CTX_init\n");
		// TODO release resources
		return 6;
	}

	r = wolfSSL_X509_verify_cert(ctx);
	if (r != WOLFSSL_SUCCESS) {
		// fprintf(stderr, "Failure: wolfSSL_X509_verify_cert\n");
		// TODO release resources
		return 7;
	}


	wolfSSL_X509_STORE_free(store);
	wolfSSL_X509_free(root_cert);
	wolfSSL_X509_free(inter1);
	wolfSSL_X509_free(leaf);
	wolfSSL_sk_X509_free(chain);
	wolfSSL_X509_STORE_CTX_free(ctx);

	return 0;
}

#if 0
int main()
{
	int r = validate_cert_chain();
	printf("validate_cert_chain, r = %d\n", r);

	// byte computed_sig[MAX_ENCODED_SIG_SZ] = {0};
	// r = compute_hash(computed_sig, msg, strlen(msg));
	// printf("compute_hash, r = %d\n", r);

	// RsaKey key;
	// r = get_rsa_pubkey_from_pem_cert(&key, inter2_buf, sizeof inter2_buf);
	// printf("get_rsa_pubkey_from_pem_cert, r = %d\n", r);

	r = verify_signature();
	printf("verify_signature, r = %d\n", r);

	// // TEMP Função que existe no 5.8.2 mas não na versão nos repos do 24.04
	// wc_GetSubjectPubKeyInfoDerFromCert(NULL, 0, NULL, 0);

	return EXIT_SUCCESS;
}
#endif

// $ gcc -g -Wall -Wextra -o chain_verify chain_verify.c -lwolfssl && ./chain_verify

//$ gcc -g -Wall -Wextra -I $WOLFSSL_ROOT -L $WOLFSSL_ROOT/src/.libs/ -o chain_verify chain_verify.c -l wolfssl && ./chain_verify
