/*
 * Copyright (c) 2015 Red Hat, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <err.h>
#include <arpa/inet.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/conf.h>

static void display_openssl_errors(int l)
{
	const char *file;
	char buf[120];
	int e, line;

	if (ERR_peek_error() == 0)
		return;
	fprintf(stderr, "At main.c:%d:\n", l);

	while ((e = ERR_get_error_line(&file, &line))) {
		ERR_error_string(e, buf);
		fprintf(stderr, "- SSL %s: %s:%d\n", buf, file, line);
	}
}

int main(int argc, char **argv)
{
	char *hash_algo = NULL;
	char *private_key_name, *x509_name, *module_name, *dest_name;
	unsigned char buf[4096];
	const EVP_MD *digest_algo;
	EVP_PKEY *private_key, *pubkey;
	char *key_pass;
	X509 *x509;
	unsigned n;
	int ret;
	long errline;
	ENGINE *e;
	CONF *conf;
	EVP_MD_CTX ctx;
	const char *module_path;
	BIO *in, *b;

	if (argc < 4) {
		fprintf(stderr, "usage: %s [CONF] [private key URL] [module]\n", argv[0]);
		exit(1);
	}

	private_key_name = argv[2];
	module_path = argv[3];

	ret = CONF_modules_load_file(argv[1], "engines", 0);
	if (ret <= 0) {
		fprintf(stderr, "cannot load %s\n", argv[1]);
		display_openssl_errors(__LINE__);
		exit(1);
	}

	ENGINE_add_conf_module();
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	ERR_clear_error();

	ENGINE_load_builtin_engines();
	e = ENGINE_by_id("pkcs11");
	if (!e) {
		display_openssl_errors(__LINE__);
		exit(1);
	}

	if (!ENGINE_ctrl_cmd_string(e, "MODULE_PATH", module_path, 0)) {
		display_openssl_errors(__LINE__);
		exit(1);
	}

	if (!ENGINE_init(e)) {
		display_openssl_errors(__LINE__);
		exit(1);
	}

#if 0
	if (!ENGINE_ctrl_cmd_string(e, "PIN", key_pass, 0)) {
		display_openssl_errors(__LINE__);
		exit(1);
	}
#endif

	private_key = ENGINE_load_private_key(e, private_key_name, NULL, NULL);
	if (!private_key) {
		fprintf(stderr, "cannot load: %s\n", private_key_name);
		display_openssl_errors(__LINE__);
		exit(1);
	}

	x509_name = "cert.der";

	b = BIO_new_file(x509_name, "rb");
	if (!b) {
		fprintf(stderr, "error loading %s\n", x509_name);
		exit(1);
	}

	x509 = d2i_X509_bio(b, NULL);	/* Binary encoded X.509 */
	if (!x509) {
		BIO_reset(b);
		x509 = PEM_read_bio_X509(b, NULL, NULL, NULL);	/* PEM encoded X.509 */
	}
	BIO_free(b);

	if (!x509) {
		fprintf(stderr, "error loading cert %s\n", x509_name);
		exit(1);
	}
	pubkey = X509_get_pubkey(x509);

	/* Digest the module data. */
	OpenSSL_add_all_digests();
	display_openssl_errors(__LINE__);

	digest_algo = EVP_get_digestbyname("sha1");

	EVP_MD_CTX_init(&ctx);
	if (EVP_DigestInit(&ctx, digest_algo) <= 0) {
		display_openssl_errors(__LINE__);
		exit(1);
	}

	EVP_SignInit(&ctx, digest_algo);

#define TEST_DATA "test data"
	if (EVP_SignUpdate(&ctx, TEST_DATA, sizeof(TEST_DATA)) <= 0) {
		display_openssl_errors(__LINE__);
		exit(1);
	}

	n = sizeof(buf);
	if (EVP_SignFinal(&ctx, buf, &n, private_key) <= 0) {
		display_openssl_errors(__LINE__);
		exit(1);
	}

	EVP_MD_CTX_init(&ctx);
	if (EVP_DigestInit(&ctx, digest_algo) <= 0) {
		display_openssl_errors(__LINE__);
		exit(1);
	}

	if (EVP_DigestVerifyInit(&ctx, NULL, digest_algo, NULL, pubkey) <= 0) {
		display_openssl_errors(__LINE__);
		exit(1);
	}

	if (EVP_DigestVerifyUpdate(&ctx, TEST_DATA, sizeof(TEST_DATA)) <= 0) {
		display_openssl_errors(__LINE__);
		exit(1);
	}

	if (EVP_DigestVerifyFinal(&ctx, buf, n) <= 0) {
		display_openssl_errors(__LINE__);
		exit(1);
	}

	CONF_modules_unload(1);
	return 0;
}
