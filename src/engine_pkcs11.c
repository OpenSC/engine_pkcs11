/*
 * Copyright (c) 2002 Juha Yrjölä.  All rights reserved.
 * Copyright (c) 2001 Markus Friedl.
 * Copyright (c) 2002 Olaf Kirch
 * Copyright (c) 2003 Kevin Stefanik
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/engine.h>
#include <libp11.h>
#include "engine_pkcs11.h"

#ifdef _WIN32
#define strncasecmp strnicmp
#endif

#define fail(msg) { fprintf(stderr,msg); return NULL;}

/** The maximum length of an internally-allocated PIN */
#define MAX_PIN_LENGTH   32

static PKCS11_CTX *ctx;

int get_pin(UI_METHOD * ui_method, void *callback_data);

/**
 * The PIN used for login. Cache for the get_pin function.
 * The memory for this PIN is always owned internally,
 * and may be freed as necessary. Before freeing, the PIN
 * must be whitened, to prevent security holes.
 */
static PKCS11_PIN _pin =
{
	.pin = {
		.len = 0,
		.data = NULL
	},
	.get_pin = get_pin
};

void pkcs11_pin_clear(void)
{
	PKCS11_PIN_clear(&_pin);
}

static int verbose = 0;

static char *module = NULL;

static char *init_args = NULL;

int set_module(const char *modulename)
{
	module = modulename ? strdup(modulename) : NULL;
	return 1;
}

/**
 * Set the PIN used for login. A copy of the PIN shall be made.
 *
 * If the PIN cannot be assigned, the value 0 shall be returned
 * and errno shall be set as follows:
 *
 *   EINVAL - a NULL PIN was supplied
 *   ENOMEM - insufficient memory to copy the PIN
 *
 * @param _pin the pin to use for login. Must not be NULL.
 *
 * @return 1 on success, 0 on failure.
 */
int set_pin(const char *_ppin)
{
	PKCS11_PIN_clear(&_pin);
	return PKCS11_PIN_dup(&_pin, _ppin);
}

int inc_verbose(void)
{
	verbose++;
	return 1;
}

/* either get the pin code from the supplied callback data, or get the pin
 * via asking our self. In both cases keep a copy of the pin code in the
 * pin variable (strdup'ed copy). */
int get_pin(UI_METHOD * ui_method, void *callback_data)
{
	UI *ui;
	struct {
		const void *password;
		const char *prompt_info;
	} *mycb = callback_data;

	PKCS11_PIN_clear(&_pin);

	/* pin in the call back data, copy and use */
	if (mycb != NULL && mycb->password) {
		PKCS11_PIN_dup(&_pin, mycb->password);
		return 1;
	}

	PKCS11_PIN_alloc(&_pin);
	/* call ui to ask for a pin */
	ui = UI_new();
	if (ui_method != NULL)
		UI_set_method(ui, ui_method);
	if (callback_data != NULL)
		UI_set_app_data(ui, callback_data);

	if (!UI_add_input_string
	    (ui, "PKCS#11 token PIN: ", 0, _pin.pin.data, 1, MAX_PIN_LENGTH)) {
		fprintf(stderr, "UI_add_input_string failed\n");
		UI_free(ui);
		return 0;
	}
	if (UI_process(ui)) {
		fprintf(stderr, "UI_process failed\n");
		UI_free(ui);
		return 0;
	}
	UI_free(ui);
	return 1;
}

int set_init_args(const char *init_args_orig)
{
	init_args = init_args_orig ? strdup(init_args_orig) : NULL;
	return 1;
}

int pkcs11_finish(ENGINE *e)
{
	(void)e;
	if (ctx) {
		PKCS11_CTX_unload(ctx);
		PKCS11_CTX_free(ctx);
		ctx = NULL;
	}
	return 1;
}

int pkcs11_init(ENGINE *e)
{
	(void)e;
	if (verbose) {
		fprintf(stderr, "initializing engine\n");
	}
	ctx = PKCS11_CTX_new();
        PKCS11_CTX_init_args(ctx, init_args);
	if (PKCS11_CTX_load(ctx, module) < 0) {
		fprintf(stderr, "unable to load module %s\n", module);
		return 0;
	}
	return 1;
}

int load_cert_ctrl(ENGINE * e, void *p)
{
	(void)e;
	struct {
		const char *s_slot_cert_id;
		X509 *cert;
	} *parms = p;

	if (parms->cert != NULL)
		return 0;

	parms->cert = PKCS11_load_cert(ctx, parms->s_slot_cert_id, verbose);
	if (parms->cert == NULL)
		return 0;

	return 1;
}


EVP_PKEY *pkcs11_load_public_key(ENGINE * e, const char *s_key_id,
				 UI_METHOD * ui_method, void *callback_data)
{
	(void)e;
	EVP_PKEY *pk;

	pk = PKCS11_load_key(ctx, s_key_id, &_pin, ui_method, callback_data, 0, verbose);
	if (pk == NULL)
		fail("PKCS11_load_public_key returned NULL\n");
	return pk;
}

EVP_PKEY *pkcs11_load_private_key(ENGINE * e, const char *s_key_id,
				  UI_METHOD * ui_method, void *callback_data)
{
	(void)e;
	EVP_PKEY *pk;

	pk = PKCS11_load_key(ctx, s_key_id, &_pin, ui_method, callback_data, 1, verbose);
	if (pk == NULL)
		fail("PKCS11_get_private_key returned NULL\n");
	return pk;
}


