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

/** 
 * The PIN used for login. Cache for the get_pin function.
 * The memory for this PIN is always owned internally,
 * and may be freed as necessary. Before freeing, the PIN 
 * must be whitened, to prevent security holes.
 *
 * length is always MAX_PIN_LENGTH and possibly not 0 terminated?
 */
static char *pin = NULL;

static int verbose = 0;

static char *module = NULL;

int set_module(const char *modulename)
{
	module = strdup(modulename);
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
int set_pin(const char *_pin)
{
	/* Pre-condition check */
	if (_pin == NULL) {
		errno = EINVAL;
		return 0;
	}

	/* Copy the PIN. If the string cannot be copied, NULL
	   shall be returned and errno shall be set. */
	pin = strdup(_pin);

	return (pin != NULL);
}

int inc_verbose(void)
{
	verbose++;
	return 1;
}

/* either get the pin code from the supplied callback data, or get the pin
 * via asking our self. In both cases keep a copy of the pin code in the
 * pin variable (strdup'ed copy). */
static int get_pin(UI_METHOD * ui_method, void *callback_data)
{
	UI *ui;
	struct {
		const void *password;
		const char *prompt_info;
	} *mycb = callback_data;

	/* pin in the call back data, copy and use */
	if (mycb->password) {
		pin = (char *)calloc(MAX_PIN_LENGTH, sizeof(char));
		if (!pin)
			return 0;
		strncpy(pin,mycb->password,MAX_PIN_LENGTH);
		return 1;
	}

	/* call ui to ask for a pin */
	ui = UI_new();
	if (ui_method != NULL)
		UI_set_method(ui, ui_method);
	if (callback_data != NULL)
		UI_set_app_data(ui, callback_data);

	if (!UI_add_input_string
	    (ui, "PKCS#11 token PIN: ", 0, pin, 1, MAX_PIN_LENGTH)) {
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

int pkcs11_finish(ENGINE * engine)
{
	if (ctx) {
		PKCS11_CTX_unload(ctx);
		PKCS11_CTX_free(ctx);
		ctx = NULL;
	}
	if (pin != NULL) {
		OPENSSL_cleanse(pin, MAX_PIN_LENGTH);
		free(pin);
		pin = NULL;
	}
	return 1;
}

int pkcs11_init(ENGINE * engine)
{
	if (verbose) {
		fprintf(stderr, "initializing engine\n");
	}
	ctx = PKCS11_CTX_new();
	if (PKCS11_CTX_load(ctx, module) < 0) {
		fprintf(stderr, "unable to load module %s\n", module);
		return 0;
	}
	return 1;
}

int pkcs11_rsa_finish(RSA * rsa)
{
	if (pin) {
		OPENSSL_cleanse(pin, MAX_PIN_LENGTH);
		free(pin);
		pin = NULL;
	}
	if (module) {
		free(module);
		module = NULL;
	}
	/* need to free RSA_ex_data? */
	return 1;
}

static int hex_to_bin(const char *in, unsigned char *out, size_t * outlen)
{
	size_t left, count = 0;

	if (in == NULL || *in == '\0') {
		*outlen = 0;
		return 1;
	}

	left = *outlen;

	while (*in != '\0') {
		int byte = 0, nybbles = 2;

		while (nybbles-- && *in && *in != ':') {
			char c;
			byte <<= 4;
			c = *in++;
			if ('0' <= c && c <= '9')
				c -= '0';
			else if ('a' <= c && c <= 'f')
				c = c - 'a' + 10;
			else if ('A' <= c && c <= 'F')
				c = c - 'A' + 10;
			else {
				fprintf(stderr,
					"hex_to_bin(): invalid char '%c' in hex string\n",
					c);
				*outlen = 0;
				return 0;
			}
			byte |= c;
		}
		if (*in == ':')
			in++;
		if (left <= 0) {
			fprintf(stderr, "hex_to_bin(): hex string too long\n");
			*outlen = 0;
			return 0;
		}
		out[count++] = (unsigned char)byte;
		left--;
	}

	*outlen = count;
	return 1;
}

/* parse string containing slot and id information */

static int parse_slot_id_string(const char *slot_id, int *slot,
				unsigned char *id, size_t * id_len,
				char **label)
{
	int n, i;

	if (!slot_id)
		return 0;

	/* support for several formats */
#define HEXDIGITS "01234567890ABCDEFabcdef"
#define DIGITS "0123456789"

	/* first: pure hex number (id, slot is 0) */
	if (strspn(slot_id, HEXDIGITS) == strlen(slot_id)) {
		/* ah, easiest case: only hex. */
		if ((strlen(slot_id) + 1) / 2 > *id_len) {
			fprintf(stderr, "id string too long!\n");
			return 0;
		}
		*slot = 0;
		return hex_to_bin(slot_id, id, id_len);
	}

	/* second: slot:id. slot is an digital int. */
	if (sscanf(slot_id, "%d", &n) == 1) {
		i = strspn(slot_id, DIGITS);

		if (slot_id[i] != ':') {
			fprintf(stderr, "could not parse string!\n");
			return 0;
		}
		i++;
		if (slot_id[i] == 0) {
			*slot = n;
			*id_len = 0;
			return 1;
		}
		if (strspn(slot_id + i, HEXDIGITS) + i != strlen(slot_id)) {
			fprintf(stderr, "could not parse string!\n");
			return 0;
		}
		/* ah, rest is hex */
		if ((strlen(slot_id) - i + 1) / 2 > *id_len) {
			fprintf(stderr, "id string too long!\n");
			return 0;
		}
		*slot = n;
		return hex_to_bin(slot_id + i, id, id_len);
	}

	/* third: id_<id>  */
	if (strncmp(slot_id, "id_", 3) == 0) {
		if (strspn(slot_id + 3, HEXDIGITS) + 3 != strlen(slot_id)) {
			fprintf(stderr, "could not parse string!\n");
			return 0;
		}
		/* ah, rest is hex */
		if ((strlen(slot_id) - 3 + 1) / 2 > *id_len) {
			fprintf(stderr, "id string too long!\n");
			return 0;
		}
		*slot = 0;
		return hex_to_bin(slot_id + 3, id, id_len);
	}

	/* label_<label>  */
	if (strncmp(slot_id, "label_", 6) == 0) {
		*label = strdup(slot_id + 6);
		return *label != NULL;
	}

	/* last try: it has to be slot_<slot> and then "-id_<cert>" */

	if (strncmp(slot_id, "slot_", 5) != 0) {
		fprintf(stderr, "format not recognized!\n");
		return 0;
	}

	/* slot is an digital int. */
	if (sscanf(slot_id + 5, "%d", &n) != 1) {
		fprintf(stderr, "slot number not deciphered!\n");
		return 0;
	}

	i = strspn(slot_id + 5, DIGITS);

        /*
         * changed 2008-01-28 9:31 GMT by SafeNet UK Ltd, akroehnert@safenet-inc.com
         * changed comparision from == to >= as we need to check for any slot equal
         * or greater zero
         */
	if (slot_id[i + 5] >= 0) {
		*slot = n;
		*id_len = 0;
	/*
	 * changed 2008-01-28 9:31 GMT by SafeNet UK Ltd, akroehnert@safenet-inc.com
      * if we jump out here we cant get the label or id parsed
	 */
	/*	return 1; */
	}

	if (slot_id[i + 5] != '-') {
		fprintf(stderr, "could not parse string!\n");
		return 0;
	}

	i = 5 + i + 1;

	/* now followed by "id_" */
	if (strncmp(slot_id + i, "id_", 3) == 0) {
		if (strspn(slot_id + i + 3, HEXDIGITS) + 3 + i !=
		    strlen(slot_id)) {
			fprintf(stderr, "could not parse string!\n");
			return 0;
		}
		/* ah, rest is hex */
		if ((strlen(slot_id) - i - 3 + 1) / 2 > *id_len) {
			fprintf(stderr, "id string too long!\n");
			return 0;
		}
		*slot = n;
		return hex_to_bin(slot_id + i + 3, id, id_len);
	}

	/* ... or "label_" */
	if (strncmp(slot_id + i, "label_", 6) == 0)
		/*
	         * changed 2008-01-28 9:31 CET by SafeNet UK Ltd, akroehnert@safenet-inc.com
        	 * we have to chop off + i + 6 characters instead of just 6
		 */
		return (*label = strdup(slot_id + i + 6)) != NULL;

	fprintf(stderr, "could not parse string!\n");
	return 0;
}

#define MAX_VALUE_LEN	200

/* prototype for OpenSSL ENGINE_load_cert */
/* used by load_cert_ctrl via ENGINE_ctrl for now */

static X509 *pkcs11_load_cert(ENGINE * e, const char *s_slot_cert_id)
{
	PKCS11_SLOT *slot_list, *slot;
	PKCS11_TOKEN *tok;
	PKCS11_CERT *certs, *selected_cert = NULL;
	X509 *x509;
	unsigned int count, n, m;
	unsigned char cert_id[MAX_VALUE_LEN / 2];
	size_t cert_id_len = sizeof(cert_id);
	char *cert_label = NULL;
	int slot_nr = -1;
	char flags[64];

	if (s_slot_cert_id && *s_slot_cert_id) {
		n = parse_slot_id_string(s_slot_cert_id, &slot_nr,
					 cert_id, &cert_id_len, &cert_label);
		if (!n) {
			fprintf(stderr,
				"supported formats: <id>, <slot>:<id>, id_<id>, slot_<slot>-id_<id>, label_<label>, slot_<slot>-label_<label>\n");
			fprintf(stderr,
				"where <slot> is the slot number as normal integer,\n");
			fprintf(stderr,
				"and <id> is the id number as hex string.\n");
			fprintf(stderr,
				"and <label> is the textual key label string.\n");
			return NULL;
		}
		if (verbose) {
			fprintf(stderr, "Looking in slot %d for certificate: ",
				slot_nr);
			if (cert_label == NULL) {
				for (n = 0; n < cert_id_len; n++)
					fprintf(stderr, "%02x", cert_id[n]);
				fprintf(stderr, "\n");
			} else
				fprintf(stderr, "label: %s\n", cert_label);

		}
	}

	if (PKCS11_enumerate_slots(ctx, &slot_list, &count) < 0)
		fail("failed to enumerate slots\n");

	if (verbose) {
		fprintf(stderr, "Found %u slot%s\n", count,
			(count <= 1) ? "" : "s");
	}
	for (n = 0; n < count; n++) {
		slot = slot_list + n;
		flags[0] = '\0';
		if (slot->token) {
			if (!slot->token->initialized)
				strcat(flags, "uninitialized, ");
			else if (!slot->token->userPinSet)
				strcat(flags, "no pin, ");
			if (slot->token->loginRequired)
				strcat(flags, "login, ");
			if (slot->token->readOnly)
				strcat(flags, "ro, ");
		} else {
			strcpy(flags, "no token");
		}
		if ((m = strlen(flags)) != 0) {
			flags[m - 2] = '\0';
		}

		if (verbose) {
			fprintf(stderr, "[%u] %-25.25s  %-16s", n,
				slot->description, flags);
			if (slot->token) {
				fprintf(stderr, "  (%s)",
					slot->token->label[0] ?
					slot->token->label : "no label");
			}
			fprintf(stderr, "\n");
		}
	}

	if (slot_nr == -1) {
		if (!(slot = PKCS11_find_token(ctx, slot_list, count)))
			fail("didn't find any tokens\n");
	} else if (slot_nr >= 0 && slot_nr < count)
		slot = slot_list + slot_nr;
	else {
		fprintf(stderr, "Invalid slot number: %d\n", slot_nr);
		PKCS11_release_all_slots(ctx, slot_list, count);
		return NULL;
	}
	tok = slot->token;

	if (tok == NULL) {
		fprintf(stderr, "Found empty token; \n");
		PKCS11_release_all_slots(ctx, slot_list, count);
		return NULL;
	}

	if (verbose) {
		fprintf(stderr, "Found slot:  %s\n", slot->description);
		fprintf(stderr, "Found token: %s\n", slot->token->label);
	}

	if (PKCS11_enumerate_certs(tok, &certs, &count)) {
		fprintf(stderr, "unable to enumerate certificates\n");
		PKCS11_release_all_slots(ctx, slot_list, count);
		return NULL;
	}

	if (verbose) {
		fprintf(stderr, "Found %u cert%s:\n", count,
			(count <= 1) ? "" : "s");
	}
	if ((s_slot_cert_id && *s_slot_cert_id) || (cert_id_len == 0)) {
		for (n = 0; n < count; n++) {
			PKCS11_CERT *k = certs + n;

			if (cert_id_len != 0 && k->id_len == cert_id_len &&
			    memcmp(k->id, cert_id, cert_id_len) == 0) {
				selected_cert = k;
			}
		}
	} else {
		selected_cert = certs;	/* use first */
	}

	if (selected_cert == NULL) {
		fprintf(stderr, "certificate not found.\n");
		PKCS11_release_all_slots(ctx, slot_list, count);
		return NULL;
	}

	x509 = X509_dup(selected_cert->x509);
	if (cert_label != NULL)
		free(cert_label);
	return x509;
}

int load_cert_ctrl(ENGINE * e, void *p)
{
	struct {
		const char *s_slot_cert_id;
		X509 *cert;
	} *parms = p;

	if (parms->cert != NULL)
		return 0;

	parms->cert = pkcs11_load_cert(e, parms->s_slot_cert_id);
	if (parms->cert == NULL)
		return 0;

	return 1;
}

static EVP_PKEY *pkcs11_load_key(ENGINE * e, const char *s_slot_key_id,
				 UI_METHOD * ui_method, void *callback_data,
				 int isPrivate)
{
	PKCS11_SLOT *slot_list, *slot;
	PKCS11_TOKEN *tok;
	PKCS11_KEY *keys, *selected_key = NULL;
	PKCS11_CERT *certs;
	EVP_PKEY *pk;
	unsigned int count, n, m;
	unsigned char key_id[MAX_VALUE_LEN / 2];
	size_t key_id_len = sizeof(key_id);
	char *key_label = NULL;
	int slot_nr = -1;
	char flags[64];

	if (s_slot_key_id && *s_slot_key_id) {
		n = parse_slot_id_string(s_slot_key_id, &slot_nr,
					 key_id, &key_id_len, &key_label);

		if (!n) {
			fprintf(stderr,
				"supported formats: <id>, <slot>:<id>, id_<id>, slot_<slot>-id_<id>, label_<label>, slot_<slot>-label_<label>\n");
			fprintf(stderr,
				"where <slot> is the slot number as normal integer,\n");
			fprintf(stderr,
				"and <id> is the id number as hex string.\n");
			fprintf(stderr,
				"and <label> is the textual key label string.\n");
			return NULL;
		}
		if (verbose) {
			fprintf(stderr, "Looking in slot %d for key: ",
				slot_nr);
			if (key_label == NULL) {
				for (n = 0; n < key_id_len; n++)
					fprintf(stderr, "%02x", key_id[n]);
				fprintf(stderr, "\n");
			} else
				fprintf(stderr, "label: %s\n", key_label);
		}
	}

	if (PKCS11_enumerate_slots(ctx, &slot_list, &count) < 0)
		fail("failed to enumerate slots\n");

	if (verbose) {
		fprintf(stderr, "Found %u slot%s\n", count,
			(count <= 1) ? "" : "s");
	}
	for (n = 0; n < count; n++) {
		slot = slot_list + n;
		flags[0] = '\0';
		if (slot->token) {
			if (!slot->token->initialized)
				strcat(flags, "uninitialized, ");
			else if (!slot->token->userPinSet)
				strcat(flags, "no pin, ");
			if (slot->token->loginRequired)
				strcat(flags, "login, ");
			if (slot->token->readOnly)
				strcat(flags, "ro, ");
		} else {
			strcpy(flags, "no token");
		}
		if ((m = strlen(flags)) != 0) {
			flags[m - 2] = '\0';
		}

		if (verbose) {
			fprintf(stderr, "[%u] %-25.25s  %-16s", n,
				slot->description, flags);
			if (slot->token) {
				fprintf(stderr, "  (%s)",
					slot->token->label[0] ?
					slot->token->label : "no label");
			}
			fprintf(stderr, "\n");
		}
	}

	if (slot_nr == -1) {
		if (!(slot = PKCS11_find_token(ctx, slot_list, count)))
			fail("didn't find any tokens\n");
	} else if (slot_nr >= 0 && slot_nr < count)
		slot = slot_list + slot_nr;
	else {
		fprintf(stderr, "Invalid slot number: %d\n", slot_nr);
		PKCS11_release_all_slots(ctx, slot_list, count);
		return NULL;
	}
	tok = slot->token;

	if (tok == NULL) {
		fprintf(stderr, "Found empty token; \n");
		PKCS11_release_all_slots(ctx, slot_list, count);
		return NULL;
	}
/* Removed for interop with some other pkcs11 libs. */
#if 0
	if (!tok->initialized) {
		fprintf(stderr, "Found uninitialized token; \n");
		return NULL;
	}
#endif
	if (isPrivate && !tok->userPinSet && !tok->readOnly) {
		fprintf(stderr, "Found slot without user PIN\n");
		PKCS11_release_all_slots(ctx, slot_list, count);
		return NULL;
	}

	if (verbose) {
		fprintf(stderr, "Found slot:  %s\n", slot->description);
		fprintf(stderr, "Found token: %s\n", slot->token->label);
	}

	if (PKCS11_enumerate_certs(tok, &certs, &count))
		fail("unable to enumerate certificates\n");

	if (verbose) {
		fprintf(stderr, "Found %u certificate%s:\n", count,
			(count <= 1) ? "" : "s");
		for (n = 0; n < count; n++) {
			PKCS11_CERT *c = certs + n;
			char *dn = NULL;

			fprintf(stderr, "  %2u    %s", n + 1, c->label);
			if (c->x509)
				dn = X509_NAME_oneline(X509_get_subject_name
						       (c->x509), NULL, 0);
			if (dn) {
				fprintf(stderr, " (%s)", dn);
				OPENSSL_free(dn);
			}
			fprintf(stderr, "\n");
		}
	}

	/* Perform login to the token if required */
	if (tok->loginRequired) {
		/* If the token has a secure login (i.e., an external keypad),
		   then use a NULL pin. Otherwise, check if a PIN exists. If
		   not, allocate and obtain a new PIN. */
		if (tok->secureLogin) {
			/* Free the PIN if it has already been 
			   assigned (i.e, cached by get_pin) */
			if (pin != NULL) {
				OPENSSL_cleanse(pin, MAX_PIN_LENGTH);
				free(pin);
				pin = NULL;
			}
		} else if (pin == NULL) {
			pin = (char *)calloc(MAX_PIN_LENGTH, sizeof(char));
			if (pin == NULL) {
				fail("Could not allocate memory for PIN");
			}
			if (!get_pin(ui_method, callback_data) ) {
				OPENSSL_cleanse(pin, MAX_PIN_LENGTH);
				free(pin);
				pin = NULL;
				fail("No pin code was entered");
			}
		}

		/* Now login in with the (possibly NULL) pin */
		if (PKCS11_login(slot, 0, pin)) {
			/* Login failed, so free the PIN if present */
			if (pin != NULL) {
				OPENSSL_cleanse(pin, MAX_PIN_LENGTH);
				free(pin);
				pin = NULL;
			}
			fail("Login failed\n");
		}
		/* Login successful, PIN retained in case further logins are 
		   required. This will occur on subsequent calls to the
		   pkcs11_load_key function. Subsequent login calls should be
		   relatively fast (the token should maintain its own login
		   state), although there may still be a slight performance 
		   penalty. We could maintain state noting that successful
		   login has been performed, but this state may not be updated
		   if the token is removed and reinserted between calls. It
		   seems safer to retain the PIN and peform a login on each
		   call to pkcs11_load_key, even if this may not be strictly
		   necessary. */
		/* TODO when does PIN get freed after successful login? */
		/* TODO confirm that multiple login attempts do not introduce
		   significant performance penalties */

	}

	/* Make sure there is at least one private key on the token */
	if (PKCS11_enumerate_keys(tok, &keys, &count)) {
		fail("unable to enumerate keys\n");
	}
	if (count == 0) {
		fail("No keys found.\n");
	}

	if (verbose) {
		fprintf(stderr, "Found %u key%s:\n", count,
			(count <= 1) ? "" : "s");
	}
	if (s_slot_key_id && *s_slot_key_id) {
		for (n = 0; n < count; n++) {
			PKCS11_KEY *k = keys + n;

			if (verbose) {
				fprintf(stderr, "  %2u %c%c %s\n", n + 1,
					k->isPrivate ? 'P' : ' ',
					k->needLogin ? 'L' : ' ', k->label);
			}
			if (key_label == NULL) {
				if (key_id_len != 0 && k->id_len == key_id_len
				    && memcmp(k->id, key_id, key_id_len) == 0) {
					selected_key = k;
				}
			} else {
				if (strcmp(k->label, key_label) == 0) {
					selected_key = k;
				}
			}
		}
	} else {
		selected_key = keys;	/* use first */
	}

	if (selected_key == NULL) {
		fprintf(stderr, "key not found.\n");
		return NULL;
	}

	if (isPrivate) {
		pk = PKCS11_get_private_key(selected_key);
	} else {
		/*pk = PKCS11_get_public_key(&keys[0]);
		   need a get_public_key? */
		pk = PKCS11_get_private_key(selected_key);
	}
	if (key_label != NULL)
		free(key_label);
	return pk;
}

EVP_PKEY *pkcs11_load_public_key(ENGINE * e, const char *s_key_id,
				 UI_METHOD * ui_method, void *callback_data)
{
	EVP_PKEY *pk;

	pk = pkcs11_load_key(e, s_key_id, ui_method, callback_data, 0);
	if (pk == NULL)
		fail("PKCS11_load_public_key returned NULL\n");
	return pk;
}

EVP_PKEY *pkcs11_load_private_key(ENGINE * e, const char *s_key_id,
				  UI_METHOD * ui_method, void *callback_data)
{
	EVP_PKEY *pk;

	pk = pkcs11_load_key(e, s_key_id, ui_method, callback_data, 1);
	if (pk == NULL)
		fail("PKCS11_get_private_key returned NULL\n");
	return pk;
}
