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
#include "fail.h"

#ifdef _WIN32
#define strncasecmp strnicmp
#endif

/** The maximum length of an internally-allocated PIN */
#define MAX_PIN_LENGTH 32

static PKCS11_CTX *ctx;

/**
 * The PIN used for login. Cache for the get_pin function.
 * The memory for this PIN is always owned internally,
 * and may be freed as necessary. Before freeing, the PIN
 * must be whitened, to prevent security holes.
 */
static char *pin;
static int pin_length;

/* Convenience function for wiping and freeing the stored PIN. */
static void zero_pin()
{
	if (pin) {
		OPENSSL_cleanse(pin, pin_length);
		free(pin);
		pin = NULL;
		pin_length = 0;
	}
}

static int verbose;

static char *module;

static char *init_args;

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
int set_pin(const char *_pin)
{
	/* Pre-condition check */
	if (!_pin) {
		errno = EINVAL;
		return 0;
	}

	/* Copy the PIN. If the string cannot be copied, NULL
	   shall be returned and errno shall be set. */
	pin = strdup(_pin);
	if (pin)
		pin_length = strlen(pin);

	return !!pin;
}

int inc_verbose(void)
{
	verbose++;
	return 1;
}

/* either get the pin code from the supplied callback data, or get the pin
 * via asking our self. In both cases keep a copy of the pin code in the
 * pin variable (strdup'ed copy). */
static int get_pin(UI_METHOD *ui_method, void *callback_data)
{
	int rv = 0;
	UI *ui;
	struct {
		const void *password;
		const char *prompt_info;
	} *mycb = callback_data;

#undef CLEANUP
#define CLEANUP cleanup_done

	/* pin in the call back data, copy and use */
	if (mycb && mycb->password) {
		pin = (char *)calloc(MAX_PIN_LENGTH, sizeof(char));
		if (!pin)
			FAIL("Could not allocate storage for PIN");
		strncpy(pin, mycb->password, MAX_PIN_LENGTH);
		pin_length = MAX_PIN_LENGTH;
		return 1;
	}

	/* call ui to ask for a pin */
	ui = UI_new();
	if (!ui)
		FAIL("Unable to allocate UI");

#undef CLEANUP
#define CLEANUP cleanup_release_ui

	if (ui_method)
		UI_set_method(ui, ui_method);

	if (callback_data)
		UI_set_app_data(ui, callback_data);

	if (!UI_add_input_string(ui, "PKCS#11 token PIN: ", 0,
				 pin, 1, MAX_PIN_LENGTH))
		FAIL("UI_add_input_string failed");

	if (UI_process(ui))
		FAIL("UI_process failed");

	rv = 1; /* success! */

cleanup_release_ui:
	UI_free(ui);

cleanup_done:
	return rv;
}

int set_init_args(const char *init_args_orig)
{
	init_args = init_args_orig ? strdup(init_args_orig) : NULL;
	return 1;
}

int pkcs11_finish(ENGINE *engine)
{
	if (ctx) {
		PKCS11_CTX_unload(ctx);
		PKCS11_CTX_free(ctx);
		ctx = NULL;
	}
	zero_pin();
	return 1;
}

int pkcs11_init(ENGINE *engine)
{
	if (verbose)
		fprintf(stderr, "initializing engine\n");

#undef CLEANUP
#define CLEANUP cleanup_done

	ctx = PKCS11_CTX_new();
	if (!ctx)
		FAIL("Unable to allocate PKCS11_CTX");

#undef CLEANUP
#define CLEANUP cleanup_release_ctx

	PKCS11_CTX_init_args(ctx, init_args);
	if (PKCS11_CTX_load(ctx, module) < 0)
		FAIL1("Unable to load module '%s'", module);

	/* in case of success, we don't want to deallocate anything. */
	return 1;

cleanup_release_ctx:
	PKCS11_CTX_free(ctx);

cleanup_done:
	return 0;
}

int pkcs11_rsa_finish(RSA *rsa)
{
	zero_pin();
	if (module) {
		free(module);
		module = NULL;
	}
	/* need to free RSA_ex_data? */
	/* FIXME: ajf -- need to PKCS11_CTX_free(ctx)? */
	return 1;
}

static int hex_to_bin(const char *in, unsigned char *out, size_t *outlen)
{
	size_t left, count = 0;

	if (!in || *in == '\0') {
		*outlen = 0;
		return 1;
	}

	left = *outlen;

#undef CLEANUP
#define CLEANUP cleanup_zero_outlen

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
			else
				FAIL1("Invalid char '%c' in hex string", c);
			byte |= c;
		}

		if (*in == ':')
			in++;

		if (left <= 0)
			FAIL("Hex string too long");

		out[count++] = (unsigned char)byte;
		left--;
	}

	*outlen = count;
	return 1;

cleanup_zero_outlen:
	*outlen = 0;
	return 0;
}

/* parse string containing slot and id information */

static int parse_slot_id_string(const char *slot_id, int *slot,
				unsigned char *id, size_t *id_len,
				char **label)
{
	size_t slot_id_len;
	int n, i;

	if (!slot_id)
		return 0;

#undef CLEANUP
#define CLEANUP cleanup_done

	/* support for several formats */
#define HEXDIGITS "01234567890ABCDEFabcdef"
#define DIGITS "0123456789"

	slot_id_len = strlen(slot_id);

	/* first: pure hex number (id, slot is 0) */
	if (strspn(slot_id, HEXDIGITS) == slot_id_len) {
		/* ah, easiest case: only hex. */
		if ((slot_id_len + 1) / 2 > *id_len)
			FAIL("Id string too long!");
		*slot = 0;
		return hex_to_bin(slot_id, id, id_len);
	}

	/* second: slot:id. slot is an digital int. */
	if (sscanf(slot_id, "%d", &n) == 1) {
		i = strspn(slot_id, DIGITS);

		if (slot_id[i] != ':')
			FAIL("Slot number followed by non-colon");

		i++;
		if (slot_id[i] == 0) {
			*slot = n;
			*id_len = 0;
			return 1;
		}

		if (strspn(slot_id + i, HEXDIGITS) + i != slot_id_len)
			FAIL("Non-hex Id after slot number");

		/* ah, rest is hex */
		if ((slot_id_len - i + 1) / 2 > *id_len)
			FAIL1("Id string too long (max=%d)", (int)*id_len);

		*slot = n;
		return hex_to_bin(slot_id + i, id, id_len);
	}

	/* third: id_<id>  */
	if (strncmp(slot_id, "id_", 3) == 0) {
		if (strspn(slot_id + 3, HEXDIGITS) + 3 != slot_id_len)
			FAIL("Non-hex Id after 'id_'");

		/* ah, rest is hex */
		if ((slot_id_len - 3 + 1) / 2 > *id_len)
			FAIL1("Id string too long (max=%d)", (int)*id_len);

		*slot = 0;
		return hex_to_bin(slot_id + 3, id, id_len);
	}

	/* label_<label>  */
	if (strncmp(slot_id, "label_", 6) == 0) {
		*label = strdup(slot_id + 6);
		return !!*label;
	}

	/* last try: it has to be slot_<slot> and then "-id_<cert>" */

	if (strncmp(slot_id, "slot_", 5) != 0)
		FAIL1("Unrecognized format '%s' (expected 'slot_...')",
		      slot_id);

	/* slot is an decimal int. */
	if (sscanf(slot_id + 5, "%d", &n) != 1)
		FAIL("Could not parse decimal slot number after 'slot_'");

	i = strspn(slot_id + 5, DIGITS);

	if (slot_id[i + 5] == 0) {
		*slot = n;
		*id_len = 0;
		return 1;
	}

	if (slot_id[i + 5] != '-')
		FAIL1("Expected hyphen at location %d after 'slot_'", i+5);

	i = 5 + i + 1;

	/* now followed by "id_" */
	if (strncmp(slot_id + i, "id_", 3) == 0) {
		if (strspn(slot_id + i + 3, HEXDIGITS) + 3 + i !=
		    slot_id_len)
			FAIL("Non-hex data after 'id_' after 'slot_'");

		/* ah, rest is hex */
		if ((slot_id_len - i - 3 + 1) / 2 > *id_len)
			FAIL1("Id string too long (max=%d)", (int)*id_len);

		*slot = n;
		return hex_to_bin(slot_id + i + 3, id, id_len);
	}

	/* ... or "label_" */
	if (strncmp(slot_id + i, "label_", 6) == 0) {
		*slot = n;
		*label = strdup(slot_id + i + 6);
		return !!*label;
	}

	FAIL1("Could not parse slot_id string '%s'", slot_id);

cleanup_done:
	return 0;
}

/* a second layer of function call lets the inner call to have
 * multiple exits gracefully. */
static int parse_slot_id_string_aux(const char *slot_id,
				    unsigned int *slot_nr,
				    unsigned char *id,
				    size_t *id_len,
				    char **label,
				    const char *use)
{
	int rc = parse_slot_id_string(slot_id, slot_nr,
				      id, id_len, label);

#undef CLEANUP
#define CLEANUP cleanup_done

	if (!rc)
		FAIL1("could not parse '%s' as slot_id:\n"
		      "  supported formats: <id>, <slot>:<id>, id_<id>,"
		      " slot_<slot>-id_<id>, label_<label>,"
		      " slot_<slot>-label_<label>\n"
		      "  where <slot> is the slot number as decimal integer,\n"
		      "  and <id> is the id number as hex nybbles,\n"
		      "  and <label> is the key label text string.\n",
		      slot_id);

	if (verbose) {
		fprintf(stderr, "Looking in slot %d for %s: ", slot_nr, use);
		if (*label) {
			fprintf(stderr, "label: '%s'\n", *label);
		} else {
			int n;
			fprintf(stderr, "id(hex): '");
			for (n = 0; n < *id_len; n++)
				fprintf(stderr, "%02x", id[n]);
			fprintf(stderr, "'\n");
		}
	}

cleanup_done:
	return rc;
}

static PKCS11_SLOT *scan_slots(const unsigned int slot_count,
			       PKCS11_SLOT *slot_list,
			       const int slot_nr)
{
	PKCS11_SLOT *rv = NULL;
	PKCS11_SLOT *found_slot = NULL;
	int n;

#undef CLEANUP
#define CLEANUP cleanup_done

	if (verbose)
		fprintf(stderr, "Num slots: %u\n", slot_count);

	for (n = 0; n < slot_count; n++) {
		char flags[64];
		PKCS11_SLOT *slot = slot_list + n;
		unsigned long slotid = PKCS11_get_slotid_from_slot(slot);
		if (slot_nr != -1 && slot_nr == slotid)
			found_slot = slot;

		if (!verbose) {
			if (found_slot)
				break;
			else
				continue;
		}

		flags[0] = '\0';
		if (!slot->token) {
			strcpy(flags, "no token");
		} else if (!slot->token->initialized) {
			strcat(flags, "uninitialized");
		} else {
			int m;
			if (!slot->token->userPinSet)
				strcat(flags, "no pin, ");
			if (slot->token->loginRequired)
				strcat(flags, "login, ");
			if (slot->token->readOnly)
				strcat(flags, "ro, ");
			m = strlen(flags);
			if (m)
				flags[m - 2] = '\0';
		}

		fprintf(stderr, "[%lu] %-25.25s  %-16s",
			slotid, slot->description, flags);

		if (slot->token)
			fprintf(stderr, "  (%s)",
				slot->token->label[0] ?
				slot->token->label : "no label");

		fprintf(stderr, "\n");
	}

	/* We didn't find one by looping through obvious slots; see if
	 * the PKCS11 library can find one "magically". */
	if (!found_slot)
		found_slot = PKCS11_find_token(ctx, slot_list, slot_count);

	/* Nothing we can do, communicate failure to caller. */
	if (!found_slot)
		FAIL("Unable to find active slot");

	/* Make sure the found slot has a token in it. */
	if (!found_slot->token)
		FAIL("No token in selected slot");

	if (verbose)
		fprintf(stderr, "Found slot '%s', token '%s'\n",
			found_slot->description, found_slot->token->label);

	/* Success. */
	rv = found_slot;

cleanup_done:
	return rv;
}

#define MAX_VALUE_LEN	200

/* prototype for OpenSSL ENGINE_load_cert */
/* used by load_cert_ctrl via ENGINE_ctrl for now */

static X509 *pkcs11_load_cert(ENGINE *e, const char *s_slot_cert_id)
{
	PKCS11_SLOT *slot_list;
	PKCS11_SLOT *slot = NULL;
	PKCS11_TOKEN *tok;
	PKCS11_CERT *certs, *selected_cert = NULL;
	X509 *x509 = NULL;
	unsigned int slot_count, cert_count, n;
	unsigned char cert_id[MAX_VALUE_LEN / 2];
	size_t cert_id_len = sizeof(cert_id);
	char *cert_label = NULL;
	int slot_nr = -1;

#undef CLEANUP
#define CLEANUP cleanup_done

	if (s_slot_cert_id && *s_slot_cert_id &&
	    !parse_slot_id_string_aux(s_slot_cert_id, &slot_nr,
				      cert_id, &cert_id_len, &cert_label,
				      "certificate"))
		return NULL;

	if (PKCS11_enumerate_slots(ctx, &slot_list, &slot_count) < 0)
		FAIL("Failed to enumerate slots");

#undef CLEANUP
#define CLEANUP cleanup_release_slots

	slot = scan_slots(slot_count, slot_list, slot_nr);
	if (!slot)
		FAIL("Unable to find active slot");

	tok = slot->token;

	if (PKCS11_enumerate_certs(tok, &certs, &cert_count))
		FAIL("Unable to enumerate certificates");

	if (verbose)
		fprintf(stderr, "Found %u cert%s:\n", cert_count,
			(cert_count <= 1) ? "" : "s");

	if ((s_slot_cert_id && *s_slot_cert_id) && (cert_id_len != 0)) {
		for (n = 0; n < cert_count; n++) {
			PKCS11_CERT *k = certs + n;

			if (cert_id_len != 0 && k->id_len == cert_id_len &&
			    memcmp(k->id, cert_id, cert_id_len) == 0) {
				selected_cert = k;
			}
		}
	} else {
		selected_cert = certs;	/* use first */
	}

	if (!selected_cert)
		FAIL("Certificate not found.");

	x509 = X509_dup(selected_cert->x509);

	if (cert_label)
		free(cert_label);

cleanup_release_slots:
	PKCS11_release_all_slots(ctx, slot_list, slot_count);

cleanup_done:
	return x509;
}

int load_cert_ctrl(ENGINE *e, void *p)
{
	struct {
		const char *s_slot_cert_id;
		X509 *cert;
	} *parms = p;

	if (parms->cert)
		return 0;

	parms->cert = pkcs11_load_cert(e, parms->s_slot_cert_id);
	return !!parms->cert;
}

static EVP_PKEY *pkcs11_load_key(ENGINE *e, const char *s_slot_key_id,
				 UI_METHOD *ui_method, void *callback_data,
				 int isPrivate)
{
	PKCS11_SLOT *slot_list;
	PKCS11_SLOT *slot = NULL;
	PKCS11_TOKEN *tok;
	PKCS11_KEY *keys, *selected_key = NULL;
	PKCS11_CERT *certs;
	EVP_PKEY *pk = NULL;
	unsigned int slot_count, cert_count, key_count, n;
	unsigned char key_id[MAX_VALUE_LEN / 2];
	size_t key_id_len = sizeof(key_id);
	char *key_label = NULL;
	int slot_nr = -1;

#undef CLEANUP
#define CLEANUP cleanup_done

	if (s_slot_key_id && *s_slot_key_id &&
	    !parse_slot_id_string_aux(s_slot_key_id, &slot_nr,
				      key_id, &key_id_len, &key_label,
				      "key"))
		return NULL;

	if (PKCS11_enumerate_slots(ctx, &slot_list, &slot_count) < 0)
		FAIL("Failed to enumerate slots");

#undef CLEANUP
#define CLEANUP cleanup_release_slots

	slot = scan_slots(slot_count, slot_list, slot_nr);
	if (!slot)
		FAIL("Unable to find active slot");

	tok = slot->token;

	if (PKCS11_enumerate_certs(tok, &certs, &cert_count))
		FAIL("Unable to enumerate certificates");

	if (isPrivate && !tok->userPinSet && !tok->readOnly)
		FAIL("Found slot without user PIN");

	if (verbose) {
		fprintf(stderr, "Found %u certificate%s:\n", cert_count,
			(cert_count <= 1) ? "" : "s");
		for (n = 0; n < cert_count; n++) {
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
			zero_pin();
		} else if (!pin) {
			pin = (char *)calloc(MAX_PIN_LENGTH, sizeof(char));
			if (!pin)
				FAIL("Could not allocate memory for PIN");
			pin_length = MAX_PIN_LENGTH;
			if (!get_pin(ui_method, callback_data)) {
				zero_pin();
				FAIL("No PIN was entered");
			}
		}

		/* Now login in with the (possibly NULL) pin */
		if (PKCS11_login(slot, 0, pin)) {
			/* Login failed, so free the PIN if present */
			zero_pin();
			FAIL("Login failed");
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
	if (PKCS11_enumerate_keys(tok, &keys, &key_count))
		FAIL("Unable to enumerate keys");

	if (key_count == 0)
		FAIL("No keys found.");

	if (verbose)
		fprintf(stderr, "Found %u key%s:\n", key_count,
			(key_count <= 1) ? "" : "s");

	if (s_slot_key_id && *s_slot_key_id && (key_id_len != 0 || key_label)) {
		for (n = 0; !selected_key && n < key_count; n++) {
			PKCS11_KEY *k = keys + n;

			if (verbose)
				fprintf(stderr, "  %2u %c%c %s\n", n + 1,
					k->isPrivate ? 'P' : ' ',
					k->needLogin ? 'L' : ' ', k->label);

			if (!key_label) {
				if (key_id_len != 0 && k->id_len == key_id_len
				    && memcmp(k->id, key_id, key_id_len) == 0) {
					selected_key = k;
				}
			} else {
				if (strcmp(k->label, key_label) == 0)
					selected_key = k;
			}
		}
	} else {
		selected_key = keys;	/* use first */
	}

	if (!selected_key)
		FAIL("Key not found");

	if (isPrivate) {
		pk = PKCS11_get_private_key(selected_key);
	} else {
		/* pk = PKCS11_get_public_key(&keys[0]);
		   need a get_public_key? */
		pk = PKCS11_get_private_key(selected_key);
	}

cleanup_done:
	if (key_label)
		free(key_label);

	/* can't release slots if we have a live key. */
	return pk;

cleanup_release_slots:
	PKCS11_release_all_slots(ctx, slot_list, slot_count);
	return NULL;
}

#undef CLEANUP
#define CLEANUP cleanup_done

EVP_PKEY *pkcs11_load_public_key(ENGINE *e, const char *s_key_id,
				 UI_METHOD *ui_method, void *callback_data)
{
	EVP_PKEY *pk = NULL;

	pk = pkcs11_load_key(e, s_key_id, ui_method, callback_data, 0);
	if (!pk)
		FAIL("PKCS11_load_public_key returned NULL");

cleanup_done:
	return pk;
}

EVP_PKEY *pkcs11_load_private_key(ENGINE *e, const char *s_key_id,
				  UI_METHOD *ui_method, void *callback_data)
{
	EVP_PKEY *pk;

	pk = pkcs11_load_key(e, s_key_id, ui_method, callback_data, 1);
	if (!pk)
		FAIL("PKCS11_load_public_key returned NULL");

cleanup_done:
	return pk;
}
