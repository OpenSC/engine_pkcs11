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
#include <stdlib.h>
#include <limits.h>
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

#define VERBOSE(fmt)							\
	do {								\
		if (verbose) {						\
			fprintf(stderr, "%s: " fmt "\n",		\
				__func__);				\
		}							\
	}								\
	while (0)

#define VERBOSE1(fmt, arg1)						\
	do {								\
		if (verbose) {						\
			fprintf(stderr, "%s: " fmt "\n",		\
				__func__, arg1);			\
		}							\
	}								\
	while (0)

#define VERBOSE2(fmt, arg1, arg2)					\
	do {								\
		if (verbose) {						\
			fprintf(stderr, "%s: " fmt "\n",		\
				__func__, arg1, arg2);			\
		}							\
	}								\
	while (0)

#define PLURAL_OF(count) ((count == 1) ? "" : "s")

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

/**
 * Store extra information associated with a particular EVP_PKEY *.
 *
 * In the process of generating an EVP_PKEY, we have to enumerate all
 * the slots, and keep that enumeration alive so long as the key is in
 * use.
 *
 * However, since the EVP_PKEY structure isn't extendable, we have to
 * store information externally, and rely on the user to call the
 * correct cleanup function when done with the key.
 */
struct pkcs11_key_ext {

	/* Since we only return the EVP_PKEY *, we can use it as an
	 * index to find the associated data. */
	EVP_PKEY *evp_pkey;

	/* Storage for slots, and how many. */
	PKCS11_SLOT *slots;
	unsigned int slot_count;

};

/* This is structured as storage, index to one-past-end of used, and
 * index to one-past-end of allocated. */
struct pkcs11_key_ext *key_exts;
int key_ext_count;
int key_ext_alloc;

/* Allocate initial storage for extra data for keys. */
static int initialize_key_ext_info()
{
	VERBOSE("Starting");

	/* (Yes, malloc+memset is calloc, but doing it this way keeps
	 * it consistent with the extension case.) */
	int new_alloc = 10;
	key_exts = malloc(new_alloc*sizeof(struct pkcs11_key_ext));
	if (!key_exts)
		return 0;
	memset(key_exts, 0, new_alloc*sizeof(struct pkcs11_key_ext));
	key_ext_alloc = 10;

	VERBOSE("Success");

	return 1;
}

/*
 * Add @key with given info.
 *
 * Returns 0 on failure, non-zero on success.
 */
static int add_key_ext_info(EVP_PKEY *evp_pkey,
			    PKCS11_SLOT *slots,
			    unsigned int slot_count)
{
	VERBOSE2("evp_pkey=%p, count=%d", evp_pkey, key_ext_count);

	/* If we have used all allocated storage, allocate more. */
	if (key_ext_count >= key_ext_alloc) {
		VERBOSE("  Reallocating");
		int new_alloc = 2*key_ext_alloc;
		struct pkcs11_key_ext *new_key_exts =
			realloc(key_exts,
				new_alloc*sizeof(struct pkcs11_key_ext));
		if (!new_key_exts)
			return 0;
		memset(key_exts+key_ext_alloc, 0,
		       (new_alloc-key_ext_alloc)*sizeof(struct pkcs11_key_ext));
		key_ext_alloc = new_alloc;
		key_exts = new_key_exts;
	}

	/* Update the first unused record. */
	struct pkcs11_key_ext *key_ext = key_exts+key_ext_count;
	key_ext->evp_pkey   = evp_pkey;
	key_ext->slots      = slots;
	key_ext->slot_count = slot_count;

	/* Mark it as used. */
	++key_ext_count;

	VERBOSE1("  count=%d", key_ext_count);

	return 1;
}

/*
 * Remove @key, filling in associated info if found.
 *
 * Returns 0 on failure, non-zero on success.
 */
static int del_key_ext_info(EVP_PKEY *evp_pkey,
			    PKCS11_SLOT **slots,
			    unsigned int *slot_count)
{
	VERBOSE1("evp_pkey=%p", evp_pkey);

	int i;
	for (i = 0; i < key_ext_count; ++i) {
		int prev_last;

		/* Examine the key_ext at index i. */
		struct pkcs11_key_ext *key_ext = key_exts+i;
		VERBOSE2("  i=%d, evp_pkey=%p", i, key_ext->evp_pkey);
		if (key_ext->evp_pkey != evp_pkey)
			continue;

		VERBOSE1("  Found, slots=%p", key_ext->slots);

		/* Found a matching key; copy values. */
		*slots      = key_ext->slots;
		*slot_count = key_ext->slot_count;

		/* Then replace the info at this index with the last. */
		prev_last = key_ext_count-1;
		if (i < prev_last)
			memcpy(key_ext, key_exts+prev_last,
			       sizeof(struct pkcs11_key_ext));

		/* Zero out the entry we copied in, update count. */
		memset(key_exts+prev_last, 0,
		       sizeof(struct pkcs11_key_ext));
		key_ext_count = prev_last;

		VERBOSE1("  Removed, count=%d", key_ext_count);

		return 1;
	}

	VERBOSE1("  Not found, count=%d", key_ext_count);
	return 0;
}

/**
 * Frees @pkey and releases any associated resources.
 *
 * Always returns non-zero success.
 */
int release_key(EVP_PKEY *evp_pkey)
{
	PKCS11_SLOT *slots;
	unsigned int slot_count;

	VERBOSE2("evp_pkey=%p, count=%d\n", evp_pkey, key_ext_count);

	if (del_key_ext_info(evp_pkey, &slots, &slot_count))
		PKCS11_release_all_slots(ctx, slots, slot_count);

	VERBOSE1("  Done, count=%d\n", key_ext_count);

	return 1;
}

/*
 * Free up all remaining key info and the key info structure
 * itself.
 */
static void finalize_key_ext_info()
{
	VERBOSE("Starting");

	/* Release everything left in the array.  Note that
	 * key_ext_count is decremented within the
	 * release_key_resources call.  Removing from the end causes
	 * more searching but less copying. */
	while (key_ext_count > 0)
		release_key(key_exts[key_ext_count-1].evp_pkey);

	/* And then release the array itself. */
	free(key_exts);
	key_exts = NULL;

	VERBOSE("  Done");
}

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
	finalize_key_ext_info();
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
	static const char *env_name = "ENGINE_PKCS11_VERBOSE";
	const char *env_val = getenv(env_name);
	if (env_val) {
		char *end;
		long tmp = strtol(env_val, &end, 10);
		if (end != env_val && INT_MIN <= tmp && tmp <= INT_MAX)
			verbose = (int)tmp;
		else
			fprintf(stderr, "%s:%s: invalid %s '%s'\n",
				"engine_pkcs11", __func__,
				env_name, env_val);
	}

	VERBOSE("Initializing engine");

#undef CLEANUP
#define CLEANUP cleanup_done

	if (!initialize_key_ext_info())
		FAIL("Unable to initialize key_ext info");

#undef CLEANUP
#define CLEANUP cleanup_key_ext

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

cleanup_key_ext:
	finalize_key_ext_info();

cleanup_done:
	return 0;
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
	int rc = 1;

	/* Empty / blank slot+id specifier is allowed. */
	if (!slot_id || slot_id[0] == '\0') {
		id[0] = '\0';
		*id_len = 0;
		return 1;
	}

	rc = parse_slot_id_string(slot_id, slot_nr,
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
			       PKCS11_SLOT *slots,
			       const int slot_nr)
{
	PKCS11_SLOT *rv = NULL;
	PKCS11_SLOT *found_slot = NULL;
	int n;

#undef CLEANUP
#define CLEANUP cleanup_done

	VERBOSE1("Num slots: %u\n", slot_count);

	for (n = 0; n < slot_count; n++) {
		char flags[64];
		PKCS11_SLOT *slot = slots + n;
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
		found_slot = PKCS11_find_token(ctx, slots, slot_count);

	/* Nothing we can do, communicate failure to caller. */
	if (!found_slot)
		FAIL("Unable to find active slot");

	/* Make sure the found slot has a token in it. */
	if (!found_slot->token)
		FAIL("No token in selected slot");

	VERBOSE2("Found slot '%s', token '%s'",
		 found_slot->description, found_slot->token->label);

	/* Success. */
	rv = found_slot;

cleanup_done:
	return rv;
}

PKCS11_CERT *scan_certs(PKCS11_CERT *certs,
			unsigned int cert_count,
			char *id,
			unsigned int id_len)
{
	PKCS11_CERT *rv = NULL;
	unsigned int n;
	unsigned int cert_num = 0;

	VERBOSE2("Found %u certificate%s:", cert_count, PLURAL_OF(cert_count));

	for (n = 0; n < cert_count; n++) {
		PKCS11_CERT *c = certs + n;

		if (id_len && c->id_len == id_len &&
		    memcmp(c->id, id, id_len) == 0) {
			rv = c;
			cert_num = n;
		}

		if (!verbose) {
			if (rv)
				break;
			else
				continue;
		}

		fprintf(stderr, "  %2u    %s", n + 1, c->label);
		if (c->x509) {
			X509_NAME *subj_name = X509_get_subject_name(c->x509);
			char *dn = X509_NAME_oneline(subj_name, NULL, 0);
			fprintf(stderr, " (%s)", dn ? dn : "<no name>");
			OPENSSL_free(dn);
		}
		fprintf(stderr, "\n");
	}

	/* If we couldn't find a match, just use the first one. */
	if (!rv)
		rv = certs;

	if (verbose) {
		if (rv)
			fprintf(stderr, "Selecting certificate %u (\"%s\")\n",
				cert_num, rv->label);
		else
			fprintf(stderr, "No certificate found\n");
	}


	return rv;
}

#define MAX_VALUE_LEN	200

/* prototype for OpenSSL ENGINE_load_cert */
/* used by load_cert_ctrl via ENGINE_ctrl for now */

static X509 *pkcs11_load_cert(ENGINE *e, const char *slot_id)
{
	PKCS11_SLOT *slots;
	PKCS11_SLOT *slot = NULL;
	PKCS11_TOKEN *token;
	PKCS11_CERT *certs;
	PKCS11_CERT *cert = NULL;
	X509 *x509 = NULL;
	unsigned int slot_count, cert_count;
	unsigned char cert_id[MAX_VALUE_LEN / 2];
	size_t cert_id_len = sizeof(cert_id);
	char *cert_label = NULL;
	int slot_nr = -1;

#undef CLEANUP
#define CLEANUP cleanup_done

	if (!parse_slot_id_string_aux(slot_id, &slot_nr, cert_id, &cert_id_len,
				      &cert_label, "certificate"))
		return NULL;

	if (PKCS11_enumerate_slots(ctx, &slots, &slot_count) < 0)
		FAIL("Failed to enumerate slots");

#undef CLEANUP
#define CLEANUP cleanup_release_slots

	slot = scan_slots(slot_count, slots, slot_nr);
	if (!slot)
		FAIL("Unable to find active slot");

	token = slot->token;
	if (!token)
		FAIL("No token in active slot");

	if (PKCS11_enumerate_certs(token, &certs, &cert_count))
		FAIL("Unable to enumerate certificates");

	cert = scan_certs(certs, cert_count, cert_id, cert_id_len);

	if (!cert)
		FAIL("Certificate not found.");

	x509 = X509_dup(cert->x509);

	if (cert_label)
		free(cert_label);

cleanup_release_slots:
	PKCS11_release_all_slots(ctx, slots, slot_count);

cleanup_done:
	return x509;
}

int load_cert_ctrl(ENGINE *e, void *p)
{
	struct {
		const char *slot_id;
		X509 *cert;
	} *parms = p;

	if (parms->cert)
		return 0;

	parms->cert = pkcs11_load_cert(e, parms->slot_id);
	return !!parms->cert;
}

static EVP_PKEY *pkcs11_load_key(ENGINE *e, const char *slot_id,
				 UI_METHOD *ui_method, void *callback_data,
				 int is_private)
{
	PKCS11_SLOT *slots;
	PKCS11_SLOT *slot = NULL;
	PKCS11_TOKEN *token;
	PKCS11_KEY *keys;
	PKCS11_KEY *key = NULL;
	PKCS11_CERT *certs;
	EVP_PKEY *pk = NULL;
	unsigned int slot_count, cert_count, key_count;
	unsigned char key_id[MAX_VALUE_LEN / 2];
	size_t key_id_len = sizeof(key_id);
	char *key_label = NULL;
	int slot_nr = -1;

#undef CLEANUP
#define CLEANUP cleanup_done

	if (!parse_slot_id_string_aux(slot_id, &slot_nr, key_id, &key_id_len,
				      &key_label, "key"))
		return NULL;

	if (PKCS11_enumerate_slots(ctx, &slots, &slot_count) < 0)
		FAIL("Failed to enumerate slots");

#undef CLEANUP
#define CLEANUP cleanup_release_slots

	slot = scan_slots(slot_count, slots, slot_nr);
	if (!slot)
		FAIL("Unable to find active slot");

	token = slot->token;
	if (!token)
		FAIL("No token in active slot");

	if (PKCS11_enumerate_certs(token, &certs, &cert_count))
		FAIL("Unable to enumerate certificates");

	if (is_private && !token->userPinSet && !token->readOnly)
		FAIL("Found slot without user PIN");

	scan_certs(certs, cert_count, key_id, key_id_len);

	/* Perform login to the token if required */
	if (token->loginRequired) {
		/* If the token has a secure login (i.e., an external keypad),
		   then use a NULL pin. Otherwise, check if a PIN exists. If
		   not, allocate and obtain a new PIN. */
		if (token->secureLogin) {
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
	if (PKCS11_enumerate_keys(token, &keys, &key_count))
		FAIL("Unable to enumerate keys");

	if (key_count == 0)
		FAIL("No keys found.");

	VERBOSE2("Found %u key%s:", key_count, PLURAL_OF(key_count));

	if (slot_id && *slot_id && (key_id_len != 0 || key_label)) {
		unsigned int n;
		for (n = 0; n < key_count; n++) {
			PKCS11_KEY *k = keys + n;

			if (verbose)
				fprintf(stderr, "  %2u %c%c %s\n", n + 1,
					k->isPrivate ? 'P' : ' ',
					k->needLogin ? 'L' : ' ', k->label);

			/* It would be nice to just break once we
			 * found the requested key, but the original
			 * code dumped all key info regardless, so we
			 * maintain compatibility. */
			if (key)
				continue;

			/* If a label is specified, it must be a
			 * string match. */
			if (key_label) {
				if (strcmp(k->label, key_label) == 0)
					key = k;
				continue;
			}

			/* Otherwise, if an id was specified, it
			 * must be a binary match of exactly the same
			 * length. */
			if (key_id_len != 0 && key_id_len == k->id_len &&
			    memcmp(k->id, key_id, key_id_len) == 0) {
				key = k;
			}
		}
	} else {
		key = keys; /* use first */
	}

	if (!key)
		FAIL("Key not found");

	if (is_private) {
		pk = PKCS11_get_private_key(key);
	} else {
		/* pk = PKCS11_get_public_key(&keys[0]);
		   need a get_public_key? */
		pk = PKCS11_get_private_key(key);
	}

	/* Save the enumerated slots so we can release them later. */
	if (pk)
		add_key_ext_info(pk, slots, slot_count);

cleanup_done:
	if (key_label)
		free(key_label);

	/* can't release slots if we have a live key. */
	return pk;

cleanup_release_slots:
	PKCS11_release_all_slots(ctx, slots, slot_count);
	return NULL;
}

#undef CLEANUP
#define CLEANUP cleanup_done

EVP_PKEY *pkcs11_load_public_key(ENGINE *e, const char *slot_id,
				 UI_METHOD *ui_method, void *callback_data)
{
	EVP_PKEY *pk = NULL;

	pk = pkcs11_load_key(e, slot_id, ui_method, callback_data, 0);
	if (!pk)
		FAIL("PKCS11_load_public_key returned NULL");

cleanup_done:
	return pk;
}

EVP_PKEY *pkcs11_load_private_key(ENGINE *e, const char *slot_id,
				  UI_METHOD *ui_method, void *callback_data)
{
	EVP_PKEY *pk;

	pk = pkcs11_load_key(e, slot_id, ui_method, callback_data, 1);
	if (!pk)
		FAIL("PKCS11_load_public_key returned NULL");

cleanup_done:
	return pk;
}
