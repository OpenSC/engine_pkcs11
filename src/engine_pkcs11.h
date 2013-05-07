/*
 * Copyright (c) 2002 Juha Yrjölä.  All rights reserved.
 * Copyright (c) 2001 Markus Friedl.
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

#ifndef _ENGINE_PKCS11_H
#define _ENGINE_PKCS11_H

#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/engine.h>

/**
 * Specify the pkcs11 provider, e.g., opensc-pkcs11.so.
 *
 * @param modulename the path to the pkcs11 provider shared library
 *
 * @return 1 in all cases.
 */
int set_module(const char *modulename);

/**
 * Set the PIN used for login. A copy of the PIN shall be made.
 *
 * If the PIN cannot be assigned, the value 0 shall be returned
 * and errno shall be set as follows:
 *
 *   EINVAL - a NULL PIN was supplied
 *   ENOMEM - insufficient memory to copy the PIN
 *
 * @param pin the pin to use for login. Must not be NULL.
 *
 * @return 1 on success, 0 on failure.
 */
int set_pin(const char *pin);

/**
 * Provide the arguments for PKCS11_CTX_init_args.
 *
 * @param args arguments to be given when creating a new PKCS11 context.
 *
 * @return 1 in all cases.
 */
int set_init_args(const char *args);

/**
 * Initialize the given engine.
 *
 * Among other actions, this function checks the environment variable
 * "ENGINE_PKCS11_VERBOSE"; if it is a non-zero integer, the verbose
 * output will be enabled.
 *
 * @param engine the engine to be initialized.
 *
 * @return 1 if engine was successfully initialized, 0 otherwise.
 */
int pkcs11_init(ENGINE *engine);

/**
 * Shut down the given engine.
 *
 * @param engine the engine to be wound down.
 *
 * @return 1 in all cases.
 */
int pkcs11_finish(ENGINE *engine);

/**
 * Load a particular certificate from the token.
 *
 * The parameter is a pointer to a structure which contains the
 * slot_id (describing where to find the certificate), and a X509*
 * (which is where the certificate is copied, if it is found.)
 *
 *     struct {
 *         const char *slot_id;
 *         X509 *cert;
 *     };
 *
 * @param p pointer to a structure as given above.
 *
 * @return zero if no cert found, non-zero if cert found.
 */
int load_cert_ctrl(ENGINE *e, void *p);

/**
 * Release a key and all resources associated with that key.
 *
 * @param pkey pointer to the evp_pkey to be freed.
 *
 * @return 1 in all cases.
 */
int release_key(EVP_PKEY *pkey);

/**
 * Increase verbosity.
 *
 * If this is greater than 0, then the engine emits diagnostics to
 * stderr.
 *
 * As of 2013-05, there are no shades of grey; the only values that
 * matter are zero and "not zero".
 *
 * @return 1 in all cases.
 */
int inc_verbose(void);

/**
 * Attempt to load a public key at the given @slot_id.
 *
 * @return NULL on failure, live key on success. 
 */
EVP_PKEY *pkcs11_load_public_key(ENGINE *e, const char *slot_id,
				 UI_METHOD *ui_method, void *callback_data);

/**
 * Attempt to load a private key at the given @slot_id.
 *
 * NOTE: the engine has to allocate extra resources to make sure that
 * the private key works even after leaving the engine.  The default
 * EVP_PKEY_free method does not know about these extra resources, so
 * do not use that method on this key.
 *
 * Instead, to insure that these resources are properly released,
 * please use the RELEASE_KEY control:
 *
 *     ENGINE_ctrl_cmd( engine, "RELEASE_KEY", 0,
 *                    (void *)pkey, NULL, 0 );
 *
 * @return NULL on failure, live key on success. 
 */
EVP_PKEY *pkcs11_load_private_key(ENGINE *e, const char *slot_id,
				  UI_METHOD *ui_method, void *callback_data);

#endif
