#ifndef ENGINE_PKCS11_SRC_FAIL_H
#define ENGINE_PKCS11_SRC_FAIL_H 1

/*
 * Copyright (c) 2013 Anthony Foiani <anthony.foiani@gmail.com>
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

/**
 * @file fail.h
 *
 * Convenience functions for quitting tersely yet gracefully.
 *
 * The "fail" macro in engine_pkcs11.c attempts to make the core code
 * easier to read.  Inspired by this, we provide variants that
 * continue to improve readability while improving correctness.
 *
 * We further leverage the Linux coding style of using goto+label to
 * perform different stages of cleanups, as well as providing a
 * C++-ish means of providing primitive unwind capability.
 */

/** The current output destination label. */
#define CLEANUP cleanup_done

/** Exit with an error message. */
#define FAIL(msg)						\
	do {							\
		fprintf(stderr, "%s: " msg "\n", __func__ );	\
		goto CLEANUP;					\
	} while (0)

/** Exit with an error message and one argument. */
#define FAIL1(msg, arg1)						\
	do {								\
		fprintf(stderr, "%s: " msg "\n", __func__ , arg1);	\
		goto CLEANUP;						\
	} while (0)

#endif /* ENGINE_PKCS11_SRC_FAIL_H */
