# Build state

[![Build Status](https://travis-ci.org/OpenSC/engine_pkcs11.png)](https://travis-ci.org/OpenSC/engine_pkcs11)


# engine_pkcs11: an OpenSSL engine for PKCS#11 modules

engine_pkcs11 is an engine plug-in for the OpenSSL library allowing to
access PKCS #11 modules in a semi-transparent way.

## PKCS#11

The PKCS#11 API is an abstract API to access operations on cryptographic objects
such as private keys, without requiring access to the objects themselves. That
is, it provides a logical separation of the keys from the operations. The
PKCS #11 API is mainly used to access objects in smart cards and Hardware or Software
Security Modules (HSMs). That is because in these modules the cryptographic keys
are isolated in hardware or software and are not made available to the applications
using them.

PKCS#11 API is an OASIS standard and it is supported by various hardware and software
vendors. Usually, hardware vendors provide a PKCS#11 module to access their devices.
A prominent example is the OpenSC PKCS #11 module which provides access to a variety
of smart cards. Other libraries like NSS or GnuTLS already take advantage of PKCS #11
to access cryptographic objects.

## OpenSSL engines

OpenSSL implements various cipher, digest, and signing features and it can
consume and produce keys. However plenty of people think that these features
should be implemented in a separate hardware, like USB tokens, smart cards or
hardware security modules. Therefore OpenSSL has an abstraction layer called
engine which can delegate some of these features to different piece of
software or hardware.

engine_pkcs11 tries to fit the PKCS #11 API within the engine API of OpenSSL.
That is, it provides a gateway between PKCS#11 modules and the OpenSSL engine API.
One has to register the engine into the OpenSSL and one has to provide
path to a PKCS#11 module which should be gatewayed to. This can be done by editing
the OpenSSL configuration file (not recommended), by engine specific controls,
or by using the p11-kit proxy module.

The p11-kit proxy module provides access to any configured PKCS #11 module
in the system. See [the p11-kit web pages](http://p11-glue.freedesktop.org/p11-kit.html)
for more information.


# PKCS #11 module configuration

## OpenSSL configuration file
To configure OpenSSL to know about the engine and to use OpenSC PKCS#11 module
by the engine_pkcs11, you add something like this into your global OpenSSL
configuration file (``/etc/ssl/openssl.cnf`` probably):

```
[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = /usr/lib/engines/engine_pkcs11.so
MODULE_PATH = /usr/lib/opensc-pkcs11.so
init = 0
```

The dynamic_path value is the engine_pkcs11 plug-in, the MODULE_PATH value is
the OpenSC PKCS#11 plug-in. The engine_id value is an arbitrary identifier for
OpenSSL applications to select the engine by the identifier.

## Engine controls

A specific module can be specified using the following call.

```
ENGINE_ctrl_cmd(engine, "MODULE_PATH",
		0, "/path/to/pkcs11module.so", NULL, 1);

## p11-kit

No action is required to load modules enabled in p11-kit. In that case objects must
be referred to, using the PKCS #11 URL.


# Developer information

## Submitting pull requests

For adding new features or extending functionality in addition to the code,
please submit a test program which verifies the correctness of operation.
See tests/ for the existing test suite.

