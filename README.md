# Build state

[![Build Status](https://travis-ci.org/OpenSC/engine_pkcs11.png)](https://travis-ci.org/OpenSC/engine_pkcs11)

# Submitting pull requests

For adding new features or extending functionality in addition to the code,
please submit a test program which verifies the correctness of operation.
See tests/ for the existing test suite.

# About engine_pkcs11: an OpenSSL engine for PKCS#11 modules

engine_pkcs11 is a plug-in for the OpenSSL

## OpenSSL

OpenSSL implements various cipher, digest, and signing features and it can
consume and produce keys. However plenty of people think that these features
should be implemented in a separate hardware, like USB tokens, smart cards or
hardware security modules. Therefore OpenSSL has an abstraction layer called
engine which can delegate some of these features to different piece of
software or hardware.

OpenSSL comes with a few engines for some hardware or software security
modules, like for IBM RSA module or Windows CryptoAPI. (See OpenSSL sources
and ``openssl engine -t`` command output). The engines can be built statically
into the OpenSSL library or they can be built as separate plug-in. Third party
engines has to be always built as plug-ins.

## OpenSSL plug-ins

One of these plug-ins is the engine_pkcs11. The engine_pkcs11 is an OpenSSL
engine which provides a gateway between PKCS#11 modules and the OpenSSL engine
API. One has to register the engine into the OpenSSL and one has to provide
path to a PKCS#11 module which should be gatewayed to. (This can be done in the
OpenSSL configuration file.)

## PKCS#11

PKCS#11 module is again a plug-in which implements PKCS#11 API and the purpose
of the API is to provide some cryptograpic features like key storage, key
generation, signing, digesting, encyphering, etc. The PKCS#11 API is something
like the OpenSSL engine API.

PKCS#11 API is a standard and it's supported by various hardware and software
vendors. Usually, hardware vendor provides a propriatary PKCS#11 module for
his cryptographic device and a cryptogrographic library, like NSS or GnuTLS,
can use it to access the hardware.

## OpenSC

Now comes OpenSC which aims to replace the proprietary PKCS#11 modules by
accessing the hardware directly (or indirectly via other software like
pscs-lite). Thefore OpenSC provides an PKCS#11 module called opensc-pkcs11
which encapsulted OpenSC into PKCS#11 API which allows to plug the OpenSC into
into any software supporting PKCS#11.

Unfortunatelly, OpenSSL does not support PKSC#11 (yet). OpenSSL has the engine
API only (like Windows have CryproAPI). Therefore the engine_pkcs11 exists
which encapsulated PKCS#11 into the OpenSSL engine API.

## OpenSSL Configuration

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


