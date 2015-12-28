# Build state

[![Build Status](https://travis-ci.org/OpenSC/engine_pkcs11.png)](https://travis-ci.org/OpenSC/engine_pkcs11)
[![Build status](https://ci.appveyor.com/api/projects/status/v1dd09ax199m0ev3?svg=true)](https://ci.appveyor.com/project/LudovicRousseau/engine-pkcs11)

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

## Copying the engine shared object to the proper location

OpenSSL has a location where engine shared objects can be placed
and they will be automatically loaded when requested. It is recommended
to copy engine_pkcs11 at that location as libpkcs11.so to ease usage.
This is handle by 'make install' of engine_pkcs11.


## Using in systems with p11-kit

In systems with p11-kit-proxy engine_pkcs11 has access to all the configured
PKCS #11 modules and requires no further configuration.


## Using in systems without p11-kit

In systems without p11-kit-proxy you need to configure OpenSSL to know about
the engine and to use OpenSC PKCS#11 module by the engine_pkcs11. For that you
add something like the following into your global OpenSSL configuration file
(often in ``/etc/ssl/openssl.cnf``).

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
OpenSSL applications to select the engine by the identifier. In systems
with p11-kit-proxy installed and configured, you do not need to modify the
OpenSSL configuration file; the configuration of p11-kit will be used.


## Testing the engine operation

To verify that the engine is properly operating you can use the following example.

```
$ openssl engine pkcs11 -t
(pkcs11) pkcs11 engine
     [ available ]
```

## Using the engine from the command line tool

This section demonstrates how to use the command line tool to create a self signed
certificate for "Andreas Jellinghaus". The key of the certificate will be generated
in the token and will not exportable.

For the examples that follow, we need to generate a private key in the token and
obtain its private key URL. The following commands utilize p11tool for that.

```
$ p11tool --provider /usr/lib/opensc-pkcs11.so --login --generate-rsa --bits 1024 --label test-key
$ p11tool --provider /usr/lib/opensc-pkcs11.so --list-privkeys --login
```

Note the PKCS #11 URL shown above and use it in the commands below.

To generate a certificate with its key in the PKCS #11 module, the following commands commands
can be used. The first command creates a self signed Certificate for "Andreas Jellinghaus". The
signing is done using the key specified by the URL. The second command creates a self-signed 
certificate for the request, the private key used to sign the certificate is the same private key
used to create the request. Note that in a PKCS #11 URL you can specify the PIN using the 
"pin-value" attribute.

```
$ openssl
OpenSSL> req -engine pkcs11 -new -key "pkcs11:object=test-key;type=private;pin-value=XXXX" \
         -keyform engine -out req.pem -text -x509 -subj "/CN=Andreas Jellinghaus"
OpenSSL> x509 -engine pkcs11 -signkey "pkcs11:object=test-key;type=private;pin-value=XXXX" \
         -keyform engine -in req.pem -out cert.pem
```

For the above commands to operate in systems without p11-kit you will need to provide the
engine configuration explicitly. The following line loads engine_pkcs11 with the PKCS#11
module opensc-pkcs11.so. 

```
OpenSSL> engine -t dynamic -pre SO_PATH:/usr/lib/engines/libpkcs11.so \
         -pre ID:pkcs11 -pre LIST_ADD:1 -pre LOAD \
         -pre MODULE_PATH:/usr/lib/opensc-pkcs11.so
```


## Engine controls

The supported engine controls are the following.

* **SO_PATH**: Specifies the path to the 'pkcs11-engine' shared library 
* **MODULE_PATH**: Specifies the path to the pkcs11 module shared library 
* **PIN**: Specifies the pin code 
* **VERBOSE**: Print additional details 
* **QUIET**: Do not print additional details 
* **LOAD_CERT_CTRL**: Load a certificate from token

An example code snippet setting specific module is shown below.

```
ENGINE_ctrl_cmd(engine, "MODULE_PATH",
		0, "/path/to/pkcs11module.so", NULL, 1);
```

In systems with p11-kit, if this engine control is not called engine_pkcs11
defaults to loading the p11-kit proxy module.


# Developer information

## Submitting pull requests

For adding new features or extending functionality in addition to the code,
please submit a test program which verifies the correctness of operation.
See tests/ for the existing test suite.

