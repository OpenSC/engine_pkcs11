#include <stdio.h>
#include <unistd.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/pem.h>

STACK_OF(X509_NAME) *load_ca_dns(int argc, char **argv) {
    STACK_OF(X509_NAME) *ca_dns = NULL;
    BIO *in;
    X509 *cert;
    X509_NAME *name;
    int i;

    for (i = 1; i < argc; i++) {
        in = BIO_new_file(argv[i], "r");
        if (NULL == in) {
            fprintf(stderr, "Could not read %s\n", argv[i]);
            continue;
        }
        cert = PEM_read_bio_X509(in, NULL, 0, NULL);
        BIO_free(in);
        if (NULL == cert) {
            fprintf(stderr, "Could not read %s\n", argv[i]);
            continue;
        }
        name = X509_NAME_dup(X509_get_subject_name(cert));
        X509_free(cert);
        if (NULL == name) {
            fprintf(stderr, "Could not get issuer from %s\n", argv[i]);
            X509_free(cert);
            continue;
        }
        if (NULL == ca_dns)
            ca_dns = sk_X509_NAME_new_null();
        sk_X509_NAME_push(ca_dns, name);
    }
    return ca_dns;
}


int main(int argc, char ** argv) {
    ENGINE *e;
    const char *engine_id = "pkcs11";
    STACK_OF(X509_NAME) *ca_dns;
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    int retval;

    printf("Testing %s\n", argv[0]);

    ENGINE_load_builtin_engines();
    OPENSSL_load_builtin_modules();
    if (CONF_modules_load_file(getenv("OPENSSL_CONF"), NULL, 0) <= 0) {
        fprintf(stderr, "Could not load modules defined in the "
                "configuration file\n");
        exit(EXIT_FAILURE);
    }

    e = ENGINE_by_id(engine_id);
    if(!e) {
        fprintf(stderr, "The engine isn't available\n");
        exit(EXIT_FAILURE);
    }
    if(!ENGINE_init(e)) {
        fprintf(stderr, "The engine couldn't ne initilized\n");
        ENGINE_free(e);
        exit(EXIT_FAILURE);
    }

    ca_dns = load_ca_dns(argc, argv);
    retval = ENGINE_load_ssl_client_cert(e, NULL, ca_dns, &cert, &pkey, NULL, NULL, NULL);
    sk_X509_NAME_free(ca_dns);

    if (!retval) {
        fprintf(stderr, "ENGINE_load_ssl_client_cert() failed\n");
        ENGINE_finish(e);
        ENGINE_free(e);
        exit(EXIT_FAILURE);
    }
    if (NULL != cert) {
        printf("A certificate returned:\n");
        X509_print_fp(stdout, cert);
        X509_free(cert);
    } else {
        printf("No certificate returned\n");
    }
    if (NULL != pkey) {
        printf("A private key returned\n");
        /*EVP_PKEY_free(pkey);*/
    } else {
        printf("No private key returned\n");
    }

    ENGINE_finish(e);
    ENGINE_free(e);
    printf("Ok.\n");
    exit(EXIT_SUCCESS);
}
