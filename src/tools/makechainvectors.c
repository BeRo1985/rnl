/******************************************************************************
 *                       RNL CERTIFICATE CHAIN VECTORS                        *
 ******************************************************************************
 *                                                                            *
 * Builds the certificate chains src/tests/RNLTestCertificates.pas holds as   *
 * vectors.                                                                   *
 *                                                                            *
 * Runs offline and is not part of the suite: it needs OpenSSL, which RNL     *
 * does not depend on and never will. The output is checked in, so the suite  *
 * stays self contained.                                                      *
 *                                                                            *
 * Why generated rather than fetched: a real chain gives exactly one valid    *
 * case. The cases a verifier is actually judged on - a missing CA bit, an    *
 * exceeded path length, a signature by the wrong key, an expired leaf -      *
 * cannot be obtained from a real certificate authority, for the obvious      *
 * reason.                                                                    *
 *                                                                            *
 * Why built by another library rather than by RNL: an anchor written by the  *
 * code under test is no anchor. It also keeps certificate signing out of     *
 * RNL, which a client never needs - it has no certificate of its own to      *
 * present.                                                                   *
 *                                                                            *
 * The five keys are derived from fixed numbers rather than generated, so a   *
 * rerun produces the same keys. The signatures are not reproducible: ECDSA   *
 * draws a fresh nonce every time, so every run yields different signature    *
 * bytes and therefore a different file. That is why the output is checked in *
 * rather than generated during the build.                                    *
 *                                                                            *
 * Build:                                                                     *
 *   cd src/tools && clang -O2 -o makechainvectors makechainvectors.c -lcrypto*
 *                                                                            *
 * Run:                                                                       *
 *   ./makechainvectors > ../tests/RNLTestCertificates.pas                    *
 *                                                                            *
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define HOST_NAME "relay.test"

/* Fixed so that a rerun produces the same keys and only the signatures churn */
static const char *const KEY_SEEDS[] = {
  "11111111", /* ROOT  */
  "22222222", /* INTER */
  "33333333", /* SUB   */
  "44444444", /* LEAF  */
  "55555555"  /* OTHER */
};
enum { KEY_ROOT = 0, KEY_INTER, KEY_SUB, KEY_LEAF, KEY_OTHER, KEY_COUNT };

/* 2026-01-01T00:00:00Z, and everything else is an offset in days from it */
#define BASE_TIME ((time_t)1767225600)
#define DAY ((time_t)86400)

static void die(const char *aWhat) {
  fprintf(stderr, "makechainvectors: %s\n", aWhat);
  exit(1);
}

/* An EC key on prime256v1 from a fixed private value. The public point is d*G, computed here
   rather than taken on trust, which is what makes the derivation deterministic at all. */
static EVP_PKEY *key_from_seed(const char *aHexSeed) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  BIGNUM *priv = NULL;
  EC_POINT *pub = NULL;
  unsigned char encoded[133];
  size_t encoded_size;
  OSSL_PARAM_BLD *build = NULL;
  OSSL_PARAM *params = NULL;
  EVP_PKEY_CTX *context = NULL;
  EVP_PKEY *key = NULL;

  if (!group) {
    die("no prime256v1");
  }
  if (!BN_hex2bn(&priv, aHexSeed)) {
    die("bad seed");
  }
  pub = EC_POINT_new(group);
  if (!pub || !EC_POINT_mul(group, pub, priv, NULL, NULL, NULL)) {
    die("point multiply failed");
  }
  encoded_size = EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED,
                                    encoded, sizeof(encoded), NULL);
  if (encoded_size == 0) {
    die("point encode failed");
  }

  build = OSSL_PARAM_BLD_new();
  if (!build ||
      !OSSL_PARAM_BLD_push_utf8_string(build, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) ||
      !OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_PRIV_KEY, priv) ||
      !OSSL_PARAM_BLD_push_octet_string(build, OSSL_PKEY_PARAM_PUB_KEY, encoded, encoded_size)) {
    die("parameter build failed");
  }
  params = OSSL_PARAM_BLD_to_param(build);
  context = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
  if (!params || !context || (EVP_PKEY_fromdata_init(context) <= 0) ||
      (EVP_PKEY_fromdata(context, &key, EVP_PKEY_KEYPAIR, params) <= 0)) {
    die("key assembly failed");
  }

  EVP_PKEY_CTX_free(context);
  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(build);
  EC_POINT_free(pub);
  BN_free(priv);
  EC_GROUP_free(group);
  return key;
}

static X509_NAME *name_with_common_name(const char *aCommonName) {
  X509_NAME *name = X509_NAME_new();
  if (!name ||
      !X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC,
                                  (const unsigned char *)aCommonName, -1, -1, 0)) {
    die("name build failed");
  }
  return name;
}

static void add_extension(X509 *aCertificate, int aNID, int aCritical, const char *aValue) {
  X509_EXTENSION *extension = X509V3_EXT_conf_nid(NULL, NULL, aNID, aValue);
  if (!extension) {
    die("extension build failed");
  }
  X509_EXTENSION_set_critical(extension, aCritical);
  if (!X509_add_ext(aCertificate, extension, -1)) {
    die("extension add failed");
  }
  X509_EXTENSION_free(extension);
}

typedef struct {
  const char *subject;
  const char *issuer;       /* common name of the issuing certificate */
  int subject_key;
  int signing_key;
  int is_authority;
  int path_length;          /* below zero for no constraint */
  int key_cert_sign;
  int not_before_days;
  int not_after_days;
  const char *dns_name;     /* NULL for none */
  int server_authentication;
  long serial;
} Recipe;

static X509 *build_certificate(const Recipe *aRecipe, EVP_PKEY *const *aKeys) {
  X509 *certificate = X509_new();
  X509_NAME *subject = name_with_common_name(aRecipe->subject);
  X509_NAME *issuer = name_with_common_name(aRecipe->issuer);
  ASN1_TIME *not_before = ASN1_TIME_new();
  ASN1_TIME *not_after = ASN1_TIME_new();
  time_t from = BASE_TIME + (aRecipe->not_before_days * DAY);
  time_t until = BASE_TIME + (aRecipe->not_after_days * DAY);
  char buffer[128];

  if (!certificate || !not_before || !not_after) {
    die("certificate allocation failed");
  }

  /* Version three, which is what any of the extensions below require */
  if (!X509_set_version(certificate, 2)) {
    die("version failed");
  }
  if (!ASN1_INTEGER_set(X509_get_serialNumber(certificate), aRecipe->serial)) {
    die("serial failed");
  }
  if (!ASN1_TIME_set(not_before, from) || !ASN1_TIME_set(not_after, until) ||
      !X509_set1_notBefore(certificate, not_before) ||
      !X509_set1_notAfter(certificate, not_after)) {
    die("validity failed");
  }
  if (!X509_set_subject_name(certificate, subject) ||
      !X509_set_issuer_name(certificate, issuer) ||
      !X509_set_pubkey(certificate, aKeys[aRecipe->subject_key])) {
    die("names or key failed");
  }

  if (aRecipe->is_authority) {
    if (aRecipe->path_length >= 0) {
      snprintf(buffer, sizeof(buffer), "critical,CA:TRUE,pathlen:%d", aRecipe->path_length);
    } else {
      snprintf(buffer, sizeof(buffer), "critical,CA:TRUE");
    }
    add_extension(certificate, NID_basic_constraints, 1, buffer);
    /* An authority which may not sign certificates still says so, and crlSign is what the
       generator this replaces put there as well */
    add_extension(certificate, NID_key_usage, 1,
                  aRecipe->key_cert_sign ? "critical,keyCertSign,cRLSign" : "critical,cRLSign");
  } else {
    add_extension(certificate, NID_basic_constraints, 1, "critical,CA:FALSE");
    add_extension(certificate, NID_key_usage, 1, "critical,digitalSignature");
    add_extension(certificate, NID_ext_key_usage, 0,
                  aRecipe->server_authentication ? "serverAuth" : "clientAuth");
  }

  if (aRecipe->dns_name) {
    snprintf(buffer, sizeof(buffer), "DNS:%s", aRecipe->dns_name);
    add_extension(certificate, NID_subject_alt_name, 0, buffer);
  }

  if (!X509_sign(certificate, aKeys[aRecipe->signing_key], EVP_sha256())) {
    die("signing failed");
  }

  ASN1_TIME_free(not_after);
  ASN1_TIME_free(not_before);
  X509_NAME_free(issuer);
  X509_NAME_free(subject);
  return certificate;
}

static void emit_pascal_array(const char *aName, const unsigned char *aData, int aSize) {
  int index;
  printf("       %s:array[0..%d] of TRNLUInt8=\r\n        (\r\r\n", aName, aSize - 1);
  for (index = 0; index < aSize; index++) {
    if ((index % 12) == 0) {
      printf("         ");
    }
    printf("$%02x", aData[index]);
    if (index < (aSize - 1)) {
      printf(",");
      if ((index % 12) == 11) {
        printf("\r\r\n");
      }
    }
  }
  printf("\r\n        );\r\r\n");
}

int main(int argc, char **argv) {
  EVP_PKEY *keys[KEY_COUNT];
  int index;
  /* Rerunning this does not reproduce the file it wrote: OpenSSL signs ECDSA with a random k, so
   * every signature comes out different while everything else stays put. The certificates are
   * therefore written once and kept, and this flag exists so that something can be added to the
   * unit without rewriting the thirteen chains underneath it. */
  int keysOnly = (argc > 1) && (strcmp(argv[1], "--public-keys-only") == 0);

  /* subject, issuer, subject key, signing key, CA, pathlen, keyCertSign,
     notBefore, notAfter, dNSName, serverAuth, serial */
  static const Recipe RECIPES[] = {
    {"R", "R", KEY_ROOT,  KEY_ROOT,  1, -1, 1,    0, 3650, NULL,      1,  1},
    {"I", "R", KEY_INTER, KEY_ROOT,  1,  0, 1,    0, 3650, NULL,      1,  2},
    {"I", "R", KEY_INTER, KEY_ROOT,  0, -1, 1,    0, 3650, NULL,      1,  3},
    {"I", "R", KEY_INTER, KEY_ROOT,  1,  0, 0,    0, 3650, NULL,      1,  4},
    {"I", "R", KEY_INTER, KEY_ROOT,  1,  1, 1,    0, 3650, NULL,      1,  5},
    {"S", "I", KEY_SUB,   KEY_INTER, 1, -1, 1,    0, 3650, NULL,      1,  6},
    {"L", "I", KEY_LEAF,  KEY_INTER, 0, -1, 1,    0, 3650, HOST_NAME, 1,  7},
    {"L", "S", KEY_LEAF,  KEY_SUB,   0, -1, 1,    0, 3650, HOST_NAME, 1,  8},
    {"L", "I", KEY_LEAF,  KEY_OTHER, 0, -1, 1,    0, 3650, HOST_NAME, 1,  9},
    {"L", "I", KEY_LEAF,  KEY_INTER, 0, -1, 1,    0,   10, HOST_NAME, 1, 10},
    {"L", "I", KEY_LEAF,  KEY_INTER, 0, -1, 1, 3000, 3650, HOST_NAME, 1, 11},
    {"L", "X", KEY_LEAF,  KEY_INTER, 0, -1, 1,    0, 3650, HOST_NAME, 1, 12},
    {"L", "I", KEY_LEAF,  KEY_INTER, 0, -1, 1,    0, 3650, HOST_NAME, 0, 13}
  };
  static const char *const NAMES[] = {
    "Root", "Intermediate", "IntermediateNotACA", "IntermediateWithoutKeyCertSign",
    "IntermediateAllowingOneMore", "SubIntermediate", "Leaf", "LeafUnderSubIntermediate",
    "LeafSignedByAStranger", "LeafExpired", "LeafNotYetValid", "LeafWithAnotherIssuerName",
    "LeafForClientAuthentication"
  };
  const int count = (int)(sizeof(RECIPES) / sizeof(RECIPES[0]));

  for (index = 0; index < KEY_COUNT; index++) {
    keys[index] = key_from_seed(KEY_SEEDS[index]);
  }

  if (keysOnly) {
    unsigned char *encoded = NULL;
    int size = i2d_PUBKEY(keys[KEY_LEAF], &encoded);
    if (size <= 0) {
      die("public key DER encode failed");
    }
    emit_pascal_array("LeafPublicKeyInfo", encoded, size);
    OPENSSL_free(encoded);
    encoded = NULL;
    size = i2d_PUBKEY(keys[KEY_OTHER], &encoded);
    if (size <= 0) {
      die("public key DER encode failed");
    }
    emit_pascal_array("StrangerPublicKeyInfo", encoded, size);
    OPENSSL_free(encoded);
    for (index = 0; index < KEY_COUNT; index++) {
      EVP_PKEY_free(keys[index]);
    }
    return 0;
  }

  printf("(* Generated by src/tools/makechainvectors.c - do not edit by hand. *)\r\n");
  printf("unit RNLTestCertificates;\r\n");
  printf("{$ifdef fpc}\r\n");
  printf(" {$mode delphi}\r\n");
  printf("{$endif}\r\n");
  printf("{$h+}\r\n");
  printf("\r\n");
  printf("interface\r\n");
  printf("\r\n");
  printf("uses RNL;\r\n");
  printf("\r\n");
  printf("const RNL_TEST_CERTIFICATE_HOST_NAME=TRNLRawByteString('%s');\r\n", HOST_NAME);
  printf("      // Seconds since the Unix epoch, inside the validity of everything but the two which\r\n");
  printf("      // are meant to be outside it\r\n");
  printf("      RNL_TEST_CERTIFICATE_NOW=TRNLInt64(%lld);\r\n",
         (long long)(BASE_TIME + (100 * DAY)));
  printf("      RNL_TEST_CERTIFICATE_TOO_LATE=TRNLInt64(%lld);\r\n",
         (long long)(BASE_TIME + (3700 * DAY)));
  printf("\r\n");
  printf("type TRNLTestCertificates=record\r\n");
  printf("      public\r\n");
  printf("       const\r\n");

  for (index = 0; index < count; index++) {
    X509 *certificate = build_certificate(&RECIPES[index], keys);
    unsigned char *encoded = NULL;
    int size = i2d_X509(certificate, &encoded);
    if (size <= 0) {
      die("DER encode failed");
    }
    emit_pascal_array(NAMES[index], encoded, size);
    OPENSSL_free(encoded);
    X509_free(certificate);
  }

  /* The leaf's key on its own, in the SubjectPublicKeyInfo encoding RFC 7250 sends instead of a
   * certificate. Written here rather than pulled out of the leaf above by the code under test,
   * for the same reason everything else in this file is written here. */
  {
    unsigned char *encoded = NULL;
    int size = i2d_PUBKEY(keys[KEY_LEAF], &encoded);
    if (size <= 0) {
      die("public key DER encode failed");
    }
    emit_pascal_array("LeafPublicKeyInfo", encoded, size);
    OPENSSL_free(encoded);
  }
  {
    unsigned char *encoded = NULL;
    int size = i2d_PUBKEY(keys[KEY_OTHER], &encoded);
    if (size <= 0) {
      die("public key DER encode failed");
    }
    /* A key which is a key and is not the one that gets pinned, so that a fingerprint which does
     * not match can be told from bytes which are not a key at all */
    emit_pascal_array("StrangerPublicKeyInfo", encoded, size);
    OPENSSL_free(encoded);
  }

  printf("     end;\r\n");
  printf("\r\n");
  printf("implementation\r\n");
  printf("\r\n");
  printf("end.\r\n");

  for (index = 0; index < KEY_COUNT; index++) {
    EVP_PKEY_free(keys[index]);
  }
  return 0;
}
