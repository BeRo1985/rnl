/******************************************************************************
 *                          RNL DTLS 1.2 VECTOR CAPTURE                       *
 ******************************************************************************
 *                                                                            *
 * Captures the DTLS 1.2 vectors which RNL.pas carries in its self tests.     *
 *                                                                            *
 * Runs offline against a real relay and is not part of the suite: it needs   *
 * the network and OpenSSL, neither of which RNL depends on. The output is    *
 * transcribed into RNL.pas by hand, so the suite stays self contained.       *
 *                                                                            *
 * Why a capture and not something built here: the vectors it produces are    *
 * the ones no published document gives and no self built message can stand   *
 * in for.                                                                    *
 *                                                                            *
 *  * The ServerKeyExchange signature covers client_random | server_random |  *
 *    params. A self built one would be signed over whatever the              *
 *    implementation thinks that is, and the two would agree while agreeing   *
 *    with no real server. Fixing the client random is what makes the capture *
 *    usable - the whole signed input can then be reconstructed and checked   *
 *    against the key in the server's own certificate.                        *
 *                                                                            *
 *  * The key schedule vectors come from a handshake which completed: the     *
 *    server accepted the Finished computed from these numbers and sent one   *
 *    back which verified against the same derivation. That pins the          *
 *    transcript rule of RFC 6347 section 4.2.6, the master secret, the key   *
 *    block and the verify data of both directions, in one go, against        *
 *    somebody else's code.                                                   *
 *                                                                            *
 * One thing this found which nothing else would have: the server's handshake *
 * message_seq starts at one and not at zero, because the HelloVerifyRequest  *
 * uses zero. Getting it wrong makes the server silently retransmit its       *
 * flight, with no error of any kind.                                         *
 *                                                                            *
 * Whether the relay honours RFC 7627, and what that derivation produces, is  *
 * the business of emsprobe.c next door.                                      *
 *                                                                            *
 * Build:                                                                     *
 *   cd src/tools && clang -O2 -o capturedtlsvectors capturedtlsvectors.c \   *
 *                        -lcrypto                                            *
 *                                                                            *
 * Run:                                                                       *
 *   ./capturedtlsvectors [host] [port]                                       *
 *                                                                            *
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

#define DEFAULT_HOST "nc-workhorse.rosseaux.com"
#define DEFAULT_PORT "5349"

/* Fixed, so that a rerun changes only what the server chooses and the vectors stay comparable */
static const char *const EPHEMERAL_HEX =
  "1122334455667788990011223344556677889900112233445566778899001122";

static const unsigned char VERSION[2] = { 0xfe, 0xfd };

static void die(const char *aWhat) {
  fprintf(stderr, "capturedtlsvectors: %s\n", aWhat);
  exit(1);
}

/* A growable byte buffer, which is all the message building here needs */
typedef struct {
  unsigned char *data;
  size_t size;
  size_t capacity;
} Buffer;

static void buffer_initialize(Buffer *aBuffer) {
  aBuffer->data = NULL;
  aBuffer->size = 0;
  aBuffer->capacity = 0;
}

static void buffer_append(Buffer *aBuffer, const void *aData, size_t aSize) {
  if ((aBuffer->size + aSize) > aBuffer->capacity) {
    size_t capacity = (aBuffer->capacity > 0) ? aBuffer->capacity : 256;
    while (capacity < (aBuffer->size + aSize)) {
      capacity *= 2;
    }
    aBuffer->data = (unsigned char *)realloc(aBuffer->data, capacity);
    if (!aBuffer->data) {
      die("out of memory");
    }
    aBuffer->capacity = capacity;
  }
  if (aSize > 0) {
    memcpy(aBuffer->data + aBuffer->size, aData, aSize);
  }
  aBuffer->size += aSize;
}

static void buffer_byte(Buffer *aBuffer, unsigned aValue) {
  unsigned char byte = (unsigned char)aValue;
  buffer_append(aBuffer, &byte, 1);
}

static void buffer_uint16(Buffer *aBuffer, unsigned aValue) {
  buffer_byte(aBuffer, (aValue >> 8) & 0xff);
  buffer_byte(aBuffer, aValue & 0xff);
}

static void buffer_uint24(Buffer *aBuffer, unsigned long aValue) {
  buffer_byte(aBuffer, (unsigned)((aValue >> 16) & 0xff));
  buffer_byte(aBuffer, (unsigned)((aValue >> 8) & 0xff));
  buffer_byte(aBuffer, (unsigned)(aValue & 0xff));
}

static void buffer_free(Buffer *aBuffer) {
  free(aBuffer->data);
  buffer_initialize(aBuffer);
}

/* RFC 5246 section 5. A(0) = label|seed, A(i) = HMAC(secret, A(i-1)), and the output is
   HMAC(secret, A(i)|label|seed) concatenated until it is long enough. */
static void prf(unsigned char *aOutput, size_t aOutputSize,
                const unsigned char *aSecret, size_t aSecretSize,
                const char *aLabel,
                const unsigned char *aSeed, size_t aSeedSize) {
  Buffer seed;
  unsigned char a[EVP_MAX_MD_SIZE];
  unsigned int a_size = 0;
  size_t done = 0;

  buffer_initialize(&seed);
  buffer_append(&seed, aLabel, strlen(aLabel));
  buffer_append(&seed, aSeed, aSeedSize);

  if (!HMAC(EVP_sha256(), aSecret, (int)aSecretSize, seed.data, seed.size, a, &a_size)) {
    die("hmac failed");
  }

  while (done < aOutputSize) {
    unsigned char block[EVP_MAX_MD_SIZE];
    unsigned int block_size = 0;
    Buffer input;
    size_t take;

    buffer_initialize(&input);
    buffer_append(&input, a, a_size);
    buffer_append(&input, seed.data, seed.size);
    if (!HMAC(EVP_sha256(), aSecret, (int)aSecretSize, input.data, input.size,
              block, &block_size)) {
      die("hmac failed");
    }
    buffer_free(&input);

    take = aOutputSize - done;
    if (take > block_size) {
      take = block_size;
    }
    memcpy(aOutput + done, block, take);
    done += take;

    if (!HMAC(EVP_sha256(), aSecret, (int)aSecretSize, a, a_size, a, &a_size)) {
      die("hmac failed");
    }
  }

  buffer_free(&seed);
}

/* One DTLS record around a payload */
static void write_record(Buffer *aOut, unsigned long long aSequenceNumber,
                         const unsigned char *aPayload, size_t aPayloadSize,
                         unsigned aContentType, unsigned aEpoch) {
  int shift;
  buffer_byte(aOut, aContentType);
  buffer_append(aOut, VERSION, 2);
  buffer_uint16(aOut, aEpoch);
  for (shift = 40; shift >= 0; shift -= 8) {
    buffer_byte(aOut, (unsigned)((aSequenceNumber >> shift) & 0xff));
  }
  buffer_uint16(aOut, (unsigned)aPayloadSize);
  buffer_append(aOut, aPayload, aPayloadSize);
}

/* One handshake message as a single fragment, which is also the form the transcript hashes */
static void write_framed(Buffer *aOut, unsigned aMessageType, unsigned aMessageSequence,
                         const unsigned char *aBody, size_t aBodySize) {
  buffer_byte(aOut, aMessageType);
  buffer_uint24(aOut, aBodySize);
  buffer_uint16(aOut, aMessageSequence);
  buffer_uint24(aOut, 0);
  buffer_uint24(aOut, aBodySize);
  buffer_append(aOut, aBody, aBodySize);
}

static void write_extension(Buffer *aOut, unsigned aType,
                            const unsigned char *aData, size_t aSize) {
  buffer_uint16(aOut, aType);
  buffer_uint16(aOut, (unsigned)aSize);
  buffer_append(aOut, aData, aSize);
}

static void build_client_hello(Buffer *aOut, const unsigned char *aClientRandom,
                               const unsigned char *aCookie, size_t aCookieSize,
                               int aExtendedMasterSecret) {
  Buffer extensions;
  unsigned char groups[4] = { 0x00, 0x02, 0x00, 0x17 };      /* secp256r1 */
  unsigned char formats[2] = { 0x01, 0x00 };                 /* uncompressed */
  unsigned char algorithms[6] = { 0x00, 0x04, 0x04, 0x03, 0x05, 0x03 };

  buffer_initialize(&extensions);
  write_extension(&extensions, 10, groups, sizeof(groups));
  write_extension(&extensions, 11, formats, sizeof(formats));
  write_extension(&extensions, 13, algorithms, sizeof(algorithms));
  if (aExtendedMasterSecret) {
    write_extension(&extensions, 23, NULL, 0);
  }

  buffer_append(aOut, VERSION, 2);
  buffer_append(aOut, aClientRandom, 32);
  buffer_byte(aOut, 0);                       /* no session id */
  buffer_byte(aOut, (unsigned)aCookieSize);
  buffer_append(aOut, aCookie, aCookieSize);
  buffer_uint16(aOut, 2);
  buffer_byte(aOut, 0xcc);                    /* ECDHE-ECDSA-CHACHA20-POLY1305 */
  buffer_byte(aOut, 0xa9);
  buffer_byte(aOut, 1);
  buffer_byte(aOut, 0);                       /* compression: none */
  buffer_uint16(aOut, (unsigned)extensions.size);
  buffer_append(aOut, extensions.data, extensions.size);
  buffer_free(&extensions);
}

/* Everything which arrives until the socket goes quiet */
static void collect(int aSocket, Buffer *aOut) {
  for (;;) {
    unsigned char datagram[4096];
    ssize_t got = recv(aSocket, datagram, sizeof(datagram), 0);
    if (got <= 0) {
      break;
    }
    buffer_append(aOut, datagram, (size_t)got);
  }
}

/* Records to reassembled handshake messages, keeping each one's message_seq */
typedef struct {
  int present;
  unsigned sequence;
  Buffer body;
} Message;

static void parse_flight(const unsigned char *aFlight, size_t aFlightSize, Message *aMessages) {
  size_t position = 0;
  while ((position + 13) <= aFlightSize) {
    size_t length = ((size_t)aFlight[position + 11] << 8) | aFlight[position + 12];
    const unsigned char *fragment = aFlight + position + 13;
    size_t q = 0;
    if ((position + 13 + length) > aFlightSize) {
      break;
    }
    position += 13 + length;
    while ((q + 12) <= length) {
      unsigned type = fragment[q];
      size_t total = ((size_t)fragment[q + 1] << 16) | ((size_t)fragment[q + 2] << 8) |
                     fragment[q + 3];
      unsigned sequence = ((unsigned)fragment[q + 4] << 8) | fragment[q + 5];
      size_t offset = ((size_t)fragment[q + 6] << 16) | ((size_t)fragment[q + 7] << 8) |
                      fragment[q + 8];
      size_t piece = ((size_t)fragment[q + 9] << 16) | ((size_t)fragment[q + 10] << 8) |
                     fragment[q + 11];
      if ((q + 12 + piece) > length) {
        break;
      }
      if (type < 32) {
        Message *message = &aMessages[type];
        if (!message->present) {
          message->present = 1;
          message->sequence = sequence;
          buffer_initialize(&message->body);
          buffer_append(&message->body, NULL, 0);
          message->body.data = (unsigned char *)calloc(total > 0 ? total : 1, 1);
          message->body.size = total;
          message->body.capacity = total > 0 ? total : 1;
        }
        if ((offset + piece) <= message->body.size) {
          memcpy(message->body.data + offset, fragment + q + 12, piece);
        }
      }
      q += 12 + piece;
    }
  }
}

static void protect_record(Buffer *aOut, const unsigned char *aKey, const unsigned char *aIV,
                           unsigned aEpoch, unsigned long long aSequenceNumber,
                           unsigned aContentType,
                           const unsigned char *aBody, size_t aBodySize) {
  unsigned char number[8];
  unsigned char nonce[12];
  unsigned char associated[13];
  unsigned char *ciphertext = (unsigned char *)malloc(aBodySize + 16);
  EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
  int length = 0;
  int index;

  if (!ciphertext || !context) {
    die("out of memory");
  }

  number[0] = (unsigned char)((aEpoch >> 8) & 0xff);
  number[1] = (unsigned char)(aEpoch & 0xff);
  for (index = 0; index < 6; index++) {
    number[2 + index] = (unsigned char)((aSequenceNumber >> ((5 - index) * 8)) & 0xff);
  }

  memcpy(nonce, aIV, 12);
  for (index = 0; index < 8; index++) {
    nonce[4 + index] ^= number[index];
  }

  memcpy(associated, number, 8);
  associated[8] = (unsigned char)aContentType;
  associated[9] = VERSION[0];
  associated[10] = VERSION[1];
  associated[11] = (unsigned char)((aBodySize >> 8) & 0xff);
  associated[12] = (unsigned char)(aBodySize & 0xff);

  if ((EVP_EncryptInit_ex(context, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1) ||
      (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1) ||
      (EVP_EncryptInit_ex(context, NULL, NULL, aKey, nonce) != 1) ||
      (EVP_EncryptUpdate(context, NULL, &length, associated, sizeof(associated)) != 1) ||
      (EVP_EncryptUpdate(context, ciphertext, &length, aBody, (int)aBodySize) != 1)) {
    die("encrypt failed");
  }
  {
    int final = 0;
    if ((EVP_EncryptFinal_ex(context, ciphertext + length, &final) != 1) ||
        (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_GET_TAG, 16,
                             ciphertext + aBodySize) != 1)) {
      die("encrypt failed");
    }
  }
  EVP_CIPHER_CTX_free(context);

  write_record(aOut, aSequenceNumber, ciphertext, aBodySize + 16, aContentType, aEpoch);
  free(ciphertext);
}

static int unprotect_record(unsigned char *aOut, size_t *aOutSize,
                            const unsigned char *aKey, const unsigned char *aIV,
                            unsigned aEpoch, unsigned long long aSequenceNumber,
                            unsigned aContentType,
                            const unsigned char *aFragment, size_t aFragmentSize) {
  unsigned char number[8];
  unsigned char nonce[12];
  unsigned char associated[13];
  size_t plain = aFragmentSize - 16;
  EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
  int length = 0;
  int index;
  int ok;

  if (aFragmentSize < 16) {
    return 0;
  }

  number[0] = (unsigned char)((aEpoch >> 8) & 0xff);
  number[1] = (unsigned char)(aEpoch & 0xff);
  for (index = 0; index < 6; index++) {
    number[2 + index] = (unsigned char)((aSequenceNumber >> ((5 - index) * 8)) & 0xff);
  }
  memcpy(nonce, aIV, 12);
  for (index = 0; index < 8; index++) {
    nonce[4 + index] ^= number[index];
  }
  memcpy(associated, number, 8);
  associated[8] = (unsigned char)aContentType;
  associated[9] = VERSION[0];
  associated[10] = VERSION[1];
  associated[11] = (unsigned char)((plain >> 8) & 0xff);
  associated[12] = (unsigned char)(plain & 0xff);

  ok = (EVP_DecryptInit_ex(context, EVP_chacha20_poly1305(), NULL, NULL, NULL) == 1) &&
       (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1) &&
       (EVP_DecryptInit_ex(context, NULL, NULL, aKey, nonce) == 1) &&
       (EVP_DecryptUpdate(context, NULL, &length, associated, sizeof(associated)) == 1) &&
       (EVP_DecryptUpdate(context, aOut, &length, aFragment, (int)plain) == 1) &&
       (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_TAG, 16,
                            (void *)(aFragment + plain)) == 1);
  if (ok) {
    int final = 0;
    ok = EVP_DecryptFinal_ex(context, aOut + length, &final) == 1;
  }
  EVP_CIPHER_CTX_free(context);
  *aOutSize = plain;
  return ok;
}

static EVP_PKEY *ephemeral_key(unsigned char *aPublicPoint, size_t *aPublicPointSize) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  BIGNUM *priv = NULL;
  EC_POINT *pub = NULL;
  OSSL_PARAM_BLD *build = OSSL_PARAM_BLD_new();
  OSSL_PARAM *params = NULL;
  EVP_PKEY_CTX *context = NULL;
  EVP_PKEY *key = NULL;

  if (!group || !build || !BN_hex2bn(&priv, EPHEMERAL_HEX)) {
    die("ephemeral key setup failed");
  }
  pub = EC_POINT_new(group);
  if (!pub || !EC_POINT_mul(group, pub, priv, NULL, NULL, NULL)) {
    die("point multiply failed");
  }
  *aPublicPointSize = EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED,
                                         aPublicPoint, 133, NULL);
  if (!OSSL_PARAM_BLD_push_utf8_string(build, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) ||
      !OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_PRIV_KEY, priv) ||
      !OSSL_PARAM_BLD_push_octet_string(build, OSSL_PKEY_PARAM_PUB_KEY,
                                        aPublicPoint, *aPublicPointSize)) {
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

static EVP_PKEY *peer_key(const unsigned char *aPoint, size_t aPointSize) {
  OSSL_PARAM_BLD *build = OSSL_PARAM_BLD_new();
  OSSL_PARAM *params = NULL;
  EVP_PKEY_CTX *context = NULL;
  EVP_PKEY *key = NULL;
  if (!build ||
      !OSSL_PARAM_BLD_push_utf8_string(build, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) ||
      !OSSL_PARAM_BLD_push_octet_string(build, OSSL_PKEY_PARAM_PUB_KEY, aPoint, aPointSize)) {
    die("peer parameter build failed");
  }
  params = OSSL_PARAM_BLD_to_param(build);
  context = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
  if (!params || !context || (EVP_PKEY_fromdata_init(context) <= 0) ||
      (EVP_PKEY_fromdata(context, &key, EVP_PKEY_PUBLIC_KEY, params) <= 0)) {
    die("peer key assembly failed");
  }
  EVP_PKEY_CTX_free(context);
  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(build);
  return key;
}

static void emit_pascal(const char *aName, const unsigned char *aData, size_t aSize) {
  size_t index;
  printf("      %s:array[0..%zu] of TRNLUInt8=\n       (\n", aName, aSize - 1);
  for (index = 0; index < aSize; index++) {
    if ((index % 12) == 0) {
      printf("        ");
    }
    printf("$%02x", aData[index]);
    if (index < (aSize - 1)) {
      printf(",");
      if ((index % 12) == 11) {
        printf("\n");
      }
    }
  }
  printf("\n       );\n");
}

int main(int argc, char **argv) {
  const char *host = DEFAULT_HOST;
  const char *port = DEFAULT_PORT;
  const int extended = 0;
  int positional = 0;
  int index;

  struct addrinfo hints, *address = NULL;
  int socket_handle;
  struct timeval timeout;

  unsigned char client_random[32];
  unsigned char cookie[64];
  size_t cookie_size = 0;
  Buffer out, hello, framed, flight, transcript;
  Message messages[32];
  unsigned char answer[4096];
  ssize_t got;

  for (index = 1; index < argc; index++) {
    if (positional == 0) {
      host = argv[index];
      positional++;
    } else {
      port = argv[index];
      positional++;
    }
  }

  for (index = 0; index < 32; index++) {
    client_random[index] = (unsigned char)index;
    messages[index].present = 0;
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  if (getaddrinfo(host, port, &hints, &address) != 0) {
    die("cannot resolve the host");
  }
  socket_handle = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
  if (socket_handle < 0) {
    die("no socket");
  }
  if (connect(socket_handle, address->ai_addr, address->ai_addrlen) != 0) {
    die("cannot connect the socket");
  }
  timeout.tv_sec = 4;
  timeout.tv_usec = 0;
  setsockopt(socket_handle, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

  /* The first ClientHello, which only ever earns a cookie */
  buffer_initialize(&hello);
  build_client_hello(&hello, client_random, cookie, 0, extended);
  buffer_initialize(&framed);
  write_framed(&framed, 1, 0, hello.data, hello.size);
  buffer_initialize(&out);
  write_record(&out, 0, framed.data, framed.size, 22, 0);
  if (send(socket_handle, out.data, out.size, 0) < 0) {
    die("send failed");
  }
  buffer_free(&out);
  buffer_free(&framed);
  buffer_free(&hello);

  got = recv(socket_handle, answer, sizeof(answer), 0);
  if (got < 26) {
    die("no HelloVerifyRequest came back");
  }
  cookie_size = answer[27];
  if ((size_t)got < (28 + cookie_size)) {
    die("the HelloVerifyRequest does not add up");
  }
  memcpy(cookie, answer + 28, cookie_size);

  /* The second one, with the cookie. The transcript begins here: the cookie exchange is left
     out of it, RFC 6347 section 4.2.6. */
  buffer_initialize(&hello);
  build_client_hello(&hello, client_random, cookie, cookie_size, extended);
  buffer_initialize(&framed);
  write_framed(&framed, 1, 1, hello.data, hello.size);
  buffer_initialize(&out);
  write_record(&out, 1, framed.data, framed.size, 22, 0);
  if (send(socket_handle, out.data, out.size, 0) < 0) {
    die("send failed");
  }
  buffer_free(&out);

  buffer_initialize(&transcript);
  buffer_append(&transcript, framed.data, framed.size);
  buffer_free(&framed);
  buffer_free(&hello);

  buffer_initialize(&flight);
  collect(socket_handle, &flight);
  parse_flight(flight.data, flight.size, messages);
  if (!messages[2].present || !messages[11].present || !messages[12].present ||
      !messages[14].present) {
    die("the server flight is incomplete");
  }

  {
    const unsigned char *server_hello = messages[2].body.data;
    const unsigned char *certificate = messages[11].body.data;
    const unsigned char *key_exchange = messages[12].body.data;
    size_t key_exchange_size = messages[12].body.size;
    unsigned char server_random[32];
    size_t point_length;
    size_t parameters_size;
    size_t certificate_size;
    const unsigned char *leaf_bytes;
    X509 *leaf;
    EVP_PKEY *leaf_key;
    EVP_PKEY *ours;
    EVP_PKEY *theirs;
    EVP_PKEY_CTX *derive;
    unsigned char our_point[133];
    size_t our_point_size = 0;
    unsigned char pre_master[64];
    size_t pre_master_size = sizeof(pre_master);
    Buffer signed_input, key_exchange_body;
    const unsigned char *signature;
    size_t signature_size;
    unsigned char master[48];
    unsigned char key_block[88];
    unsigned char session_hash[32];
    unsigned char verify_data[12];
    unsigned char transcript_hash[32];
    int types[4] = { 2, 11, 12, 14 };
    int which;

    memcpy(server_random, server_hello + 2, 32);

    for (which = 0; which < 4; which++) {
      Buffer piece;
      buffer_initialize(&piece);
      write_framed(&piece, (unsigned)types[which], messages[types[which]].sequence,
                   messages[types[which]].body.data, messages[types[which]].body.size);
      buffer_append(&transcript, piece.data, piece.size);
      buffer_free(&piece);
    }

    point_length = key_exchange[3];
    parameters_size = 4 + point_length;

    certificate_size = ((size_t)certificate[3] << 16) | ((size_t)certificate[4] << 8) |
                       certificate[5];
    leaf_bytes = certificate + 6;
    leaf = d2i_X509(NULL, &leaf_bytes, (long)certificate_size);
    if (!leaf) {
      die("the leaf certificate does not parse");
    }
    leaf_key = X509_get_pubkey(leaf);

    signature = key_exchange + parameters_size + 4;
    signature_size = key_exchange_size - (parameters_size + 4);

    buffer_initialize(&signed_input);
    buffer_append(&signed_input, client_random, 32);
    buffer_append(&signed_input, server_random, 32);
    buffer_append(&signed_input, key_exchange, parameters_size);
    {
      EVP_MD_CTX *verify = EVP_MD_CTX_new();
      if (!verify ||
          (EVP_DigestVerifyInit(verify, NULL, EVP_sha256(), NULL, leaf_key) != 1) ||
          (EVP_DigestVerify(verify, signature, signature_size,
                            signed_input.data, signed_input.size) != 1)) {
        die("the ServerKeyExchange signature does not verify");
      }
      EVP_MD_CTX_free(verify);
    }
    printf("# the ServerKeyExchange signature verifies over the two randoms and the parameters\n");

    ours = ephemeral_key(our_point, &our_point_size);
    theirs = peer_key(key_exchange + 4, point_length);
    derive = EVP_PKEY_CTX_new(ours, NULL);
    if (!derive || (EVP_PKEY_derive_init(derive) <= 0) ||
        (EVP_PKEY_derive_set_peer(derive, theirs) <= 0) ||
        (EVP_PKEY_derive(derive, pre_master, &pre_master_size) <= 0)) {
      die("the shared secret could not be derived");
    }
    EVP_PKEY_CTX_free(derive);

    buffer_initialize(&key_exchange_body);
    buffer_byte(&key_exchange_body, (unsigned)our_point_size);
    buffer_append(&key_exchange_body, our_point, our_point_size);
    {
      Buffer piece;
      buffer_initialize(&piece);
      write_framed(&piece, 16, 2, key_exchange_body.data, key_exchange_body.size);
      buffer_append(&transcript, piece.data, piece.size);
      buffer_free(&piece);
    }

    SHA256(transcript.data, transcript.size, session_hash);

    if (extended) {
      /* RFC 7627: the two randoms give way to the hash of everything up to and including the
         ClientKeyExchange */
      prf(master, sizeof(master), pre_master, pre_master_size,
          "extended master secret", session_hash, sizeof(session_hash));
    } else {
      unsigned char seed[64];
      memcpy(seed, client_random, 32);
      memcpy(seed + 32, server_random, 32);
      prf(master, sizeof(master), pre_master, pre_master_size,
          "master secret", seed, sizeof(seed));
    }
    {
      unsigned char seed[64];
      memcpy(seed, server_random, 32);
      memcpy(seed + 32, client_random, 32);
      prf(key_block, sizeof(key_block), master, sizeof(master),
          "key expansion", seed, sizeof(seed));
    }
    prf(verify_data, sizeof(verify_data), master, sizeof(master),
        "client finished", session_hash, sizeof(session_hash));

    /* ClientKeyExchange, ChangeCipherSpec and the protected Finished, all in one datagram */
    buffer_initialize(&out);
    {
      Buffer piece;
      unsigned char one = 1;
      buffer_initialize(&piece);
      write_framed(&piece, 16, 2, key_exchange_body.data, key_exchange_body.size);
      write_record(&out, 2, piece.data, piece.size, 22, 0);
      buffer_free(&piece);
      write_record(&out, 3, &one, 1, 20, 0);
      buffer_initialize(&piece);
      write_framed(&piece, 20, 3, verify_data, sizeof(verify_data));
      protect_record(&out, key_block, key_block + 64, 1, 0, 22, piece.data, piece.size);
      buffer_free(&piece);
    }
    if (send(socket_handle, out.data, out.size, 0) < 0) {
      die("send failed");
    }
    buffer_free(&out);

    {
      Buffer reply;
      size_t position = 0;
      int accepted = 0;
      unsigned char expected[12];
      Buffer with_finished;

      buffer_initialize(&with_finished);
      buffer_append(&with_finished, transcript.data, transcript.size);
      {
        Buffer piece;
        buffer_initialize(&piece);
        write_framed(&piece, 20, 3, verify_data, sizeof(verify_data));
        buffer_append(&with_finished, piece.data, piece.size);
        buffer_free(&piece);
      }
      SHA256(with_finished.data, with_finished.size, transcript_hash);
      prf(expected, sizeof(expected), master, sizeof(master),
          "server finished", transcript_hash, sizeof(transcript_hash));
      buffer_free(&with_finished);

      buffer_initialize(&reply);
      collect(socket_handle, &reply);
      while ((position + 13) <= reply.size) {
        unsigned content_type = reply.data[position];
        unsigned epoch = ((unsigned)reply.data[position + 3] << 8) | reply.data[position + 4];
        unsigned long long sequence = 0;
        size_t length = ((size_t)reply.data[position + 11] << 8) | reply.data[position + 12];
        int shift;
        for (shift = 0; shift < 6; shift++) {
          sequence = (sequence << 8) | reply.data[position + 5 + shift];
        }
        if ((position + 13 + length) > reply.size) {
          break;
        }
        if ((content_type == 22) && (epoch == 1)) {
          unsigned char plain[4096];
          size_t plain_size = 0;
          if (unprotect_record(plain, &plain_size, key_block + 32, key_block + 76,
                               epoch, sequence, content_type,
                               reply.data + position + 13, length)) {
            if ((plain_size >= 24) && (memcmp(plain + 12, expected, 12) == 0)) {
              accepted = 1;
            }
          }
        }
        position += 13 + length;
      }
      buffer_free(&reply);
      close(socket_handle);

      if (!accepted) {
        printf("# the handshake did not complete, so nothing below would be worth anything\n");
        return 1;
      }
      printf("# the handshake completed: the server took our Finished and its own verified\n");
      printf("\n");
    }

    if (extended) {
      emit_pascal("EMSPreMasterSecret", pre_master, pre_master_size);
      emit_pascal("EMSSessionHash", session_hash, sizeof(session_hash));
      emit_pascal("EMSExpectedMasterSecret", master, sizeof(master));
      emit_pascal("EMSExpectedClientVerifyData", verify_data, sizeof(verify_data));
    } else {
      emit_pascal("CapturedClientRandom", client_random, sizeof(client_random));
      emit_pascal("CapturedServerRandom", server_random, sizeof(server_random));
      emit_pascal("CapturedServerHello", messages[2].body.data, messages[2].body.size);
      emit_pascal("CapturedServerKeyExchange", key_exchange, key_exchange_size);
      emit_pascal("PreMasterSecret", pre_master, pre_master_size);
      emit_pascal("ExpectedMasterSecret", master, sizeof(master));
      emit_pascal("ExpectedKeyBlock", key_block, sizeof(key_block));
      emit_pascal("TranscriptHash", session_hash, sizeof(session_hash));
      emit_pascal("ExpectedClientVerifyData", verify_data, sizeof(verify_data));
    }

    EVP_PKEY_free(theirs);
    EVP_PKEY_free(ours);
    EVP_PKEY_free(leaf_key);
    X509_free(leaf);
  }

  freeaddrinfo(address);
  return 0;
}
