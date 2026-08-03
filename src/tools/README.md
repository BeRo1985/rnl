# RNL tools

Five programs which are deliberately **not** part of the test suite. Two reasons run through all of
them: they need something RNL does not depend on — the internet, or OpenSSL — and the suite next door
is hermetic and has to stay that way.

| Tool | What it does |
| --- | --- |
| `turnprobe.dpr` | Drives RNL's STUN and TURN client against a real relay |
| `dtlsprobe.dpr` | Drives RNL's DTLS client through a handshake with a real relay |
| `capturedtlsvectors.c` | Captures the DTLS 1.2 vectors which `RNL.pas` carries in its self tests |
| `emsprobe.c` | Asks a real relay whether it honours RFC 7627, and derives a master secret that way if it does |
| `makechainvectors.c` | Builds the certificate chains and raw public keys `../tests/RNLTestCertificates.pas` holds as vectors |

## Why they exist at all

The suite drives every client against a stub built out of RNL's own code. A handshake completing there
proves the two halves agree with **each other** and says nothing about whether they agree with anybody
else. These five are where the other end is a stranger.

* `turnprobe` and `dtlsprobe` ask a real coturn, or anything else which will answer. `dtlsprobe` is
  the only thing which shows DTLS interoperability at all, and it has earned its keep twice: it found
  that a relay's chain ends with a root cross signed using `sha256WithRSAEncryption`, which RNL cannot
  parse and was refusing the whole path over — surplus entries above the trust anchor are now ignored,
  as RFC 5280 section 6.1 allows — and, pointed at `openssl s_server`, that RNL was dropping the
  HelloVerifyRequest outright because OpenSSL sends it in a DTLS 1.0 record, which RFC 6347
  section 4.2.1 allows and coturn happens not to do. Six datagrams out, six in, no handshake and no
  error: the kind of failure only a stranger produces.

  It is worth pointing at a plain `openssl s_server` for that reason. A DTLS 1.2 server with the one
  cipher suite RNL offers, and a pinned fingerprint of what it presents:

  ```
  openssl s_server -dtls1_2 -accept 25353 -listen -cert cert.pem -key key.pem \
                   -cipher ECDHE-ECDSA-CHACHA20-POLY1305 [-enable_server_rpk]
  ./dtlsprobe [--rawkey] --pin=$(openssl pkey -in key.pem -pubout -outform DER | sha256sum | cut -c1-64) \
              127.0.0.1 25353
  ```

  With `-enable_server_rpk` on both sides that is RNL's RFC 7250 path against something which is not
  RNL, which is the only way it can be shown at all.
* `capturedtlsvectors` and `emsprobe` produce the anchors no published document gives: a
  ServerKeyExchange signature over `client_random | server_random | params`, a master secret and key
  block a real server agreed with, and the RFC 7627 variant of the same, for which no vectors are
  published anywhere. A self built vector would be signed over whatever the implementation thinks
  those are, and would agree with itself while agreeing with no real server.
* `makechainvectors` builds what cannot be fetched. A real chain gives exactly one valid case; a
  missing CA bit, an exceeded path length, a signature by the wrong key and an expired leaf are what a
  verifier is actually judged on, and no certificate authority will issue those. Built by OpenSSL
  rather than by RNL, because an anchor written by the code under test is no anchor.

## Building and running

The two Pascal ones:

```
cd src/tools
fpc -Mdelphi -O1 -Fu.. -FU. turnprobe.dpr
fpc -Mdelphi -O1 -Fu.. -FU. dtlsprobe.dpr

./turnprobe [username] [password]
./turnprobe --dtls --anchor=<root.der|sha256 hex> [--name=<host name>] [username] [password]
./dtlsprobe [--pin=<sha256>] [--rawkey] <host> [port] [root.der ...]
```

`turnprobe` carries the two relay addresses it asks in the source and takes only credentials on the
command line; without them it still exercises realm, nonce and MESSAGE-INTEGRITY, since a 401 means the
relay read the message and rejected the credentials while a 400 would mean it could not read it.
Without an `--anchor` a DTLS run stops at the certificate, and says so before it tries.

The three C ones need OpenSSL:

```
clang -O2 -o makechainvectors makechainvectors.c -lcrypto
clang -O2 -o capturedtlsvectors capturedtlsvectors.c -lcrypto
clang -O2 -o emsprobe emsprobe.c -lcrypto
```

`makechainvectors` writes `../tests/RNLTestCertificates.pas`; the other two print what is meant to be
transcribed into `RNL.pas` by hand. Note that `makechainvectors` is **not** idempotent: OpenSSL signs
ECDSA with a random k, so a second run reproduces every key but no signature. The thirteen chains are
therefore written once and kept, and `./makechainvectors --public-keys-only` exists so that something
can be added to the unit without rewriting them. All output is checked in, so nothing here has to be run to build or
test RNL — which is the point.

## Their output is checked in, and that is on purpose

Every vector these produce lives in the repository as source. Running any of them again is a way to
*re-derive* an anchor, never a build step. A suite which had to reach a relay to run would fail for
reasons that have nothing to do with the code, and an anchor which is regenerated on every build is
not an anchor but a mirror.
