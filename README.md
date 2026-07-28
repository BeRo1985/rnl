> [!IMPORTANT]
> The primary repository has moved to [git.rosseaux.net/BeRo1985/rnl](https://git.rosseaux.net/BeRo1985/rnl).
> This GitHub repository is kept up-to-date via push mirroring.

# Warning

RNL including its cryptography code is non-audited so far, thus RNL is only intended for real-time games and multimedia applications without processing of any with critical data, but not for serious applications with critical data!

# Description

RNL stands for "Realtime Network Library" 
 
RNL is an UDP-based network library for real-time applications and games, inspired by ENet, yojimbo, libgren, and so on.

RNL is designed around common patterns used in real-time games, which are simulation bound, not I/O bound, and completely stateful, so async IO does not make a lot of sense. Thus the RNL core design is single-threaded, not multi-threaded. But you can use multiple TRNLHost instances inside multiple different threads (one to very few instances per one thread), so that you can host multiple network game matches at the same machine, as long as this one machine is strong and fast enough for hosting multiple network game matches at the same time.

And at game client side, the whole network stuff should run, if possible, in an own (also if possible, CPU-core-pinned) thread, for possible few interferences and other similiar problems. (offtopic: the same also applies to the audio thread, unless one likes possible audio buffer underrun issues and so on, when it did not get enough CPU time at the right time points. :-) )
 
And for larger games with masses of clients in a single game world, you should use several subdivided TRNLHost instances, so that each TRNLHost must handle only few connected clients, in multiple threads and that in turn on multiple physical dedicated servers, which also in turn may communicate with each other to mimic the impression of a single very large game world. At least a single TRNLHost instance is rather designed for typical low client numbers, as these
are the typical case for egoshooters, racing games, and so forth. Or in other words for large game worlds with masses of clients: Divide and conquer (for example with partially sector-border overlapping game world sectors for just as an example of an divide-and-conquer concept idea)

# Support me

[Support me at Patreon](https://www.patreon.com/bero)

# Features

   - Mostly fully object oriented code design
   - IPv6 support
   - Cross platform
       - Windows (with FreePascal and Delphi)
       - Linux (with FreePascal)
       - *BSD (with FreePascal)
       - Android (with FreePascal and Delphi)
       - Darwin (MacOS(X) and iOS) (with FreePascal and Delphi)
   - UDP-based protocol
   - Sequencing
   - Channels
       - With following possible free configurable channel types: 
           - Reliable ordered
           - Reliable unordered
           - Unreliable ordered
           - Unreliable unordered
   - Reliability
   - Fragmentation and reassembly
   - Aggregation
   - Adaptability
   - Portability
   - Possibility of using a peer-to-peer model or even a mixed peer-to-peer and client/server hybrid model instead only a pure client/server model, and of course also of a classic client/server model 
   - Cryptographically secure pseudo-random number generator (CSPRNG)
       - Based on arc4random but with ChaCha20 instead RC4 as the basic building block
       - Multiple sources of entropy (because you should never trust a single source of
         entropy, as it may have a backdoor)
           - Including usage of the rdseed/rdrand instructions on newer x86 processors as an optional additional quasi-hardware-based entropy source, if these instructions are supported by the current running processor
   - Mutual authentication
       - Based on a Station-to-Station (STS) like protocol, which assumes that the parties have signature keys, which are used to sign messages, thereby providing minification security against man-in-the-middle attacks, unlike the basic plain Diffie-Hellman method without any so such extensions.
       - Long-term private/public keys are ED25519 keys and are used only for signing purposes
   - Forward secrecy using elliptic curve ephemeral Diffie-Hellman (curve 25519)
       - The consequence of this along other facts is that each connection always has new different private and public short-term keys on both sides and therefore also new shared secret short-term keys
       - Short-term private/public keys are X25519 keys and the short-term shared secret key is using only for AEAD-based ciphering purposes
   - Authenticated Encryption with Associated Data (AEAD) packet encryption
       - Based on ChaCha20 as cipher and Poly1305 as cryptographic message authentication code
   - Replay protection of application packet data
       - Based on various protection mechanisms at the connection establishment phase and encrypted packet sequence numbers
   - Delayed connection establishment mechanism as an additional attack surface minification mechanism
   - Connection and authentication tokens (as an optional option, where you should have a separate out-of-band communication channel, for example a HTTPS-based master backend for to generate and handle this stuff) as an additional attack surface minification mechanism against DDoS amplification attacks
       - Connection token are transferred in clear text, so that they are checked in a fast way at the first ever data packet from a connection attempt, without the need to decrypt the connection token first before it is possible to check the token, so in order to save CPU time in this point. This option is primarily for use in against DDoS amplification attacks, which means that the server will not respond straight away if the connection token does not match at the first ever data packet from a connection attempt, and thus DDoS amplification attacks would simply go into the nothing. Consequently, these tokens should only be valid for a short period of time, which also applies to the master backend side of your infrastructure.
       - Authentication tokens are transferred encrypted, after the private/public key exchange, shared secret key generation, etc. were successfully processed. Authentication tokens, in contrast to the connection token, are NOT a countermeasure against DDoS-category attacks, but rather authentication tokens are, as the name suggests, only for separate out-of-band communication channel authentication purposes, in other words, as additional protection against unauthorized connections, where you can check it in more detail on your master backend side of your infrastructure, before the "client" can connect to the real server, where all the real action happens.
   - Connection attempt rate limiter
       - Configurable with two constants, burst and period
       - Relay aware: an address which was declared as a relay is limited on two levels at once, a
         bucket per client behind it and a ceiling for the relay as a whole. Behind a relay every
         client arrives under the same address, so a single bucket would let any one of them lock out
         all the others; the clients are told apart by the relayed port, which the relay assigns per
         allocation, and the ceiling is what keeps that from being a way around the limit
   - Configurable bandwidth rate limiter
   - Optional virtual network feature (for example for fast network-API-less local loopback solution for singleplayer game matches, which should be still server/client concept based)
   - Network interference simulator (for example for testcases and so on)
       - Configurable simulated packet loss probability (each for incoming and outgoing packets)
       - Configurable simulated latency (each for incoming and outgoing packets)
       - Configurable simulated jitter (each for incoming and outgoing packets)
       - Configurable simulated duplicate packet probability (each for incoming and outgoing packets)
   - Dynamic connection challenge request response difficulty adjustment mechanism
       - Configurable with a factor value
       - Based on history-smoothing-frames-per-second-style determination mechanism, but just instead frames per second, connection attempts per second
   - More compression algorithms as choices
       - Deflate (a zlib bit-stream compatible LZ77 and canonical Huffman hybrid, only fixed-static-canonical-huffman in this implementation here on compressor side, but the decompressor side is full featured)
       - LZBRRC (a LZ77-style compressor together with an entropy range coder backend)
       - BRRC (a pure order 0 entropy range coder)
   - CRC32C instead CRC32 (without C at the end), and CRC32 (IEEE) as well, which STUN needs for its
     FINGERPRINT attribute
   - Optional handshake transcript binding
       - The signatures of the mutual authentication cover the whole transcript of the handshake,
         including the fields which travel in clear text, rather than only the two ephemeral keys
       - Three modes, off, allowed and required. Off by default, so that existing code keeps behaving
         exactly as it did, down to the same bytes on the wire and the same protocol version; only
         required is fully safe, and allowed exists as a migration step and can be downgraded by an
         attacker rewriting one clear text version field, which is why it says so here
       - The long term public key the counter side proved possession of is available on every
         connection and can be pinned
   - Optional single stage certificates for the mutual authentication
       - One public key of an issuing authority in the client's configuration instead of one pinned key
         per server, which is what pinning cannot do: key rotation, and several servers behind one name.
         Several authority keys are accepted at once, so that rotating the authority itself is not a
         flag day either
       - No chain, no ASN.1, no revocation list. Subject, issuer signature and two validity fields, 104
         bytes, in a fixed area which is all zero when there is none. It does not carry the subject's
         public key although that is what it vouches for: the key is already in the payload as the one
         which signed the handshake, and the signature covers it from there, so there cannot be a second
         copy disagreeing with the first
       - The subject is opaque and RNL never interprets it. No host name concept, no wildcard matching,
         no case folding, no parsing; the issuer puts whatever the deployment uses as an identity into
         it and the client compares byte for byte. That is deliberate: every serious failure of X.509
         name handling comes from the library trying to understand names
       - Validity as two counts of minutes since 1 January 2026, zero for no bound. Minutes rather than
         days because the most useful shape is a short lived certificate issued per session by the same
         thing that already hands out connection and authentication tokens. The wall clock is set by the
         application rather than read from the operating system, and a certificate with a validity
         period is refused outright where there is no clock to hold it against
       - Checked before the client hands over its authentication token, which is the real gain rather
         than the rotation: the server's identity travels in the packet before the one carrying the
         token, so a bearer token is only ever given to a server which has proved who it is
       - Entirely opt in. Without a configured certificate and without an authority key, nothing about
         a handshake changes
   - NAT traversal
       - Candidate gathering: one host candidate per local interface address and socket, one server
         reflexive candidate per STUN server which answers, and a relayed one if a relay is in front
         of the network. Priority and foundation as RFC 8445 computes them, plus serialisation, so
         that the application can carry candidates over whatever signalling it already has
       - STUN client (RFC 8489). FINGERPRINT is included and checked, which is what makes it possible
         for STUN and RNL to share one socket. Usable during startup, and also while a host is being
         serviced, in which case the host answers its own binding requests out of its receive path
       - NAT behaviour discovery, split the way RFC 4787 splits it. The mapping behaviour comes from
         two servers on different hosts, the filtering behaviour from RFC 5780 CHANGE-REQUEST where a
         server offers it and stays unknown where none does. From the two of them plus the counter
         side's, the viability of a direct connection can be predicted before it is attempted rather
         than after a ten second timeout
       - Hole punching. The handshake repetition fans out over every pairing of a local socket with a
         remote candidate, bounded per round so that a candidate list from the counter side cannot
         turn this host into a sender of padded datagrams at every address in it. A four byte punch
         packet opens a mapping without starting a connection, for the side which is being called
       - Two sides connecting to each other at the same time end up with one connection rather than
         two, resolved by comparing the random salts both sides exchange anyway, without a protocol
         field for it
       - One socket per named local address instead of one per address family, for a host which wants
         to decide which interfaces it is reachable on. A peer then keeps the socket its handshake ran
         over, because an answer has to leave where the question came in
   - TURN relay (RFC 8656) for the case a direct path cannot be had at all
       - As a network decorator, so that host and peer never learn about it
       - Allocate, Refresh, CreatePermission and ChannelBind, long term credentials with both
         MESSAGE-INTEGRITY and MESSAGE-INTEGRITY-SHA256, realm and nonce handling including the
         STALE_NONCE retry
       - ChannelData once a channel is bound, which replaces the thirty six bytes of a Send indication
         around every datagram with four. Channel numbers are let go of when they go quiet and come
         back into circulation after the delay RFC 8656 requires
       - IPv6 allocations through REQUESTED-ADDRESS-FAMILY, asked for only where it is needed, since
         the attribute is comprehension required and a relay which does not know it would refuse
       - UDP or TCP as the transport to the relay. TCP is there for the network which lets no UDP out
         at all, which is exactly the case a relay exists for
   - Hash primitives
       - SHA-512 and BLAKE2B for the handshake, plus SHA-256, SHA-1 and MD5 for what STUN and TURN
         need of them. SHA-1 and MD5 are only ever used for the credentials of a relay which speaks
         the older revision, never for anything RNL itself protects, and can be switched off
       - One HMAC implementation for all of them, over a descriptor of the hash rather than a generic
         type parameter, so that it compiles on FreePascal and Delphi alike
   - Cryptography self test callable at run time, so that a build can prove its own primitives against
     the published test vectors instead of assuming them
   - And a lot of more stuff  . . .

# Planned features (a.k.a Todo) in random order of priorities

   - TLS as a transport to the TURN relay. Plain TCP is there, which already covers a network that
     blocks UDP; TLS additionally covers one which only lets TLS out. It needs a TLS stack, which RNL
     does not have and which is a good deal larger than everything around it, so the sensible shape is
     an external library behind a callback interface rather than own code
   - Adaptive congestion control. The measurements are already taken, they are simply not acted upon
     yet, and a relayed path is where it would matter most
   - TODO

# General guidelines for code contributors 

[General guidelines for code contributors](CONTRIBUTING.md)

# License

[zlib License](LICENSE)

# IRC channel

IRC channel #rnl on Freenode

 # Thanks

   - Thanks to Lee Salzman for ENet as inspiration for the base API design implementation ideas
   - Thanks to Glenn Fiedler for inspiration for security-oriented implementation ideas
   - Thanks to Sergey Ignatchenko ("No Bugs" Hare) for inspiration also for security-oriented implementation ideas

