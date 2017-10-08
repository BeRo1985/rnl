(******************************************************************************
 *                        RNL (Realtime Network Library)                      *
 ******************************************************************************
 *                      Version see RNL_VERSION code constant                 *
 ******************************************************************************
 *                                zlib license                                *
 *============================================================================*
 *                                                                            *
 * Copyright (C) 2016-2017, Benjamin Rosseaux (benjamin@rosseaux.de)          *
 *                                                                            *
 * This software is provided 'as-is', without any express or implied          *
 * warranty. In no event will the authors be held liable for any damages      *
 * arising from the use of this software.                                     *
 *                                                                            *
 * Permission is granted to anyone to use this software for any purpose,      *
 * including commercial applications, and to alter it and redistribute it     *
 * freely, subject to the following restrictions:                             *
 *                                                                            *
 * 1. The origin of this software must not be misrepresented; you must not    *
 *    claim that you wrote the original software. If you use this software    *
 *    in a product, an acknowledgement in the product documentation would be  *
 *    appreciated but is not required.                                        *
 * 2. Altered source versions must be plainly marked as such, and must not be *
 *    misrepresented as being the original software.                          *
 * 3. This notice may not be removed or altered from any source distribution. *
 *                                                                            *
 ******************************************************************************
 *                  General guidelines for code contributors                  *
 *============================================================================*
 *                                                                            *
 * 1. Make sure you are legally allowed to make a contribution under the zlib *
 *    license.                                                                *
 * 2. The zlib license header goes at the top of each source file, with       *
 *    appropriate copyright notice.                                           *
 * 3. After a pull request, check the status of your pull request on          *
      http://github.com/BeRo1985/rnl                                          *
 * 4. Write code, which is compatible with newer modern Delphi versions and   *
 *    FreePascal >= 3.0.4, but if needed, make it out-ifdef-able.             *
 * 5. Don't use Delphi-only, FreePascal-only or Lazarus-only libraries/units, *
 *    but if needed, make it out-ifdef-able.                                  *
 * 6. No use of third-party libraries/units as possible, but if needed, make  *
 *    it out-ifdef-able.                                                      *
 * 7. Try to use const when possible.                                         *
 * 8. Make sure to comment out writeln, used while debugging.                 *
 * 9. Make sure the code compiles on 32-bit and 64-bit platforms (x86-32,     *
 *    x86-64, ARM, ARM64, etc.).                                              *
 * 10. Make sure the code runs on platforms with weak and strong memory       *
 *     models without any issues.                                             *
 *                                                                            *
 ******************************************************************************
 *
 * RNL is an UDP-based network library for real-time applications and games, inspired
 * by ENet, yojimbo, libgren, and so on.
 *
 * Thanks to Lee Salzman for ENet as inspiration for the base API design implementation ideas
 * Thanks to Glenn Fiedler for inspiration for security-oriented implementation ideas
 * Thanks to Sergey Ignatchenko ("No Bugs" Hare) for inspiration also for security-oriented
 * implementation ideas
 *
 * Warning: RNL including its cryptography code is non-audited so far, thus RNL is only intended
 *          for real-time games and multimedia applications without processing of any with critical
 *          data, but not for serious applications with critical data!
 *
 * RNL is designed around common patterns used in real-time games, which are simulation bound,
 * not I/O bound, and completely stateful, so async IO does not make a lot of sense. Thus the
 * RNL core design is single-threaded, not multi-threaded. But you can use multiple TRNLHost
 * instances inside multiple different threads (one to very few instances per one thread), so
 * that you can host multiple network game matches at the same machine, as long as this one
 * machine is strong and fast enough for hosting multiple network game matches at the same time.
 *
 * And at game client side, the whole network stuff should run, if possible, in an own
 * (also if possible, CPU-core-pinned) thread, for possible few interferences and other similiar
 * problems. (offtopic: the same also applies to the audio thread, unless one likes possible
 * audio buffer underrun issues and so on, when it did not get enough CPU time at the right
 * time points. :-) )
 *
 * And for larger games with masses of clients in a single game world, you should use several
 * subdivided TRNLHost instances, so that each TRNLHost must handle only few connected clients,
 * in multiple threads and that in turn on multiple physical dedicated servers, which also in
 * turn may communicate with each other to mimic the impression of a single very large game world.
 * At least a single TRNLHost instance is rather designed for typical low client numbers, as these
 * are the typical case for egoshooters, racing games, and so forth. Or in other words for large
 * game worlds with masses of clients: Divide and conquer (for example with partially sector-border
 * overlapping game world sectors for just as an example of an divide-and-conquer concept idea)
 *
 * RNL features:
 *
 *   - Mostly fully object oriented code design
 *   - IPv6 support
 *   - Cross platform
 *       - Windows (with FreePascal and Delphi)
 *       - Linux (with FreePascal)
 *       - *BSD (with FreePascal)
 *       - Android (with FreePascal and Delphi)
 *       - Darwin (MacOS(X) and iOS) (with FreePascal and Delphi)
 *   - UDP-based protocol
 *   - Sequencing
 *   - Channels
 *      - With following possible free configurable channel types:
 *         - Reliable ordered
 *         - Reliable unordered
 *         - Unreliable ordered
 *         - Unreliable unordered
 *   - Reliability
 *   - Fragmentation and reassembly
 *   - Aggregation
 *   - Adaptability
 *   - Portability
 *   - Possibility of using a peer-to-peer model or even a mixed peer-to-peer
 *     and client/server hybrid model instead only a pure client/server model, and
 *     of course also of a classic client/server model
 *   - Cryptographically secure pseudo-random number generator (CSPRNG)
 *       - Based on arc4random but with ChaCha20 instead RC4 as the basic building block
 *       - Multiple sources of entropy (because you should never trust a single source of
 *         entropy, as it may have a backdoor)
 *           - Including usage of the rdseed/rdrand instructions on newer x86 processors
 *             as an optional additional quasi-hardware-based entropy source, if these
 *             instructions are supported by the current running processor
 *   - Mutual authentication
 *       - Based on a Station-to-Station (STS) like protocol, which assumes that the parties
 *         have signature keys, which are used to sign messages, thereby providing minification
 *         security against man-in-the-middle attacks, unlike the basic plain Diffie-Hellman
 *         method without any so such extensions.
 *       - Long-term private/public keys are ED25519 keys and are used only for
 *         signing purposes
 *   - Forward secrecy using elliptic curve ephemeral Diffie-Hellman (curve 25519)
 *       - The consequence of this along other facts is that each connection always has
 *         new different private and public short-term keys on both sides and therefore
 *         also new shared secret short-term keys
 *       - Short-term private/public keys are X25519 keys and the short-term shared
 *         secret key is using only for AEAD-based ciphering purposes
 *   - Authenticated Encryption with Associated Data (AEAD) packet encryption
 *       - Based on ChaCha20 as cipher and Poly1305 as cryptographic message authentication code
 *   - Replay protection of application packet data
 *       - Based on various protection mechanisms at the connection establishment phase and
 *         encrypted packet sequence numbers
 *   - Delayed connection establishment mechanism as an additional attack surface minification
 *     mechanism
 *   - Connection and authentication tokens (as an optional option, where you should have a
 *     separate out-of-band communication channel, for example a HTTPS-based master backend
 *     for to generate and handle this stuff) as an additional attack surface minification
 *     mechanism against DDoS amplification attacks
 *       - Connection token are transferred in clear text, so that they are checked in a fast
 *         way at the first ever data packet from a connection attempt, without the need to
 *         decrypt the connection token first before it is possible to check the token, so
 *         in order to save CPU time in this point. This option is primarily for use in against
 *         DDoS amplification attacks, which means that the server will not respond straight
 *         away if the connection token does not match at the first ever data packet from a
 *         connection attempt, and thus DDoS amplification attacks would simply go into the
 *         nothing. Consequently, these tokens should only be valid for a short period of
 *         time, which also applies to the master backend side of your infrastructure.
 *       - Authentication tokens are transferred encrypted, after the private/public key
 *         exchange, shared secret key generation, etc. were successfully processed.
 *         Authentication tokens, in contrast to the connection token, are NOT a
 *         countermeasure against DDoS-category attacks, but rather authentication tokens are,
 *         as the name suggests, only for separate out-of-band communication channel
 *         authentication purposes, in other words, as additional protection against
 *         unauthorized connections, where you can check it in more detail on your master
 *         backend side of your infrastructure, before the "client" can connect to the
 *         real server, where all the real action happens.
 *   - Connection attempt rate limiter
 *       - Configurable with two constants, burst and period
 *   - Configurable bandwidth rate limiter
 *   - Optional virtual network feature (for example for fast network-API-less local
 *     loopback solution for singleplayer game matches, which should be still server/client
 *     concept based)
 *   - Network interference simulator (for example for testcases and so on)
 *       - Configurable simulated packet loss probability (each for incoming and outgoing packets)
 *       - Configurable simulated latency (each for incoming and outgoing packets)
 *       - Configurable simulated jitter (each for incoming and outgoing packets)
 *       - Configurable simulated duplicate packet probability (each for incoming and outgoing packets)
 *   - Dynamic connection challenge request response difficulty adjustment mechanism
 *       - Configurable with a factor value
 *       - Based on history-smoothing-frames-per-second-style determination mechanism,
 *         but just instead frames per second, connection attempts per second
 *   - More compression algorithms as choices
 *       - Deflate (a zlib bit-stream compatible LZ77 and canonical Huffman hybrid,
 *                  only fixed-static-canonical-huffman in this implementation here on
 *                  compressor side, but the decompressor side is full featured)
 *       - LZBRRC (a LZ77-style compressor together with an entropy range coder backend)
 *       - BRRC (a pure order 0 entropy range coder)
 *   - CRC32C instead CRC32 (without C at the end)
 *   - And a lot of more stuff  . . .
 *
 * Planned features (a.k.a Todo) in random order of priorities:
 *
 * - TODO
 *
 *)
unit RNL;
{$ifdef fpc}
 {$mode delphi}
 {$ifdef CPUI386}
  {$define CPU386}
 {$endif}
 {$ifdef CPU386}
  {$define CPUX86}
  {$asmmode intel}
 {$endif}
 {$ifdef CPUAMD64}
  {$define CPUX64}
  {$asmmode intel}
 {$endif}
 {$ifdef FPC_LITTLE_ENDIAN}
  {$define LITTLE_ENDIAN}
 {$else}
  {$ifdef FPC_BIG_ENDIAN}
   {$define BIG_ENDIAN}
  {$endif}
 {$endif}
 {$define CAN_INLINE}
 {$define HAS_ADVANCED_RECORDS}
{$else}
 {$realcompatibility off}
 {$localsymbols on}
 {$undef CPU64}
 {$ifdef CPU64BITS}
  {$define CPU64}
 {$else}
  {$ifdef CPUX64}
   {$define CPU64}
  {$endif}
 {$endif}
 {$ifndef CPU64}
  {$define CPU32}
 {$endif}
 {$undef CAN_INLINE}
 {$undef HAS_ADVANCED_RECORDS}
 {$define LITTLE_ENDIAN}
 {$ifndef BCB}
  {$ifdef ver120}
   {$define Delphi4or5}
  {$endif}
  {$ifdef ver130}
   {$define Delphi4or5}
  {$endif}
  {$ifdef ver140}
   {$define Delphi6}
  {$endif}
  {$ifdef ver150}
   {$define Delphi7}
  {$endif}
  {$ifdef ver170}
   {$define Delphi2005}
  {$endif}
 {$else}
  {$ifdef ver120}
   {$define Delphi4or5}
   {$define BCB4}
  {$endif}
  {$ifdef ver130}
   {$define Delphi4or5}
  {$endif}
 {$endif}
 {$ifdef conditionalexpressions}
  {$if CompilerVersion>=24.0}
   {$legacyifend on}
  {$ifend}
  {$if CompilerVersion>=14.0}
   {$if CompilerVersion=14.0}
    {$define Delphi6}
   {$ifend}
   {$define Delphi6AndUp}
  {$ifend}
  {$if CompilerVersion>=15.0}
   {$if CompilerVersion=15.0}
    {$define Delphi7}
   {$ifend}
   {$define Delphi7AndUp}
  {$ifend}
  {$if CompilerVersion>=17.0}
   {$if CompilerVersion=17.0}
    {$define Delphi2005}
   {$ifend}
   {$define Delphi2005AndUp}
  {$ifend}
  {$if CompilerVersion>=18.0}
   {$if CompilerVersion=18.0}
    {$define BDS2006}
    {$define Delphi2006}
   {$ifend}
   {$define Delphi2006AndUp}
   {$define CAN_INLINE}
   {$define HAS_ADVANCED_RECORDS}
  {$ifend}
  {$if CompilerVersion>=18.5}
   {$if CompilerVersion=18.5}
    {$define Delphi2007}
   {$ifend}
   {$define Delphi2007AndUp}
  {$ifend}
  {$if CompilerVersion=19.0}
   {$define Delphi2007Net}
  {$ifend}
  {$if CompilerVersion>=20.0}
   {$if CompilerVersion=20.0}
    {$define Delphi2009}
   {$ifend}
   {$define Delphi2009AndUp}
  {$ifend}
  {$if CompilerVersion>=21.0}
   {$if CompilerVersion=21.0}
    {$define Delphi2010}
   {$ifend}
   {$define Delphi2010AndUp}
  {$ifend}
  {$if CompilerVersion>=22.0}
   {$if CompilerVersion=22.0}
    {$define DelphiXE}
   {$ifend}
   {$define DelphiXEAndUp}
  {$ifend}
  {$if CompilerVersion>=23.0}
   {$if CompilerVersion=23.0}
    {$define DelphiXE2}
   {$ifend}
   {$define DelphiXE2AndUp}
  {$ifend}
  {$if CompilerVersion>=24.0}
   {$legacyifend on}
   {$if CompilerVersion=24.0}
    {$define DelphiXE3}
   {$ifend}
   {$define DelphiXE3AndUp}
  {$ifend}
  {$if CompilerVersion>=25.0}
   {$if CompilerVersion=25.0}
    {$define DelphiXE4}
   {$ifend}
   {$define DelphiXE4AndUp}
  {$ifend}
  {$if CompilerVersion>=26.0}
   {$if CompilerVersion=26.0}
    {$define DelphiXE5}
   {$ifend}
   {$define DelphiXE5AndUp}
  {$ifend}
  {$if CompilerVersion>=27.0}
   {$if CompilerVersion=27.0}
    {$define DelphiXE6}
   {$ifend}
   {$define DelphiXE6AndUp}
  {$ifend}
  {$if CompilerVersion>=28.0}
   {$if CompilerVersion=28.0}
    {$define DelphiXE7}
   {$ifend}
   {$define DelphiXE7AndUp}
  {$ifend}
  {$if CompilerVersion>=29.0}
   {$if CompilerVersion=29.0}
    {$define DelphiXE8}
   {$ifend}
   {$define DelphiXE8AndUp}
  {$ifend}
  {$if CompilerVersion>=30.0}
   {$if CompilerVersion=30.0}
    {$define Delphi10Seattle}
   {$ifend}
   {$define Delphi10SeattleAndUp}
  {$ifend}
  {$if CompilerVersion>=31.0}
   {$if CompilerVersion=31.0}
    {$define Delphi10Berlin}
   {$ifend}
   {$define Delphi10BerlinAndUp}
  {$ifend}
 {$endif}
 {$ifndef Delphi4or5}
  {$ifndef BCB}
   {$define Delphi6AndUp}
  {$endif}
   {$ifndef Delphi6}
    {$define BCB6OrDelphi7AndUp}
    {$ifndef BCB}
     {$define Delphi7AndUp}
    {$endif}
    {$ifndef BCB}
     {$ifndef Delphi7}
      {$ifndef Delphi2005}
       {$define BDS2006AndUp}
      {$endif}
     {$endif}
    {$endif}
   {$endif}
 {$endif}
 {$ifdef Delphi6AndUp}
  {$warn symbol_platform off}
  {$warn symbol_deprecated off}
 {$endif}
 {$ifdef DelphiXE2AndUp}
  {$warn implicit_string_cast_loss off}
  {$warn implicit_string_cast off}
  {$warn suspicious_typecast off}
  {$warn unit_platform off}
 {$endif}
{$endif}
{$if defined(Win32) or defined(Win64)}
 {$define Windows}
{$ifend}
{$rangechecks off}
{$extendedsyntax on}
{$writeableconst on}
{$hints off}
{$booleval off}
{$typedaddress off}
{$stackframes off}
{$varstringchecks on}
{$typeinfo on}
{$overflowchecks off}
{$longstrings on}
{$openstrings on}
{$m+}

{$ifndef HAS_ADVANCED_RECORDS}
 {$error "Sorry, but your compiler is too old, because it doesn't support advanced records"}
{$endif}

{$ifndef CAN_INLINE}
 {$error "Sorry, but your compiler is too old, because it doesn't suppont inlined functions"}
{$endif}

interface

uses {$if defined(Posix)}
      // Delphi: Linux, Android, Darwin (MacOS, iOS)
      Posix.Base,
      Posix.NetDB,
      Posix.NetIf,
      Posix.NetinetIn,
      Posix.NetinetIp6,
      Posix.NetinetTCP,
      Posix.NetinetUDP,
      Posix.StrOpts,
      Posix.SysSelect,
      Posix.SysSocket,
      Posix.SysTime,
      Posix.SysTimes,
      Posix.SysTypes,
      Posix.SysWait,
      Posix.Termios,
      Posix.Errno,
      Posix.Unistd,
      System.Net.Socket,
      {$ifdef Linux}
       Linuxapi.KernelIoctl,
      {$endif}
     {$elseif defined(Unix)}
      // FreePascal: Unix, Linux, Android, Darwin (MacOS, iOS)
      BaseUnix,
      Unix,
      UnixType,
      Sockets,
      cnetdb,
      termio,
     {$else}
      // Delphi and FreePascal: Win32, Win64
      Windows,
      MMSystem,
     {$ifend}
     SysUtils,
     Classes,
     SyncObjs,
     TypInfo,
     Math;

{    Generics.Defaults,
     Generics.Collections;}

const RNL_VERSION='1.00.2017.10.08.02.52.0000';

type PPRNLInt8=^PRNLInt8;
     PRNLInt8=^TRNLInt8;
     TRNLInt8={$ifdef fpc}Int8{$else}ShortInt{$endif};

     PPRNLUInt8=^PRNLUInt8;
     PRNLUInt8=^TRNLUInt8;
     TRNLUInt8={$ifdef fpc}UInt8{$else}byte{$endif};

     PPRNLInt16=^PRNLInt16;
     PRNLInt16=^TRNLInt16;
     TRNLInt16={$ifdef fpc}Int16{$else}SmallInt{$endif};

     PPRNLUInt16=^PRNLUInt16;
     PRNLUInt16=^TRNLUInt16;
     TRNLUInt16={$ifdef fpc}UInt16{$else}Word{$endif};

     PPRNLInt32=^PRNLInt32;
     PRNLInt32=^TRNLInt32;
     TRNLInt32={$ifdef fpc}Int32{$else}LongInt{$endif};

     PPRNLUInt32=^PRNLUInt32;
     PRNLUInt32=^TRNLUInt32;
     TRNLUInt32={$ifdef fpc}UInt32{$else}LongWord{$endif};

     PPRNLInt64=^PRNLInt64;
     PRNLInt64=^TRNLInt64;
     TRNLInt64=Int64;

     PPRNLUInt64=^PRNLUInt64;
     PRNLUInt64=^TRNLUInt64;
     TRNLUInt64=UInt64;

     PPRNLUInt64Record=^PRNLUInt64Record;
     PRNLUInt64Record=^TRNLUInt64Record;
     TRNLUInt64Record=record
      case boolean of
       false:(
        {$ifdef BIG_ENDIAN}Hi,Lo{$else}Lo,Hi{$endif}:TRNLUInt32;
       );
       true:(
        Value:TRNLUInt64;
       );
     end;

{$if defined(NEXTGEN)}
     PPRNLChar=^PChar;
     PRNLChar=PChar;
     TRNLChar=Char;
{$else}
     PPRNLChar=^PAnsiChar;
     PRNLChar=PAnsiChar;
     TRNLChar=AnsiChar;

     PPRNLRawByteChar=^PAnsiChar;
     PRNLRawByteChar=PAnsiChar;
     TRNLRawByteChar=AnsiChar;
{$ifend}

     PPRNLPointer=^PRNLPointer;
     PRNLPointer=^TRNLPointer;
     TRNLPointer=Pointer;

     PPRNLPtrUInt=^PRNLPtrUInt;
     PPRNLPtrInt=^PRNLPtrInt;
     PRNLPtrUInt=^TRNLPtrUInt;
     PRNLPtrInt=^TRNLPtrInt;
{$ifdef fpc}
     TRNLPtrUInt=PtrUInt;
     TRNLPtrInt=PtrInt;
 {$undef OldDelphi}
{$else}
 {$ifdef conditionalexpressions}
  {$if CompilerVersion>=23.0}
   {$undef OldDelphi}
     TRNLPtrUInt=NativeUInt;
     TRNLPtrInt=NativeInt;
  {$else}
   {$define OldDelphi}
  {$ifend}
 {$else}
  {$define OldDelphi}
 {$endif}
{$endif}
{$ifdef OldDelphi}
{$ifdef CPU64}
     TRNLPtrUInt=TRNLUInt64;
     TRNLPtrInt=TRNLInt64;
{$else}
     TRNLPtrUInt=TRNLUInt32;
     TRNLPtrI
     nt=TRNLInt32;
{$endif}
{$endif}

     PPRNLSizeUInt=^PRNLSizeUInt;
     PRNLSizeUInt=^TRNLSizeUInt;
     TRNLSizeUInt=TRNLPtrUInt;

     PPRNLSizeInt=^PRNLSizeInt;
     PRNLSizeInt=^TRNLSizeInt;
     TRNLSizeInt=TRNLPtrInt;

     PPRNLNativeUInt=^PRNLNativeUInt;
     PRNLNativeUInt=^TRNLNativeUInt;
     TRNLNativeUInt=TRNLPtrUInt;

     PPRNLNativeInt=^PRNLNativeInt;
     PRNLNativeInt=^TRNLNativeInt;
     TRNLNativeInt=TRNLPtrInt;

     PPRNLSize=^PRNLSizeUInt;
     PRNLSize=^TRNLSizeUInt;
     TRNLSize=TRNLPtrUInt;

     PPRNLPtrDiff=^PRNLPtrDiff;
     PRNLPtrDiff=^TRNLPtrDiff;
     TRNLPtrDiff=TRNLPtrInt;

     PPRNLRawByteString=^PRNLRawByteString;
     PRNLRawByteString=^TRNLRawByteString;
     TRNLRawByteString={$if declared(RawByteString)}RawByteString{$else}AnsiString{$ifend};

     PPRNLUTF8String=^PRNLUTF8String;
     PRNLUTF8String=^TRNLUTF8String;
     TRNLUTF8String={$if declared(UTF8String)}UTF8String{$else}AnsiString{$ifend};

     PPRNLUTF16String=^PRNLUTF16String;
     PRNLUTF16String=^TRNLUTF16String;
     TRNLUTF16String={$if declared(UnicodeString)}UnicodeString{$else}WideString{$ifend};

     PRNLInt8Array=^TRNLUInt8Array;
     TRNLInt8Array=array[0..65535] of TRNLInt8;

     PRNLUInt8Array=^TRNLUInt8Array;
     TRNLUInt8Array=array[0..65535] of TRNLUInt8;

     PRNLInt16Array=^TRNLInt16Array;
     TRNLInt16Array=array[0..65535] of TRNLInt16;

     PRNLUInt16Array=^TRNLUInt16Array;
     TRNLUInt16Array=array[0..65535] of TRNLUInt16;

     PRNLInt32Array=^TRNLInt32Array;
     TRNLInt32Array=array[0..65535] of TRNLInt32;

     PRNLUInt32Array=^TRNLUInt32Array;
     TRNLUInt32Array=array[0..65535] of TRNLUInt32;

     PRNLInt64Array=^TRNLInt64Array;
     TRNLInt64Array=array[0..65535] of TRNLInt64;

     PRNLUInt64Array=^TRNLUInt64Array;
     TRNLUInt64Array=array[0..65535] of TRNLUInt64;

const RNL_PROTOCOL_VERSION_MAJOR=1;
      RNL_PROTOCOL_VERSION_MINOR=0;
      RNL_PROTOCOL_VERSION_PATCH=0;

      RNL_PROTOCOL_VERSION=TRNLUInt64((TRNLUInt64(RNL_PROTOCOL_VERSION_MAJOR) shl 32) or (TRNLUInt64(RNL_PROTOCOL_VERSION_MINOR) shl 16) or RNL_PROTOCOL_VERSION_PATCH);

      RNL_TIME_HALF_OVERFLOW=TRNLUInt64($2000000000000000); // 1/8 of a 64-bit unsigned integer

      RNL_TIME_OVERFLOW=TRNLUInt64($4000000000000000); // 1/4 of a 64-bit unsigned integer

      RNL_TIME_OVERFLOW_MASK=TRNLUInt64($3fffffffffffffff); // 1/4 of a 64-bit unsigned integer

      RNL_IPV4MAPPED_PREFIX_LEN=12; // specifies the length of the IPv4-mapped IPv6 prefix

      RNL_PORT_ANY=0; // specifies that a Port should be automatically chosen

      RNL_NO_ADDRESS_FAMILY=0;
      RNL_IPV4=1 shl 0;
      RNL_IPV6=1 shl 1;

      RNL_FD_SETSIZE={$ifdef Unix}64{$else}64{$endif};

      RNL_KEY_SIZE=256 shr 3; // 32 bytes, 256 bits (DON'T CHANGE OR YOU WILL BREAK IT!)

      RNL_CONNECTION_TOKEN_SIZE=128;

      RNL_AUTHENTICATION_TOKEN_SIZE=128;

      RNL_MAXIMUM_PEER_CHANNELS=32;

      RNL_MINIMUM_MTU=576;
      RNL_MAXIMUM_MTU=4096;

      RNL_IPV4_HEADER_SIZE=60; // 20 bytes as minimum size and 60 bytes as maximum size
                               // of an IPv4 header, but we just assume the maximum size
                               // here, just for the worst case

      RNL_IPV6_HEADER_SIZE=40; // But the IPv6 header has luckly a fixed size of 40 bytes

      RNL_IP_HEADER_SIZE=RNL_IPV4_HEADER_SIZE; // We are using the IPv4 header size here, because it is the bigger thing

      RNL_UDP_HEADER_SIZE=8;

      RNL_CONNECTION_ATTEMPT_SIZE=256; // Must be power of two
      RNL_CONNECTION_ATTEMPT_MASK=RNL_CONNECTION_ATTEMPT_SIZE-1;

      RNL_PROTOCOL_PACKET_HEADER_SESSION_MASK=$ff;

      RNL_PROTOCOL_PACKET_HEADER_FLAG_COMPRESSED=1 shl 0;

      RNL_PEER_KEEP_ALIVE_TIME_HISTORY_SIZE=4; // Must be power of two
      RNL_PEER_KEEP_ALIVE_TIME_HISTORY_MASK=RNL_PEER_KEEP_ALIVE_TIME_HISTORY_SIZE-1;

      RNL_PEER_PACKET_LOSS_INTERVAL=10000;

      RNL_BROADCAST_IPV4='255.255.255.255';

      RNL_MULTICAST_GROUP_IPV4='224.0.0.1';

      RNL_MULTICAST_GROUP_IPV6='FF02:0:0:0:0:0:0:1';

type PRNLVersion=^TRNLVersion;
     TRNLVersion=TRNLUInt32;

     ERNL=class(Exception);

     ERNLNetwork=class(ERNL);

     ERNLInstance=class(ERNL);

     ERNLHost=class(ERNL);

     TRNLHost=class;

     TRNLPeer=class;

     TRNLMath=class
      public
       class function RoundUpToPowerOfTwo32(Value:TRNLUInt32):TRNLUInt32; static;
       class function RoundUpToPowerOfTwo64(Value:TRNLUInt64):TRNLUInt64; static;
       class function RoundUpToPowerOfTwo(Value:TRNLPtrUInt):TRNLPtrUInt; static;
     end;

     PRNLEndianness=^TRNLEndianness;
     TRNLEndianness=record
      public
       class function Swap16(const aValue:TRNLUInt16):TRNLUInt16; static; {$if defined(CPU386) or defined(CPUX64)}register;{$else}inline;{$ifend}
       class function Swap32(const aValue:TRNLUInt32):TRNLUInt32; static; {$if defined(CPU386) or defined(CPUX64)}register;{$else}inline;{$ifend}
       class function Swap64(const aValue:TRNLUInt64):TRNLUInt64; static; {$if defined(CPU386) or defined(CPUX64)}register;{$else}inline;{$ifend}
       class function HostToNet16(const aValue:TRNLUInt16):TRNLUInt16; static; {$if defined(CPU386) or defined(CPUX64)}register;{$else}inline;{$ifend}
       class function HostToNet32(const aValue:TRNLUInt32):TRNLUInt32; static; {$if defined(CPU386) or defined(CPUX64)}register;{$else}inline;{$ifend}
       class function HostToNet64(const aValue:TRNLUInt64):TRNLUInt64; static; {$if defined(CPU386) or defined(CPUX64)}register;{$else}inline;{$ifend}
       class function NetToHost16(const aValue:TRNLUInt16):TRNLUInt16; static; {$if defined(CPU386) or defined(CPUX64)}register;{$else}inline;{$ifend}
       class function NetToHost32(const aValue:TRNLUInt32):TRNLUInt32; static; {$if defined(CPU386) or defined(CPUX64)}register;{$else}inline;{$ifend}
       class function NetToHost64(const aValue:TRNLUInt64):TRNLUInt64; static; {$if defined(CPU386) or defined(CPUX64)}register;{$else}inline;{$ifend}
       class function HostToLittleEndian16(const aValue:TRNLUInt16):TRNLUInt16; static; inline;
       class function HostToLittleEndian32(const aValue:TRNLUInt32):TRNLUInt32; static; inline;
       class function HostToLittleEndian64(const aValue:TRNLUInt64):TRNLUInt64; static; inline;
       class function LittleEndianToHost16(const aValue:TRNLUInt16):TRNLUInt16; static; inline;
       class function LittleEndianToHost32(const aValue:TRNLUInt32):TRNLUInt32; static; inline;
       class function LittleEndianToHost64(const aValue:TRNLUInt64):TRNLUInt64; static; inline;
     end;

     PRNLMemoryAccess=^TRNLMemoryAccess;
     TRNLMemoryAccess=record
      public
       class function LoadBigEndianInt8(const aLocation):TRNLInt8; static; inline;
       class function LoadBigEndianUInt8(const aLocation):TRNLUInt8; static; inline;
       class function LoadBigEndianInt16(const aLocation):TRNLInt16; static; {$if defined(CPU386) or defined(CPUX64)}register;{$else}inline;{$ifend}
       class function LoadBigEndianUInt16(const aLocation):TRNLUInt16; static; {$if defined(CPU386) or defined(CPUX64)}register;{$else}inline;{$ifend}
       class function LoadBigEndianInt32(const aLocation):TRNLInt32; static; {$if defined(CPU386) or defined(CPUX64)}register;{$else}inline;{$ifend}
       class function LoadBigEndianUInt32(const aLocation):TRNLUInt32; static; {$if defined(CPU386) or defined(CPUX64)}register;{$else}inline;{$ifend}
       class function LoadBigEndianInt64(const aLocation):TRNLInt64; static; {$if defined(CPU386) or defined(CPUX64)}register;{$else}inline;{$ifend}
       class function LoadBigEndianUInt64(const aLocation):TRNLUInt64; static; {$if defined(CPU386) or defined(CPUX64)}register;{$else}inline;{$ifend}
       class function LoadLittleEndianInt8(const aLocation):TRNLInt8; static; inline;
       class function LoadLittleEndianUInt8(const aLocation):TRNLUInt8; static; inline;
       class function LoadLittleEndianInt16(const aLocation):TRNLInt16; static; inline;
       class function LoadLittleEndianUInt16(const aLocation):TRNLUInt16; static; inline;
       class function LoadLittleEndianUInt24(const aLocation):TRNLUInt32; static; inline;
       class function LoadLittleEndianInt32(const aLocation):TRNLInt32; static; inline;
       class function LoadLittleEndianUInt32(const aLocation):TRNLUInt32; static; inline;
       class function LoadLittleEndianInt64(const aLocation):TRNLInt64; static; inline;
       class function LoadLittleEndianUInt64(const aLocation):TRNLUInt64; static; inline;
       class procedure StoreBigEndianInt8(out aLocation;const aValue:TRNLInt8); static; inline;
       class procedure StoreBigEndianUInt8(out aLocation;const aValue:TRNLUInt8); static; inline;
       class procedure StoreBigEndianInt16(out aLocation;const aValue:TRNLInt16); static; {$if defined(CPU386) or defined(CPUX64)}register;{$else}inline;{$ifend}
       class procedure StoreBigEndianUInt16(out aLocation;const aValue:TRNLUInt16); static; {$if defined(CPU386) or defined(CPUX64)}register;{$else}inline;{$ifend}
       class procedure StoreBigEndianInt32(out aLocation;const aValue:TRNLInt32); static; {$if defined(CPU386) or defined(CPUX64)}register;{$else}inline;{$ifend}
       class procedure StoreBigEndianUInt32(out aLocation;const aValue:TRNLUInt32); static; {$if defined(CPU386) or defined(CPUX64)}register;{$else}inline;{$ifend}
       class procedure StoreBigEndianInt64(out aLocation;const aValue:TRNLInt64); static; {$if defined(CPU386) or defined(CPUX64)}register;{$else}inline;{$ifend}
       class procedure StoreBigEndianUInt64(out aLocation;const aValue:TRNLUInt64); static; {$if defined(CPU386) or defined(CPUX64)}register;{$else}inline;{$ifend}
       class procedure StoreLittleEndianInt8(out aLocation;const aValue:TRNLInt8); static; inline;
       class procedure StoreLittleEndianUInt8(out aLocation;const aValue:TRNLUInt8); static; inline;
       class procedure StoreLittleEndianInt16(out aLocation;const aValue:TRNLInt16); static; inline;
       class procedure StoreLittleEndianUInt16(out aLocation;const aValue:TRNLUInt16); static; inline;
       class procedure StoreLittleEndianInt32(out aLocation;const aValue:TRNLInt32); static; inline;
       class procedure StoreLittleEndianUInt32(out aLocation;const aValue:TRNLUInt32); static; inline;
       class procedure StoreLittleEndianInt64(out aLocation;const aValue:TRNLInt64); static; inline;
       class procedure StoreLittleEndianUInt64(out aLocation;const aValue:TRNLUInt64); static; inline;
     end;

     PRNLMemory=^TRNLMemory;
     TRNLMemory=record
      public
       class function SecureIsEqual(const aLocationA,aLocationB;const aSize:TRNLSizeUInt):boolean; static; inline;
       class function SecureIsNonEqual(const aLocationA,aLocationB;const aSize:TRNLSizeUInt):boolean; static; inline;
       class function SecureIsZero(const aLocation;const aSize:TRNLSizeUInt):boolean; static; inline;
       class function SecureIsNonZero(const aLocation;const aSize:TRNLSizeUInt):boolean; static; inline;
     end;

     TRNLTypedSort<T>=class
      public
       type TRNLTypedSortCompareFunction=function(const a,b:T):TRNLInt32;
      public
       class procedure IntroSort(const pItems:TRNLPointer;const pLeft,pRight:TRNLInt32;const pCompareFunc:TRNLTypedSortCompareFunction); static;
     end;

     PRNLHashUtils=^TRNLHashUtils;
     TRNLHashUtils=record
      public
       class function Hash32(const aLocation;const aSize:TRNLSizeUInt):TRNLUInt32; static;
     end;

     PRNLChaCha20State=^TRNLChaCha20State;
     TRNLChaCha20State=array[0..15] of TRNLUInt32;

     PRNLChaCha20Context=^TRNLChaCha20Context;
     TRNLChaCha20Context=record
      private
       fInput:TRNLChaCha20State;
       fPool:TRNLChaCha20State;
       fPoolIndex:TRNLUInt32;
       function GetCounter:TRNLUInt64; inline;
       procedure SetCounter(const aCounter:TRNLUInt64); inline;
      public
       class procedure Update(out aOutput:TRNLChaCha20State;const aInput:TRNLChaCha20State); static; inline;
       class procedure HChaCha20Process(out aOutput;const aKey,aInput); static;
      public
       procedure Initialize(const aKey,aNonce;const aCounter:TRNLUInt64=0);
       procedure EndianNeutralInitialize(const aKey;const aNonce:TRNLUInt64=0;const aCounter:TRNLUInt64=0);
       procedure XChaCha20Initialize(const aKey,aNonce;const aCounter:TRNLUInt64=0);
       procedure RefillPool;
       procedure Process(out aCipherText;const aPlainText;const aTextSize:TRNLSizeUInt;const aUsePlainText:boolean=true);
       procedure Stream(out aCipherText;const aTextSize:TRNLSizeUInt);
      public
       property Counter:TRNLUInt64 read GetCounter write SetCounter;
     end;

     PRNLChaCha20=^TRNLChaCha20;
     TRNLChaCha20=record
      public
       class procedure SelfTest; static;
     end;

     // arc4random-based random generator, but with ChaCha20 instead RC4 as the basic building block
     TRNLRandomGenerator=class
      public
       const KeySize=32;
             NonceSize=12;
             BlockSize=64;
             BufferSize=BlockSize*16;
       type PRNLRandomGeneratorKey=^TRNLRandomGeneratorKey;
            TRNLRandomGeneratorKey=array[0..KeySize-1] of TRNLUInt8;
            PRNLRandomGeneratorNonce=^TRNLRandomGeneratorNonce;
            TRNLRandomGeneratorNonce=array[0..NonceSize-1] of TRNLUInt8;
            PRNLRandomGeneratorBuffer=^TRNLRandomGeneratorBuffer;
            TRNLRandomGeneratorBuffer=array[0..BufferSize-1] of TRNLUInt8;
            PRNLRandomGeneratorSeed=^TRNLRandomGeneratorSeed;
            TRNLRandomGeneratorSeed=packed record
             Key:TRNLRandomGeneratorKey;
             Nonce:TRNLRandomGeneratorNonce;
            end;
            PRNLRandomGeneratorEntropyData=^TRNLRandomGeneratorEntropyData;
            TRNLRandomGeneratorEntropyData=array[0..(KeySize+NonceSize)-1] of TRNLUInt8;
{$if defined(Windows)}
      private
       fWindowsCryptProvider:PRNLUInt32;
       fWindowsCryptProviderInitialized:boolean;
{$ifend}
      private
       fInitialized:boolean;
       fPosition:TRNLSizeUInt;
       fHave:TRNLSizeUInt;
       fCount:TRNLSizeUInt;
       fBuffer:TRNLRandomGeneratorBuffer;
       fChaCha20Context:TRNLChaCha20Context;
       fGuassianFloatUseLast:boolean;
       fGuassianFloatLast:single;
       fGuassianDoubleUseLast:boolean;
       fGuassianDoubleLast:double;
       procedure Initialize(const aData;const aDataLength:TRNLSizeUInt);
       procedure Rekey(const aData;const aDataLength:TRNLSizeUInt);
       procedure Reseed;
       procedure ReseedIfNeeded(const aCount:TRNLSizeUInt);
      public
       constructor Create; reintroduce;
       destructor Destroy; override;
       procedure GetRandomBytes(out aLocation;const aCount:TRNLSizeUInt);
       function GetUInt32:TRNLUInt32;
       function GetUInt64:TRNLUInt64;
       function GetBoundedUInt32(const aBound:TRNLUInt32):TRNLUInt32;
       function GetUniformBoundedUInt32(const aBound:TRNLUInt32):TRNLUInt32;
       function GetFloat:single; // -1.0.0 .. 1.0
       function GetAbsoluteFloat:single; // 0.0 .. 1.0
       function GetDouble:double; // -1.0.0 .. 1.0
       function GetAbsoluteDouble:Double; // 0.0 .. 1.0
       function GetGuassianFloat:single; // -1.0 .. 1.0
       function GetAbsoluteGuassianFloat:single; // 0.0 .. 1.0
       function GetGuassianDouble:double; // -1.0 .. 1.0
       function GetAbsoluteGuassianDouble:double; // 0.0 .. 1.0
       function GetGuassian(const aBound:TRNLUInt32):TRNLUInt32;
     end;

     PPRNLTime=^PRNLTime;
     PRNLTime=^TRNLTime;
     TRNLTime=record
      private
       fValue:TRNLUInt64;
      public
       class operator Implicit(const a:TRNLUInt64):TRNLTime; inline;
       class operator Explicit(const a:TRNLUInt64):TRNLTime; inline;
       class operator Implicit(const a:TRNLTime):TRNLUInt64; inline;
       class operator Explicit(const a:TRNLTime):TRNLUInt64; inline;
       class operator Equal(const a,b:TRNLTime):boolean; inline;
       class operator NotEqual(const a,b:TRNLTime):boolean; inline;
       class operator GreaterThan(const a,b:TRNLTime):boolean;
       class operator GreaterThanOrEqual(const a,b:TRNLTime):boolean;
       class operator LessThan(const a,b:TRNLTime):boolean;
       class operator LessThanOrEqual(const a,b:TRNLTime):boolean;
       class function RelativeDifference(const a,b:TRNLTime):TRNLInt64; static;
       class function Difference(const a,b:TRNLTime):TRNLInt64; static;
       class function Minimum(const a,b:TRNLTime):TRNLTime; static;
       class operator Inc(const a:TRNLTime):TRNLTime; inline;
       class operator Dec(const a:TRNLTime):TRNLTime; inline;
       class operator LogicalNot(const a:TRNLTime):TRNLTime; inline;
       class operator Add(const a,b:TRNLTime):TRNLTime; inline;
       class operator Add(const a:TRNLTime;const b:TRNLUInt64):TRNLUInt64; inline;
       class operator Add(const a:TRNLUInt64;const b:TRNLTime):TRNLUInt64; inline;
       class operator Subtract(const a,b:TRNLTime):TRNLTime; inline;
       class operator Subtract(const a:TRNLTime;const b:TRNLUInt64):TRNLUInt64; inline;
       class operator Subtract(const a:TRNLUInt64;const b:TRNLTime):TRNLUInt64; inline;
       class operator Multiply(const a,b:TRNLTime):TRNLTime; inline;
       class operator Multiply(const a:TRNLTime;const b:TRNLUInt64):TRNLUInt64; inline;
       class operator Multiply(const a:TRNLUInt64;const b:TRNLTime):TRNLUInt64; inline;
       class operator Divide(const a,b:TRNLTime):TRNLTime; inline;
       class operator Divide(const a:TRNLTime;const b:TRNLUInt64):TRNLUInt64; inline;
       class operator Divide(const a:TRNLUInt64;const b:TRNLTime):TRNLUInt64; inline;
       class operator IntDivide(const a,b:TRNLTime):TRNLTime; inline;
       class operator IntDivide(const a:TRNLTime;const b:TRNLUInt64):TRNLUInt64; inline;
       class operator IntDivide(const a:TRNLUInt64;const b:TRNLTime):TRNLUInt64; inline;
       class operator Modulus(const a,b:TRNLTime):TRNLTime; inline;
       class operator LeftShift(const a:TRNLTime;const b:TRNLInt32):TRNLTime; inline;
       class operator RightShift(const a:TRNLTime;const b:TRNLInt32):TRNLTime; inline;
       class operator BitwiseAnd(const a,b:TRNLTime):TRNLTime; inline;
       class operator BitwiseOr(const a,b:TRNLTime):TRNLTime; inline;
       class operator BitwiseXor(const a,b:TRNLTime):TRNLTime; inline;
       class operator Negative(const a:TRNLTime):TRNLTime; inline;
       class operator Positive(const a:TRNLTime):TRNLTime; inline;
       property Value:TRNLUInt64 read fValue write fValue;
     end;

     PPRNLSequenceNumber=^PRNLSequenceNumber;
     PRNLSequenceNumber=^TRNLSequenceNumber;
     TRNLSequenceNumber=record
      private
       fValue:TRNLUInt16;
      public
       class operator Implicit(const a:TRNLUInt16):TRNLSequenceNumber; inline;
       class operator Explicit(const a:TRNLUInt16):TRNLSequenceNumber; inline;
       class operator Implicit(const a:TRNLSequenceNumber):TRNLUInt16; inline;
       class operator Explicit(const a:TRNLSequenceNumber):TRNLUInt16; inline;
       class operator Equal(const a,b:TRNLSequenceNumber):boolean; inline;
       class operator NotEqual(const a,b:TRNLSequenceNumber):boolean; inline;
       class operator GreaterThan(const a,b:TRNLSequenceNumber):boolean; inline;
       class operator GreaterThanOrEqual(const a,b:TRNLSequenceNumber):boolean; inline;
       class operator LessThan(const a,b:TRNLSequenceNumber):boolean; inline;
       class operator LessThanOrEqual(const a,b:TRNLSequenceNumber):boolean; inline;
       class function RelativeDifference(const a,b:TRNLSequenceNumber):TRNLInt32; static; inline;
       class function Difference(const a,b:TRNLSequenceNumber):TRNLInt32; static; inline;
       class function Minimum(const a,b:TRNLSequenceNumber):TRNLSequenceNumber; static;
       class operator Inc(const a:TRNLSequenceNumber):TRNLSequenceNumber; inline;
       class operator Dec(const a:TRNLSequenceNumber):TRNLSequenceNumber; inline;
       class operator LogicalNot(const a:TRNLSequenceNumber):TRNLSequenceNumber; inline;
       class operator Add(const a,b:TRNLSequenceNumber):TRNLSequenceNumber; inline;
       class operator Add(const a:TRNLSequenceNumber;const b:TRNLUInt16):TRNLUInt16; inline;
       class operator Add(const a:TRNLUInt16;const b:TRNLSequenceNumber):TRNLUInt16; inline;
       class operator Subtract(const a,b:TRNLSequenceNumber):TRNLSequenceNumber; inline;
       class operator Subtract(const a:TRNLSequenceNumber;const b:TRNLUInt16):TRNLUInt16; inline;
       class operator Subtract(const a:TRNLUInt16;const b:TRNLSequenceNumber):TRNLUInt16; inline;
       class operator Multiply(const a,b:TRNLSequenceNumber):TRNLSequenceNumber; inline;
       class operator Multiply(const a:TRNLSequenceNumber;const b:TRNLUInt16):TRNLUInt16; inline;
       class operator Multiply(const a:TRNLUInt16;const b:TRNLSequenceNumber):TRNLUInt16; inline;
       class operator Divide(const a,b:TRNLSequenceNumber):TRNLSequenceNumber; inline;
       class operator Divide(const a:TRNLSequenceNumber;const b:TRNLUInt16):TRNLUInt16; inline;
       class operator Divide(const a:TRNLUInt16;const b:TRNLSequenceNumber):TRNLUInt16; inline;
       class operator IntDivide(const a,b:TRNLSequenceNumber):TRNLSequenceNumber; inline;
       class operator IntDivide(const a:TRNLSequenceNumber;const b:TRNLUInt16):TRNLUInt16; inline;
       class operator IntDivide(const a:TRNLUInt16;const b:TRNLSequenceNumber):TRNLUInt16; inline;
       class operator Modulus(const a,b:TRNLSequenceNumber):TRNLSequenceNumber; inline;
       class operator LeftShift(const a:TRNLSequenceNumber;const b:TRNLInt32):TRNLSequenceNumber; inline;
       class operator RightShift(const a:TRNLSequenceNumber;const b:TRNLInt32):TRNLSequenceNumber; inline;
       class operator BitwiseAnd(const a,b:TRNLSequenceNumber):TRNLSequenceNumber; inline;
       class operator BitwiseOr(const a,b:TRNLSequenceNumber):TRNLSequenceNumber; inline;
       class operator BitwiseXor(const a,b:TRNLSequenceNumber):TRNLSequenceNumber; inline;
       class operator Negative(const a:TRNLSequenceNumber):TRNLSequenceNumber; inline;
       class operator Positive(const a:TRNLSequenceNumber):TRNLSequenceNumber; inline;
       property Value:TRNLUInt16 read fValue write fValue;
     end;

     TRNLSequenceNumberArray=array of TRNLSequenceNumber;

     PRNLKey=^TRNLKey;
     TRNLKey=record
      public
       class operator Implicit(const a:TRNLUInt64):TRNLKey;
       class operator Explicit(const a:TRNLUInt64):TRNLKey;
       class operator Implicit(const a:TRNLKey):TRNLUInt64;
       class operator Explicit(const a:TRNLKey):TRNLUInt64;
       class operator Equal(const a,b:TRNLKey):boolean;
       class operator NotEqual(const a,b:TRNLKey):boolean;
       function ClampForCurve25519:TRNLKey; inline;
       class function CreateRandom(const aRandomGenerator:TRNLRandomGenerator):TRNLKey; static;
       case TRNLUInt8 of
        0:(
         ui8:array[0..(RNL_KEY_SIZE div SizeOf(TRNLUInt8))-1] of TRNLUInt8;
        );
        1:(
         ui16:array[0..(RNL_KEY_SIZE div SizeOf(TRNLUInt16))-1] of TRNLUInt16;
        );
        2:(
         ui32:array[0..(RNL_KEY_SIZE div SizeOf(TRNLUInt32))-1] of TRNLUInt32;
        );
        3:(
         ui64:array[0..(RNL_KEY_SIZE div SizeOf(TRNLUInt64))-1] of TRNLUInt64;
        );
     end;

     PRNLTwoKeys=^TRNLTwoKeys;
     TRNLTwoKeys=array[0..1] of TRNLKey;

     PRNLValue2551964=^TRNLValue2551964;
     TRNLValue2551964=record
      public
       Limbs:array[0..9] of TRNLInt64;
     end;

     PRNLValue25519=^TRNLValue25519;
     TRNLValue25519=record
      public
       constructor Create(const aValue:TRNLInt32);
       class operator Implicit(const a:TRNLInt32):TRNLValue25519; inline;
       class operator Explicit(const a:TRNLInt32):TRNLValue25519; inline;
       class operator Add(const a,b:TRNLValue25519):TRNLValue25519; inline;
       class operator Subtract(const a,b:TRNLValue25519):TRNLValue25519; inline;
       class operator Multiply(const a,b:TRNLValue25519):TRNLValue25519; {$if not (defined(CPUX64) and not defined(fpc))}inline;{$ifend}
       class operator Negative(const a:TRNLValue25519):TRNLValue25519; inline;
       class operator Positive(const a:TRNLValue25519):TRNLValue25519; inline;
       class operator Equal(const a,b:TRNLValue25519):boolean; inline;
       class operator NotEqual(const a,b:TRNLValue25519):boolean; inline;
       function Square:TRNLValue25519; overload; {$if not (defined(CPUX64) and not defined(fpc))}inline;{$ifend}
       function Square(const aCount:TRNLInt32):TRNLValue25519; overload;
       class procedure ConditionalSwap(var a,b:TRNLValue25519;const aSelect:TRNLInt32); static;
       function Carry:TRNLValue25519; inline;
       class function Carry64(const aValue:TRNLValue2551964):TRNLValue25519; static; inline;
       class function CreateRandom(const aRandomGenerator:TRNLRandomGenerator):TRNLValue25519; static; inline;
       class function LoadFromMemory(const aLocation):TRNLValue25519; static;
       procedure SaveToMemory(out aLocation);
       class operator Multiply(const a:TRNLValue25519;const b:TRNLInt32):TRNLValue25519; inline;
       function Mul121666:TRNLValue25519; inline;
       function Mul973324:TRNLValue25519; inline;
       function Invert:TRNLValue25519; inline;
       function Pow22523:TRNLValue25519; inline;
       function IsNegative:boolean; inline;
       function IsNonZero:boolean; inline;
       function IsZero:boolean; inline;
       class procedure SelfTest; static;
       case TRNLUInt8 of
        0:(
         Limbs:array[0..9] of TRNLInt32;
        );
     end;

     PRNLPoint25519=^TRNLPoint25519;
     TRNLPoint25519=record
      private
       fX:TRNLValue25519;
       fY:TRNLValue25519;
       fZ:TRNLValue25519;
       fT:TRNLValue25519;
      public
       constructor CreateFromXY(const aX,aY:TRNLValue25519);
       class function LoadFromMemory(out aPoint:TRNLPoint25519;const aLocation):boolean; static;
       procedure SaveToMemory(out aLocation);
       class operator Add(const p,q:TRNLPoint25519):TRNLPoint25519;
     end;

     PRNLCurve25519=^TRNLCurve25519;
     TRNLCurve25519=record
      public
       class procedure Clean(out aX:TRNLKey); static;
       class function IsWeakPoint(const aK:TRNLKey):boolean; static;
       class function IsInRange(const aX:TRNLKey):boolean; static;
       class procedure Ladder(const aX1:TRNLValue25519;out aX2,aZ2,aX3,aZ3:TRNLValue25519;const aScalar:TRNLKey); static;
       class function Eval(out aResult:TRNLKey;const aSecret:TRNLKey;const aBasePoint:PRNLKey=nil):boolean; static;
       class procedure SelfTest; static;
     end;

     PRNLX25519=^TRNLX25519;
     TRNLX25519=record
      public
       class function GeneratePublicPrivateKeyPair(const aRandomGenerator:TRNLRandomGenerator;out aPublicKey,aPrivateKey:TRNLKey):boolean; static;
       class function GenerateSharedSecretKey(out aSharedSecretKey:TRNLKey;const aPublicKey,aPrivateKey:TRNLKey):boolean; static;
       class procedure SelfTest; static;
     end;

     PRNLPoly1305MAC=^TRNLPoly1305MAC;
     TRNLPoly1305MAC=array[0..15] of TRNLUInt8;

     PRNLPoly1305Context=^TRNLPoly1305Context;
     TRNLPoly1305Context=record
      private
       fR:array[0..3] of TRNLUInt32;
       fH:array[0..4] of TRNLUInt32;
       fC:array[0..4] of TRNLUInt32;
       fPad:array[0..3] of TRNLUInt32;
       fCIndex:TRNLUInt32;
       procedure ClearC; inline;
       procedure ProcessByte(const aValue:TRNLUInt8); inline;
       procedure Block;
      public
       procedure Initialize(const aKey);
       procedure Update(const aMessage;const aMessageSize:TRNLSizeUInt);
       procedure Finalize(out aMAC);
     end;

     PRNLPoly1305=^TRNLPoly1305;
     TRNLPoly1305=record
      public
       class function OneTimeAuthentication(out aOutput;const aInput;const aInputLength:TRNLSizeUInt;const aSecretKey):boolean; static;
       class function OneTimeAuthenticationVerify(const aComparsion;const aInput;const aInputLength:TRNLSizeUInt;const aSecretKey):boolean; static;
       class procedure SelfTest; static;
     end;

     PRNLSHA512State=^TRNLSHA512State;
     TRNLSHA512State=array[0..7] of TRNLUInt64;

     PRNLSHA512Hash=^TRNLSHA512Hash;
     TRNLSHA512Hash=array[0..63] of TRNLUInt8;

     PRNLSHA512Input=^TRNLSHA512Input;
     TRNLSHA512Input=array[0..15] of TRNLUInt64;

     PRNLSHA512Context=^TRNLSHA512Context;
     TRNLSHA512Context=record
      public
       const BLOCK_SIZE=512;
             HASH_SIZE=64;
      private
       const InitialState:TRNLSHA512State=
              (
               TRNLUInt64($6a09e667f3bcc908),TRNLUInt64($bb67ae8584caa73b),
               TRNLUInt64($3c6ef372fe94f82b),TRNLUInt64($a54ff53a5f1d36f1),
               TRNLUInt64($510e527fade682d1),TRNLUInt64($9b05688c2b3e6c1f),
               TRNLUInt64($1f83d9abfb41bd6b),TRNLUInt64($5be0cd19137e2179)
              );
             RoundK:array[0..79] of TRNLUInt64=
              (
               TRNLUInt64($428a2f98d728ae22),TRNLUInt64($7137449123ef65cd),
               TRNLUInt64($b5c0fbcfec4d3b2f),TRNLUInt64($e9b5dba58189dbbc),
               TRNLUInt64($3956c25bf348b538),TRNLUInt64($59f111f1b605d019),
               TRNLUInt64($923f82a4af194f9b),TRNLUInt64($ab1c5ed5da6d8118),
               TRNLUInt64($d807aa98a3030242),TRNLUInt64($12835b0145706fbe),
               TRNLUInt64($243185be4ee4b28c),TRNLUInt64($550c7dc3d5ffb4e2),
               TRNLUInt64($72be5d74f27b896f),TRNLUInt64($80deb1fe3b1696b1),
               TRNLUInt64($9bdc06a725c71235),TRNLUInt64($c19bf174cf692694),
               TRNLUInt64($e49b69c19ef14ad2),TRNLUInt64($efbe4786384f25e3),
               TRNLUInt64($0fc19dc68b8cd5b5),TRNLUInt64($240ca1cc77ac9c65),
               TRNLUInt64($2de92c6f592b0275),TRNLUInt64($4a7484aa6ea6e483),
               TRNLUInt64($5cb0a9dcbd41fbd4),TRNLUInt64($76f988da831153b5),
               TRNLUInt64($983e5152ee66dfab),TRNLUInt64($a831c66d2db43210),
               TRNLUInt64($b00327c898fb213f),TRNLUInt64($bf597fc7beef0ee4),
               TRNLUInt64($c6e00bf33da88fc2),TRNLUInt64($d5a79147930aa725),
               TRNLUInt64($06ca6351e003826f),TRNLUInt64($142929670a0e6e70),
               TRNLUInt64($27b70a8546d22ffc),TRNLUInt64($2e1b21385c26c926),
               TRNLUInt64($4d2c6dfc5ac42aed),TRNLUInt64($53380d139d95b3df),
               TRNLUInt64($650a73548baf63de),TRNLUInt64($766a0abb3c77b2a8),
               TRNLUInt64($81c2c92e47edaee6),TRNLUInt64($92722c851482353b),
               TRNLUInt64($a2bfe8a14cf10364),TRNLUInt64($a81a664bbc423001),
               TRNLUInt64($c24b8b70d0f89791),TRNLUInt64($c76c51a30654be30),
               TRNLUInt64($d192e819d6ef5218),TRNLUInt64($d69906245565a910),
               TRNLUInt64($f40e35855771202a),TRNLUInt64($106aa07032bbd1b8),
               TRNLUInt64($19a4c116b8d2d0c8),TRNLUInt64($1e376c085141ab53),
               TRNLUInt64($2748774cdf8eeb99),TRNLUInt64($34b0bcb5e19b48a8),
               TRNLUInt64($391c0cb3c5c95a63),TRNLUInt64($4ed8aa4ae3418acb),
               TRNLUInt64($5b9cca4f7763e373),TRNLUInt64($682e6ff3d6b2b8a3),
               TRNLUInt64($748f82ee5defb2fc),TRNLUInt64($78a5636f43172f60),
               TRNLUInt64($84c87814a1f0ab72),TRNLUInt64($8cc702081a6439ec),
               TRNLUInt64($90befffa23631e28),TRNLUInt64($a4506cebde82bde9),
               TRNLUInt64($bef9a3f7b2c67915),TRNLUInt64($c67178f2e372532b),
               TRNLUInt64($ca273eceea26619c),TRNLUInt64($d186b8c721c0c207),
               TRNLUInt64($eada7dd6cde0eb1e),TRNLUInt64($f57d4f7fee6ed178),
               TRNLUInt64($06f067aa72176fba),TRNLUInt64($0a637dc5a2c898a6),
               TRNLUInt64($113f9804bef90dae),TRNLUInt64($1b710b35131c471b),
               TRNLUInt64($28db77f523047d84),TRNLUInt64($32caab7b40c72493),
               TRNLUInt64($3c9ebe0a15c9bebc),TRNLUInt64($431d67c49c100d4c),
               TRNLUInt64($4cc5d4becb3e42b6),TRNLUInt64($597f299cfc657e2a),
               TRNLUInt64($5fcb6fab3ad6faec),TRNLUInt64($6c44198c4a475817)
              );
      private
       fState:TRNLSHA512State;
       fInput:TRNLSHA512Input;
       fInputSize:array[0..1] of TRNLUInt64;
       fInputIndex:TRNLUInt32;
       class function RotateRight64(const aValue:TRNLUInt64;const aBits:TRNLUInt32):TRNLUInt64; static; inline;
       procedure ResetInput;
       procedure Compress;
       procedure ProcessByte(const aValue:TRNLUInt8);
       procedure Increment(var aX;const aY:TRNLUInt64);
       procedure EndBlock;
      public
       procedure Initialize;
       procedure Update(const aMessage;const aMessageSize:TRNLSizeUInt);
       procedure Finalize(out aHash);
     end;

     PRNLSHA512=^TRNLSHA512;
     TRNLSHA512=record
      public
       class procedure Process(out aHash;const aMessage;const aMessageSize:TRNLSizeUInt); static;
       class procedure SelfTest; static;
     end;

     PRNLED25519HashContext=^TRNLED25519HashContext;
     TRNLED25519HashContext=TRNLSHA512Context;

     PRNLED25519Hash=^TRNLED25519Hash;
     TRNLED25519Hash=TRNLSHA512;

     PRNLED25519Signature=^TRNLED25519Signature;
     TRNLED25519Signature=array[0..63] of TRNLUInt8;

     PRNLED25519=^TRNLED25519;
     TRNLED25519=record
      private
       class procedure ModL(out aR;const aX); static;
       class procedure Reduce(var aR); static;
       class procedure HashRAM(out aK;const aR,aA,aM;const aMSize:TRNLSizeUInt); static;
       class function ScalarMultiplication(out aResult:TRNLPoint25519;const aInput:TRNLPoint25519;const aScalar:TRNLKey):boolean; overload; static;
       class function ScalarMultiplicationBase(out aResult:TRNLPoint25519;const aScalar:TRNLKey):boolean; overload; static;
      public
       class procedure DerivePublicKey(out aPublicKey;const aPrivateKey); static;
       class procedure GeneratePublicPrivateKeyPair(const aRandomGenerator:TRNLRandomGenerator;out aPublicKey,aPrivateKey); static;
       class procedure Sign(out aSignature;const aPrivateKey,aMessage;const aMessageSize:TRNLSizeUInt;const aPublicKey:TRNLPointer=nil); overload; static;
       class procedure Sign(out aSignature;const aPrivateKey,aPublicKey,aMessage;const aMessageSize:TRNLSizeUInt); overload; static;
       class function Verify(const aSignature,aPublicKey,aMessage;const aMessageSize:TRNLSizeUInt):boolean; static;
       class procedure SelfTest; static;
     end;

     PRNLKeyExchange=^TRNLKeyExchange;
     TRNLKeyExchange=record
      public
       class function Process(out aSharedKey:TRNLKey;const aYourSecretKey,aTheirPublicKey:TRNLKey):boolean; static;
     end;

     PRNLAuthenticatedEncryption=^TRNLAuthenticatedEncryption;
     TRNLAuthenticatedEncryption=record
      private
       class procedure Authenticate(out aMAC;const aAuthKey,aT1;const aT1Size:TRNLSizeUInt;const aT2;const aT2Size:TRNLSizeUInt); static;
      public
       class function Encrypt(out aCipherText;const aKey,aNonce;out aMAC;const aAssociatedData;const aAssociatedDataSize:TRNLSizeUInt;const aPlainText;const aPlainTextSize:TRNLSizeUInt):boolean; overload; static;
       class function Encrypt(out aCipherText;const aKey,aNonce;out aMAC;const aPlainText;const aPlainTextSize:TRNLSizeUInt):boolean; overload; static;
       class function Decrypt(out aPlainText;const aKey,aNonce,aMAC,aAssociatedData;const aAssociatedDataSize:TRNLSizeUInt;const aCipherText;const aCipherTextSize:TRNLSizeUInt):boolean; overload; static;
       class function Decrypt(out aPlainText;const aKey,aNonce,aMAC,aCipherText;const aCipherTextSize:TRNLSizeUInt):boolean; overload; static;
     end;

     PRNLSocket=^TRNLSocket;
     TRNLSocket=type {$if defined(Unix)}TSocket{$else}TRNLPtrUInt{$ifend};

     PRNLSocketSet=^TRNLSocketSet;
     TRNLSocketSet={$if defined(Posix)}fd_Set{$elseif defined(Unix)}TFDSet{$else}record
      fd_count:TRNLUInt32;
      fd_array:array[0..RNL_FD_SETSIZE-1] of TRNLSocket;
     end{$ifend};

     TRNLSocketSetHelper=record helper for TRNLSocketSet
      public
       class function Empty:TRNLSocketSet; static;
       procedure Add(const aSocket:TRNLSocket);
       procedure Remove(const aSocket:TRNLSocket);
       function Check(const aSocket:TRNLSocket):boolean;
     end;

     PRNLProtocolFlags=^TRNLProtocolFlags;
     TRNLProtocolFlags=TRNLInt32;

     TRNLCircularDoublyLinkedListNode<T>=class
      public
       type TValueEnumerator=record
             private
              fCircularDoublyLinkedList:TRNLCircularDoublyLinkedListNode<T>;
              fNode:TRNLCircularDoublyLinkedListNode<T>;
              function GetCurrent:T; inline;
             public
              constructor Create(const aCircularDoublyLinkedList:TRNLCircularDoublyLinkedListNode<T>);
              function MoveNext:boolean; inline;
              property Current:T read GetCurrent;
            end;
      private
       fNext:TRNLCircularDoublyLinkedListNode<T>;
       fPrevious:TRNLCircularDoublyLinkedListNode<T>;
       fValue:T;
      public
       constructor Create; reintroduce;
       destructor Destroy; override;
       procedure Clear; inline;
       function Head:TRNLCircularDoublyLinkedListNode<T>; inline;
       function Tail:TRNLCircularDoublyLinkedListNode<T>; inline;
       function Empty:boolean; inline;
       function Front:TRNLCircularDoublyLinkedListNode<T>; inline;
       function Back:TRNLCircularDoublyLinkedListNode<T>; inline;
       function Insert(const aData:TRNLCircularDoublyLinkedListNode<T>):TRNLCircularDoublyLinkedListNode<T>; inline;
       function Add(const aData:TRNLCircularDoublyLinkedListNode<T>):TRNLCircularDoublyLinkedListNode<T>; inline;
       function Remove:TRNLCircularDoublyLinkedListNode<T>; // inline;
       function Move(const aDataFirst,aDataLast:TRNLCircularDoublyLinkedListNode<T>):TRNLCircularDoublyLinkedListNode<T>; inline;
       function PopFromFront(out aData):boolean; inline;
       function PopFromBack(out aData):boolean; inline;
       function ListSize:TRNLInt32;
       function GetEnumerator:TValueEnumerator;
      published
       property Next:TRNLCircularDoublyLinkedListNode<T> read fNext write fNext;
       property Previous:TRNLCircularDoublyLinkedListNode<T> read fPrevious write fPrevious;
      public
       property Value:T read fValue write fValue;
     end;

     TRNLQueue<T>=class
      private
       type TRNLQueueItems=array of T;
      private
       fItems:TRNLQueueItems;
       fHead:TRNLSizeInt;
       fTail:TRNLSizeInt;
       fCount:TRNLSizeInt;
       fSize:TRNLSizeInt;
       function GetCount:TRNLSizeInt; inline;
       procedure GrowResize(const aSize:TRNLSizeInt);
      public
       constructor Create; reintroduce;
       destructor Destroy; override;
       procedure Clear;
       function IsEmpty:boolean; inline;
       procedure EnqueueAtFront(const aItem:T);
       procedure Enqueue(const aItem:T);
       function Dequeue(out aItem:T):boolean; overload;
       function Dequeue:boolean; overload;
       function Peek(out aItem:T):boolean;
      published
       property Count:TRNLSizeInt read GetCount;
     end;

     TRNLSequenceNumberQueue=TRNLQueue<TRNLSequenceNumber>;

     TRNLStack<T>=class
      private
       type TRNLStackArray=array of T;
      private
       fItems:TRNLStackArray;
       fCount:TRNLSizeInt;
       function GetCount:TRNLSizeInt; inline;
      public
       constructor Create; reintroduce;
       destructor Destroy; override;
       procedure Clear;
       function IsEmpty:boolean; inline;
       procedure Push(const aItem:T);
       function Pop(out aItem:T):boolean;
       function Peek(out aItem:T):boolean;
      published
       property Count:TRNLSizeInt read GetCount;
     end;

     TRNLObjectList<T:class>=class
      public
       type TValueEnumerator=record
             private
              fObjectList:TRNLObjectList<T>;
              fIndex:TRNLSizeInt;
              function GetCurrent:T; inline;
             public
              constructor Create(const aObjectList:TRNLObjectList<T>);
              function MoveNext:boolean; inline;
              property Current:T read GetCurrent;
            end;
      private
       fItems:array of T;
       fCount:TRNLSizeInt;
       fAllocated:TRNLSizeInt;
       fOwnObjects:boolean;
       function GetItem(const pIndex:TRNLSizeInt):T; inline;
       procedure SetItem(const pIndex:TRNLSizeInt;const pItem:T); inline;
      protected
      public
       constructor Create(const aOwnObjects:boolean);
       destructor Destroy; override;
       procedure Clear;
       procedure Assign(const pFrom:TRNLObjectList<T>);
       function IndexOf(const pItem:T):TRNLSizeInt;
       function Add(const pItem:T):TRNLSizeInt;
       procedure Insert(const pIndex:TRNLSizeInt;const pItem:T);
       procedure Delete(const pIndex:TRNLSizeInt);
       procedure Remove(const pItem:T);
       procedure Exchange(const pIndex,pWithIndex:TRNLSizeInt);
       function GetEnumerator:TValueEnumerator;
       property Count:TRNLSizeInt read fCount{ write SetCount};
       property Allocated:TRNLSizeInt read fAllocated;
       property Items[const pIndex:TRNLSizeInt]:T read GetItem write SetItem; default;
     end;

     TRNLBits=class
      private
       type TRNLBitsData=array of TRNLUInt32;
      private
       fData:TRNLBitsData;
       fSize:TRNLSizeInt;
       function GetBit(const aIndex:TRNLSizeInt):boolean; inline;
       procedure SetBit(const aIndex:TRNLSizeInt;const aBit:boolean); inline;
      public
       constructor Create(const aSize:TRNLSizeInt); reintroduce;
       destructor Destroy; override;
       procedure Clear;
       function GetNextSetBitIndex(const aIndex:TRNLSizeInt=-1):TRNLSizeInt;
       property Bits[const aIndex:TRNLSizeInt]:boolean read GetBit write SetBit; default;
       property Size:TRNLSizeInt read fSize;
     end;

     TRNLID=TRNLUInt32;

     TRNLIDManager=class
      private
       type TRNLIDManagerFreeStack=TRNLStack<TRNLID>;
      private
       fIDCounter:TRNLID;
       fFreeStack:TRNLIDManagerFreeStack;
      public
       constructor Create; reintroduce;
       destructor Destroy; override;
       function AllocateID:TRNLID;
       procedure FreeID(const aID:TRNLID);
      published
       property IDCounter:TRNLID read fIDCounter;
     end;

     TRNLIDMap<T:class>=class
      private
       fItems:array of T;
       fCount:TRNLSizeUInt;
       function GetItem(const aID:TRNLID):T;
       procedure SetItem(const aID:TRNLID;const aItem:T);
      public
       constructor Create; reintroduce;
       destructor Destroy; override;
       property Items[const aID:TRNLID]:T read GetItem write SetItem; default;
      published
     end;

     PRNLCipherNonce=^TRNLCipherNonce;
     TRNLCipherNonce=record
      case TRNLUInt8 of
       0:(
        ui8:array[0..23] of TRNLUInt8;
       );
       1:(
        ui16:array[0..11] of TRNLUInt16;
       );
       2:(
        ui32:array[0..5] of TRNLUInt32;
       );
       3:(
        ui64:array[0..2] of TRNLUInt64;
       );
     end;

     PRNLCipherMAC=^TRNLCipherMAC;
     TRNLCipherMAC=array[0..15] of TRNLUInt8;

     PRNLBuffer=^TRNLBuffer;
     TRNLBuffer=record
{$ifdef Unix}
      Data:PRNLUInt8Array;
      DataLength:TRNLUInt32;
{$else}
      DataLength:TRNLUInt32;
      Data:PRNLUInt8Array;
{$endif}
     end;

     TRNLBuffers=array of TRNLBuffer;

     PRNLBufferArray=^TRNLBufferArray;
     TRNLBufferArray=array[0..65535] of TRNLBuffer;

     PRNLSocketType=^TRNLSocketType;
     TRNLSocketType=
      (
       RNL_SOCKET_TYPE_STREAM=1,
       RNL_SOCKET_TYPE_DATAGRAM=2
      );

     PRNLSocketWait=^TRNLSocketWait;
     TRNLSocketWait=TRNLUInt8;

     PRNLSocketOption=^TRNLSocketOption;
     TRNLSocketOption=
      (
       RNL_SOCKET_OPTION_NONE,
       RNL_SOCKET_OPTION_NONBLOCK,
       RNL_SOCKET_OPTION_BROADCAST,
       RNL_SOCKET_OPTION_RCVBUF,
       RNL_SOCKET_OPTION_SNDBUF,
       RNL_SOCKET_OPTION_REUSEADDR,
       RNL_SOCKET_OPTION_RCVTIMEO,
       RNL_SOCKET_OPTION_SNDTIMEO,
       RNL_SOCKET_OPTION_ERROR,
       RNL_SOCKET_OPTION_NODELAY,
       RNL_SOCKET_OPTION_DONTFRAGMENT,
       RNL_SOCKET_OPTION_IPV6_V6ONLY
      );

     PRNLSocketShutdown=^TRNLSocketShutdown;
     TRNLSocketShutdown=
      (
       RNL_SOCKET_SHUTDOWN_READ=0,
       RNL_SOCKET_SHUTDOWN_WRITE=1,
       RNL_SOCKET_SHUTDOWN_READ_WRITE=2
      );

     PRNLHostAddress=^TRNLHostAddress;
     TRNLHostAddress=packed record
      public
       Addr:array[0..15] of TRNLUInt8;
       constructor CreateFromIPV4(Address:TRNLUInt32);
       function Equals(const aWith:TRNLHostAddress):boolean;
     end;

     PRNLAddressFamily=^TRNLAddressFamily;
     TRNLAddressFamily=TRNLUInt8;

     TRNLAddressFamilyHelper=record helper for TRNLAddressFamily
      public
       function GetAddressFamily:TRNLUInt16;
       function GetSockAddrSize:TRNLInt32;
     end;

     PRNLAddress=^TRNLAddress;
     TRNLAddress=packed record
      public
       Host:TRNLHostAddress;
       ScopeID:{$ifdef Unix}TRNLUInt32{$else}TRNLInt64{$endif};
       Port:TRNLUInt16;
       function GetAddressFamily:TRNLAddressFamily; inline;
       function SetAddress(const aSIN:TRNLPointer):TRNLAddressFamily;
       function SetSIN(const aSIN:TRNLPointer;const aFamily:TRNLAddressFamily):boolean;
     end;

     PRNLSocketWaitCondition=^TRNLSocketWaitCondition;
     TRNLSocketWaitCondition=
      (
       RNL_SOCKET_WAIT_CONDITION_RECEIVE,
       RNL_SOCKET_WAIT_CONDITION_SEND,
       RNL_SOCKET_WAIT_CONDITION_INTERRUPT
      );

     PRNLSocketWaitConditions=^TRNLSocketWaitConditions;
     TRNLSocketWaitConditions=set of TRNLSocketWaitCondition;

     PRNLConnectionChallenge=^TRNLConnectionChallenge;
     TRNLConnectionChallenge=TRNLSHA512Hash;

     PRNLConnectionChallengePair=^TRNLConnectionChallengePair;
     TRNLConnectionChallengePair=array[0..1] of TRNLConnectionChallenge;

     PRNLConnectionRequestRateLimiter=^TRNLConnectionRequestRateLimiter;
     TRNLConnectionRequestRateLimiter=record
      private
       fBurst:TRNLInt64;
       fLastTime:TRNLUInt64;
      public
       procedure Reset(const aTime:TRNLTime);
       function RateLimit(const aTime:TRNLTime;const aBurst:TRNLInt64;const aPeriod:TRNLUInt64):boolean;
     end;

     PRNLBandwidthRateLimiter=^TRNLBandwidthRateLimiter;
     TRNLBandwidthRateLimiter=record
      private
       fMaximumPerPeriod:TRNLUInt64;
       fPeriodLength:TRNLUInt64;
       fUsedInPeriod:TRNLUInt64;
       fPeriodStart:TRNLTime;
       fPeriodEnd:TRNLTime;
      public
       constructor Create(const aMaximumPerPeriod,aPeriodLength:TRNLUInt64;const aTime:TRNLTime);
       procedure Setup(const aMaximumPerPeriod,aPeriodLength:TRNLUInt64);
       procedure Reset(const aTime:TRNLTime);
       function CanProceed(const aDesired:TRNLUInt32;const aTime:TRNLTime):boolean;
       procedure AddAmount(const aUsed:TRNLUInt32;const aTime:TRNLTime);
       property MaximumPerPeriod:TRNLUInt64 read fMaximumPerPeriod;
       property UsedInPeriod:TRNLUInt64 read fUsedInPeriod;
     end;

     PRNLBandwidthRateTracker=^TRNLBandwidthRateTracker;
     TRNLBandwidthRateTracker=record
      private
       fPeriodUnits:TRNLSizeUInt;
       fUnitsPerSecond:TRNLUInt32;
       fLastTime:TRNLTime;
       fTime:TRNLTime;
      public
       procedure Reset;
       procedure SetTime(const aTime:TRNLTime);
       procedure AddUnits(const aUnits:TRNLUInt32);
       procedure Update;
       property UnitsPerSecond:TRNLUInt32 read fUnitsPerSecond;
     end;

     PRNLPacketBuffer=^TRNLPacketBuffer;
     TRNLPacketBuffer=array[0..65535] of TRNLUInt8;

     PRNLOutgoingPacketBuffer=^TRNLOutgoingPacketBuffer;
     TRNLOutgoingPacketBuffer=record
      private
       fAssociatedDataSize:TRNLSizeUInt;
       fSize:TRNLSizeUInt;
       fBufferLength:TRNLSizeUInt;
       fData:TRNLPacketBuffer;
      public
       procedure Reset(const aAssociatedDataSize:TRNLSizeUInt=0;const aBufferLength:TRNLSizeUInt=SizeOf(TRNLPacketBuffer));
       function HasSpaceFor(const aDataLength:TRNLSizeUInt):boolean;
       function Write(const aData;const aDataLength:TRNLSizeUInt):TRNLSizeUInt;
       property Size:TRNLSizeUInt read fSize;
     end;

     PRNLConnectionKnownCandidateHostAddress=^TRNLConnectionKnownCandidateHostAddress;
     TRNLConnectionKnownCandidateHostAddress=record
      case boolean of
       false:(
        HostAddress:TRNLHostAddress;
        RateLimiter:TRNLConnectionRequestRateLimiter;
       );
       true:(
       );
     end;

     PRNLConnectionKnownCandidateHostAddressHashTable=^TRNLConnectionKnownCandidateHostAddressHashTable;
     TRNLConnectionKnownCandidateHostAddressHashTable=record
      public
       const HashBits=12;
             HashSize=1 shl HashBits;
             HashMask=HashSize-1;
       type PRNLConnectionKnownCandidateHostAddressHashTableEntries=^TRNLConnectionKnownCandidateHostAddressHashTableEntries;
            TRNLConnectionKnownCandidateHostAddressHashTableEntries=array[0..HashSize-1] of TRNLConnectionKnownCandidateHostAddress;
      private
       fEntries:TRNLConnectionKnownCandidateHostAddressHashTableEntries;
      public
       procedure Clear;
       function Find(const aHostAddress:TRNLHostAddress;const aTime:TRNLTime;const aAddIfNotExist:boolean):PRNLConnectionKnownCandidateHostAddress;
     end;

     PRNLConnectionCandidateState=^TRNLConnectionCandidateState;
     TRNLConnectionCandidateState=
      (
       RNL_CONNECTION_STATE_INVALID=0,
       RNL_CONNECTION_STATE_REQUESTING,
       RNL_CONNECTION_STATE_CHALLENGING,
       RNL_CONNECTION_STATE_AUTHENTICATING,
       RNL_CONNECTION_STATE_APPROVING
      );

     PRNLConnectionCandidate=^TRNLConnectionCandidate;
     TRNLConnectionCandidate=record
      case boolean of
       false:(
        State:TRNLConnectionCandidateState;
        RemoteSalt:TRNLUInt64;
        LocalSalt:TRNLUInt64;
        CreateTime:TRNLTime;
        Address:TRNLAddress;
        LocalShortTermPrivateKey:TRNLKey;
        LocalShortTermPublicKey:TRNLKey;
        RemoteShortTermPublicKey:TRNLKey;
        SharedSecretKey:TRNLKey;
        OutgoingPeerID:TRNLUInt16;
        IncomingBandwidthLimit:TRNLUInt32;
        OutgoingBandwidthLimit:TRNLUInt32;
        Nonce:TRNLUInt64;
        CountChallengeRepetitions:TRNLUInt16;
        Challenge:TRNLConnectionChallenge;
        SolvedChallenge:TRNLConnectionChallenge;
        Peer:TRNLPeer;
       );
       true:(
       );
     end;

     PRNLConnectionCandidateHashTable=^TRNLConnectionCandidateHashTable;
     TRNLConnectionCandidateHashTable=record
      public
       const HashBits=12;
             HashSize=1 shl HashBits;
             HashMask=HashSize-1;
       type PRNLConnectionCandidateHashTableEntries=^TRNLConnectionCandidateHashTableEntries;
            TRNLConnectionCandidateHashTableEntries=array[0..HashSize-1] of TRNLConnectionCandidate;
      private
       fEntries:TRNLConnectionCandidateHashTableEntries;
      public
       procedure Clear;
       function Find(const aRandomGenerator:TRNLRandomGenerator;const aAddress:TRNLAddress;const aRemoteSalt,aLocalSalt:TRNLUInt64;const aTime,aTimeout:TRNLTime;const aAddIfNotExist:boolean):PRNLConnectionCandidate;
     end;

     PRNLConnectionToken=^TRNLConnectionToken;
     TRNLConnectionToken=array[0..RNL_CONNECTION_TOKEN_SIZE-1] of TRNLUInt8;

     PRNLAuthenticationToken=^TRNLAuthenticationToken;
     TRNLAuthenticationToken=array[0..RNL_AUTHENTICATION_TOKEN_SIZE-1] of TRNLUInt8;

     PRNLConnectionDenialReason=^TRNLConnectionDenialReason;
     TRNLConnectionDenialReason=
      (
       RNL_CONNECTION_DENIAL_REASON_UNKNOWN=0,
       RNL_CONNECTION_DENIAL_REASON_FULL=1,
       RNL_CONNECTION_DENIAL_REASON_TOO_LESS_CHANNELS=2,
       RNL_CONNECTION_DENIAL_REASON_TOO_MANY_CHANNELS=3,
       RNL_CONNECTION_DENIAL_REASON_WRONG_CHANNEL_TYPES=4,
       RNL_CONNECTION_DENIAL_REASON_UNAUTHORIZED=5
      );

     PRNLProtocolHandshakePacketHeaderSignature=^TRNLProtocolHandshakePacketHeaderSignature;
     TRNLProtocolHandshakePacketHeaderSignature=array[0..3] of TRNLUInt8;

     PRNLProtocolHandshakePacketType=^TRNLProtocolHandshakePacketType;
     TRNLProtocolHandshakePacketType=
      (
       RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_NONE=-1,
       RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_REQUEST=0,
       RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_CHALLENGE_REQUEST=1,
       RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_CHALLENGE_RESPONSE=2,
       RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_AUTHENTICATION_REQUEST=3,
       RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_AUTHENTICATION_RESPONSE=4,
       RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_APPROVAL_RESPONSE=5,
       RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_DENIAL_RESPONSE=6,
       RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_APPROVAL_ACKNOWLEDGE=7,
       RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_DENIAL_ACKNOWLEDGE=8
      );

     PRNLProtocolHandshakePacketHeader=^TRNLProtocolHandshakePacketHeader;
     TRNLProtocolHandshakePacketHeader=packed record
      Signature:TRNLProtocolHandshakePacketHeaderSignature;
      ProtocolVersion:TRNLUInt64;
      ProtocolID:TRNLUInt64;
      Checksum:TRNLUInt32;
      PacketType:TRNLUInt8;
     end;

     // DDoS minification
     // Make DDoS-amplification-attacks unattractive for anyone thinking of launching
     // this kind of attack, when the outgoing response packet is bigger or equal-
     // sized like the incoming request packet
     PRNLProtocolHandshakePacketAntiDDoSAmplificationPadding=^TRNLProtocolHandshakePacketAntiDDoSAmplificationPadding;
     TRNLProtocolHandshakePacketAntiDDoSAmplificationPadding=packed record
      // should big enough but also including the IP+UDP headers additionally top on it
      // smaller than the minimum MTU of 576 bytes at the same time
      Padding:array[1..RNL_MINIMUM_MTU-(RNL_IPV4_HEADER_SIZE+RNL_UDP_HEADER_SIZE)] of TRNLUInt8;
     end;

     PRNLProtocolHandshakePacketConnectionRequest=^TRNLProtocolHandshakePacketConnectionRequest;
     TRNLProtocolHandshakePacketConnectionRequest=packed record
      case boolean of
       false:(
        Header:TRNLProtocolHandshakePacketHeader;
        PeerID:TRNLUInt16;
        OutgoingSalt:TRNLUInt64;
        IncomingBandwidthLimit:TRNLUInt32;
        OutgoingBandwidthLimit:TRNLUInt32;
        ConnectionToken:TRNLConnectionToken;
       );
       true:(
        AntiDDoSAmplificationPadding:TRNLProtocolHandshakePacketAntiDDoSAmplificationPadding;
       );
     end;

     PRNLProtocolHandshakePacketConnectionChallengeRequest=^TRNLProtocolHandshakePacketConnectionChallengeRequest;
     TRNLProtocolHandshakePacketConnectionChallengeRequest=packed record
      case boolean of
       false:(
        Header:TRNLProtocolHandshakePacketHeader;
        PeerID:TRNLUInt16;
        IncomingSalt:TRNLUInt64;
        OutgoingSalt:TRNLUInt64;
        IncomingBandwidthLimit:TRNLUInt32;
        OutgoingBandwidthLimit:TRNLUInt32;
        CountChallengeRepetitions:TRNLUInt16;
        Challenge:TRNLConnectionChallenge;
       );
       true:(
        AntiDDoSAmplificationPadding:TRNLProtocolHandshakePacketAntiDDoSAmplificationPadding;
       );
     end;

     PRNLProtocolHandshakePacketConnectionChallengeResponse=^TRNLProtocolHandshakePacketConnectionChallengeResponse;
     TRNLProtocolHandshakePacketConnectionChallengeResponse=packed record
      case boolean of
       false:(
        Header:TRNLProtocolHandshakePacketHeader;
        ConnectionSalt:TRNLUInt64;
        ShortTermPublicKey:TRNLKey;
        ChallengeResponse:TRNLConnectionChallenge;
       );
       true:(
        AntiDDoSAmplificationPadding:TRNLProtocolHandshakePacketAntiDDoSAmplificationPadding;
       );
     end;

     PTRNLProtocolHandshakePacketConnectionAuthenticationRequestPayload=^TTRNLProtocolHandshakePacketConnectionAuthenticationRequestPayload;
     TTRNLProtocolHandshakePacketConnectionAuthenticationRequestPayload=packed record
      LongTermPublicKey:TRNLKey;
      Signature:TRNLED25519Signature;
      MTU:TRNLUInt16;
     end;

     PRNLProtocolHandshakePacketConnectionAuthenticationRequest=^TRNLProtocolHandshakePacketConnectionAuthenticationRequest;
     TRNLProtocolHandshakePacketConnectionAuthenticationRequest=packed record
      case boolean of
       false:(
        Header:TRNLProtocolHandshakePacketHeader;
        PeerID:TRNLUInt16;
        ConnectionSalt:TRNLUInt64;
        ShortTermPublicKey:TRNLKey;
        Nonce:TRNLUInt64;
        PayloadMAC:TRNLCipherMAC;
        Payload:TTRNLProtocolHandshakePacketConnectionAuthenticationRequestPayload;
       );
       true:(
        AntiDDoSAmplificationPadding:TRNLProtocolHandshakePacketAntiDDoSAmplificationPadding;
       );
     end;

     PRNLProtocolHandshakePacketPeerChannelTypes=^TRNLProtocolHandshakePacketPeerChannelTypes;
     TRNLProtocolHandshakePacketPeerChannelTypes=array[0..RNL_MAXIMUM_PEER_CHANNELS-1] of TRNLUInt8;

     PRNLProtocolHandshakePacketConnectionAuthenticationResponsePayload=^TRNLProtocolHandshakePacketConnectionAuthenticationResponsePayload;
     TRNLProtocolHandshakePacketConnectionAuthenticationResponsePayload=packed record
      LongTermPublicKey:TRNLKey;
      Signature:TRNLED25519Signature;
      AuthenticationToken:TRNLAuthenticationToken;
      MTU:TRNLUInt16;
      CountChannels:TRNLUInt16;
      ChannelTypes:TRNLProtocolHandshakePacketPeerChannelTypes;
      Data:TRNLUInt64;
     end;

     PRNLProtocolHandshakePacketConnectionAuthenticationResponse=^TRNLProtocolHandshakePacketConnectionAuthenticationResponse;
     TRNLProtocolHandshakePacketConnectionAuthenticationResponse=packed record
      case boolean of
       false:(
        Header:TRNLProtocolHandshakePacketHeader;
        ConnectionSalt:TRNLUInt64;
        Nonce:TRNLUInt64;
        PayloadMAC:TRNLCipherMAC;
        Payload:TRNLProtocolHandshakePacketConnectionAuthenticationResponsePayload;
       );
       true:(
        AntiDDoSAmplificationPadding:TRNLProtocolHandshakePacketAntiDDoSAmplificationPadding;
       );
     end;

     PRNLProtocolHandshakePacketConnectionApprovalResponsePayload=^TRNLProtocolHandshakePacketConnectionApprovalResponsePayload;
     TRNLProtocolHandshakePacketConnectionApprovalResponsePayload=packed record
      PeerID:TRNLUInt16;
     end;

     PRNLProtocolHandshakePacketConnectionApprovalResponse=^TRNLProtocolHandshakePacketConnectionApprovalResponse;
     TRNLProtocolHandshakePacketConnectionApprovalResponse=packed record
      case boolean of
       false:(
        Header:TRNLProtocolHandshakePacketHeader;
        PeerID:TRNLUInt16;
        ConnectionSalt:TRNLUInt64;
        Nonce:TRNLUInt64;
        PayloadMAC:TRNLCipherMAC;
        Payload:TRNLProtocolHandshakePacketConnectionApprovalResponsePayload;
       );
       true:(
        AntiDDoSAmplificationPadding:TRNLProtocolHandshakePacketAntiDDoSAmplificationPadding;
       );
     end;

     PRNLProtocolHandshakePacketConnectionDenialResponsePayload=^TRNLProtocolHandshakePacketConnectionDenialResponsePayload;
     TRNLProtocolHandshakePacketConnectionDenialResponsePayload=packed record
      Reason:TRNLUInt8;
     end;

     PRNLProtocolHandshakePacketConnectionDenialResponse=^TRNLProtocolHandshakePacketConnectionDenialResponse;
     TRNLProtocolHandshakePacketConnectionDenialResponse=packed record
      case boolean of
       false:(
        Header:TRNLProtocolHandshakePacketHeader;
        PeerID:TRNLUInt16;
        ConnectionSalt:TRNLUInt64;
        Nonce:TRNLUInt64;
        PayloadMAC:TRNLCipherMAC;
        Payload:TRNLProtocolHandshakePacketConnectionDenialResponsePayload;
       );
       true:(
        AntiDDoSAmplificationPadding:TRNLProtocolHandshakePacketAntiDDoSAmplificationPadding;
       );
     end;

     PRNLProtocolHandshakePacketConnectionApprovalAcknowledge=^TRNLProtocolHandshakePacketConnectionApprovalAcknowledge;
     TRNLProtocolHandshakePacketConnectionApprovalAcknowledge=packed record
      case boolean of
       false:(
        Header:TRNLProtocolHandshakePacketHeader;
        PeerID:TRNLUInt16;
        ConnectionSalt:TRNLUInt64;
        Nonce:TRNLUInt64;
        WholePacketMAC:TRNLCipherMAC;
       );
       true:(
        AntiDDoSAmplificationPadding:TRNLProtocolHandshakePacketAntiDDoSAmplificationPadding;
       );
     end;

     PRNLProtocolHandshakePacketConnectionDenialAcknowledgePayload=^TRNLProtocolHandshakePacketConnectionDenialAcknowledgePayload;
     TRNLProtocolHandshakePacketConnectionDenialAcknowledgePayload=packed record
      Data:TRNLUInt64;
     end;

     PRNLProtocolHandshakePacketConnectionDenialAcknowledge=^TRNLProtocolHandshakePacketConnectionDenialAcknowledge;
     TRNLProtocolHandshakePacketConnectionDenialAcknowledge=packed record
      case boolean of
       false:(
        Header:TRNLProtocolHandshakePacketHeader;
        PeerID:TRNLUInt16;
        ConnectionSalt:TRNLUInt64;
        Nonce:TRNLUInt64;
        PayloadMAC:TRNLCipherMAC;
        Payload:TRNLProtocolHandshakePacketConnectionDenialAcknowledgePayload;
       );
       true:(
        AntiDDoSAmplificationPadding:TRNLProtocolHandshakePacketAntiDDoSAmplificationPadding;
       );
     end;

     PRNLProtocolHandshakePacket=^TRNLProtocolHandshakePacket;
     TRNLProtocolHandshakePacket=packed record
      case TRNLProtocolHandshakePacketType of
       RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_NONE:(
        Header:TRNLProtocolHandshakePacketHeader;
       );
       RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_REQUEST:(
        ConnectionRequest:TRNLProtocolHandshakePacketConnectionRequest;
       );
       RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_CHALLENGE_REQUEST:(
        ConnectionChallengeRequest:TRNLProtocolHandshakePacketConnectionChallengeRequest;
       );
       RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_CHALLENGE_RESPONSE:(
        ConnectionChallengeResponse:TRNLProtocolHandshakePacketConnectionChallengeResponse;
       );
       RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_AUTHENTICATION_REQUEST:(
        ConnectionAuthenticationRequest:TRNLProtocolHandshakePacketConnectionAuthenticationRequest;
       );
       RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_AUTHENTICATION_RESPONSE:(
        ConnectionAuthenticationResponse:TRNLProtocolHandshakePacketConnectionAuthenticationResponse;
       );
       RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_APPROVAL_RESPONSE:(
        ConnectionApprovalResponse:TRNLProtocolHandshakePacketConnectionApprovalResponse;
       );
       RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_DENIAL_RESPONSE:(
        ConnectionDenialResponse:TRNLProtocolHandshakePacketConnectionDenialResponse;
       );
       RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_APPROVAL_ACKNOWLEDGE:(
        ConnectionApprovalAcknowledge:TRNLProtocolHandshakePacketConnectionApprovalAcknowledge;
       );
       RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_DENIAL_ACKNOWLEDGE:(
        ConnectionDenialAcknowledge:TRNLProtocolHandshakePacketConnectionDenialAcknowledge;
       );
     end;

     PRNLProtocolNormalPacketHeader=^TRNLProtocolNormalPacketHeader;
     TRNLProtocolNormalPacketHeader=packed record
      PeerID:TRNLUInt16;
      Flags:TRNLUInt8;
      Not255:TRNLUInt8; // <= Must be never 255, otherwise we've a conflict with RNLProtocolHandshakePacketHeaderSignature at this packet data position
      SentTime:TRNLUInt16;
      EncryptedPacketSequenceNumber:TRNLUInt64;
      PayloadMAC:TRNLCipherMAC;
      // No extra checksum, because the Authenticated Encryption with Associated Data (AEAD) stuff
      // does also this task as a positive side-effect
     end;

     PRNLProtocolBlockPacketType=^TRNLProtocolBlockPacketType;
     TRNLProtocolBlockPacketType=
      (
       RNL_PROTOCOL_BLOCK_PACKET_TYPE_NONE=0,
       RNL_PROTOCOL_BLOCK_PACKET_TYPE_PING=1,
       RNL_PROTOCOL_BLOCK_PACKET_TYPE_PONG=2,
       RNL_PROTOCOL_BLOCK_PACKET_TYPE_DISCONNECT=3,
       RNL_PROTOCOL_BLOCK_PACKET_TYPE_DISCONNECT_ACKNOWLEGDEMENT=4,
       RNL_PROTOCOL_BLOCK_PACKET_TYPE_BANDWIDTH_LIMITS=5,
       RNL_PROTOCOL_BLOCK_PACKET_TYPE_BANDWIDTH_LIMITS_ACKNOWLEGDEMENT=6,
       RNL_PROTOCOL_BLOCK_PACKET_TYPE_MTU_PROBE=7,
       RNL_PROTOCOL_BLOCK_PACKET_TYPE_CHANNEL=8
      );

     PRNLProtocolBlockPacketHeader=^TRNLProtocolBlockPacketHeader;
     TRNLProtocolBlockPacketHeader=packed record // 1 byte
      TypeAndSubtype:TRNLUInt8;
     end;

     PRNLProtocolBlockPacketPing=^TRNLProtocolBlockPacketPing;
     TRNLProtocolBlockPacketPing=packed record // 2 bytes
      Header:TRNLProtocolBlockPacketHeader;
      SequenceNumber:TRNLUInt8;
     end;

     PRNLProtocolBlockPacketPong=^TRNLProtocolBlockPacketPong;
     TRNLProtocolBlockPacketPong=packed record // 4 bytes
      Header:TRNLProtocolBlockPacketHeader;
      SequenceNumber:TRNLUInt8;
      SentTime:TRNLUInt16;
     end;

     PRNLProtocolBlockPacketDisconnect=^TRNLProtocolBlockPacketDisconnect;
     TRNLProtocolBlockPacketDisconnect=packed record // 9 bytes
      Header:TRNLProtocolBlockPacketHeader;
      Data:TRNLUInt64;
     end;

     PRNLProtocolBlockPacketDisconnectAcknowledgement=^TRNLProtocolBlockPacketDisconnectAcknowledgement;
     TRNLProtocolBlockPacketDisconnectAcknowledgement=packed record // 2 bytes
      Header:TRNLProtocolBlockPacketHeader;
      SequenceNumber:TRNLUInt8;
     end;

     PRNLProtocolBlockPacketBandwidthLimits=^TRNLProtocolBlockPacketBandwidthLimits;
     TRNLProtocolBlockPacketBandwidthLimits=packed record // 10 bytes
      Header:TRNLProtocolBlockPacketHeader;
      SequenceNumber:TRNLUInt8;
      IncomingBandwidthLimit:TRNLUInt32;
      OutgoingBandwidthLimit:TRNLUInt32;
     end;

     PRNLProtocolBlockPacketBandwidthLimitsAcknowledgement=^TRNLProtocolBlockPacketBandwidthLimitsAcknowledgement;
     TRNLProtocolBlockPacketBandwidthLimitsAcknowledgement=packed record // 2 bytes
      Header:TRNLProtocolBlockPacketHeader;
      SequenceNumber:TRNLUInt8;
     end;

     PRNLProtocolBlockPacketMTUProbe=^TRNLProtocolBlockPacketMTUProbe;
     TRNLProtocolBlockPacketMTUProbe=packed record // 8 bytes + size of dummy payload
      Header:TRNLProtocolBlockPacketHeader;
      SequenceNumber:TRNLUInt16;
      Phase:TRNLUInt8;
      Size:TRNLUInt16;
      PayloadDataLength:TRNLUInt16;
     end;

     PRNLProtocolBlockPacketChannel=^TRNLProtocolBlockPacketChannel;
     TRNLProtocolBlockPacketChannel=packed record // 4 bytes + size of channel-protocol-dependent payload
      Header:TRNLProtocolBlockPacketHeader;
      ChannelNumber:TRNLUInt8;
      PayloadDataLength:TRNLUInt16;
     end;

     PRNLProtocolBlockPacket=^TRNLProtocolBlockPacket;
     TRNLProtocolBlockPacket=packed record
      case TRNLProtocolBlockPacketType of
       RNL_PROTOCOL_BLOCK_PACKET_TYPE_NONE:(
        Header:TRNLProtocolBlockPacketHeader;
       );
       RNL_PROTOCOL_BLOCK_PACKET_TYPE_PING:(
        Ping:TRNLProtocolBlockPacketPing;
       );
       RNL_PROTOCOL_BLOCK_PACKET_TYPE_PONG:(
        Pong:TRNLProtocolBlockPacketPong;
       );
       RNL_PROTOCOL_BLOCK_PACKET_TYPE_DISCONNECT:(
        Disconnect:TRNLProtocolBlockPacketDisconnect;
       );
       RNL_PROTOCOL_BLOCK_PACKET_TYPE_DISCONNECT_ACKNOWLEGDEMENT:(
        DisconnectAcknowledgement:TRNLProtocolBlockPacketDisconnectAcknowledgement;
       );
       RNL_PROTOCOL_BLOCK_PACKET_TYPE_BANDWIDTH_LIMITS:(
        BandwidthLimits:TRNLProtocolBlockPacketBandwidthLimits;
       );
       RNL_PROTOCOL_BLOCK_PACKET_TYPE_BANDWIDTH_LIMITS_ACKNOWLEGDEMENT:(
        BandwidthLimitsAcknowledgement:TRNLProtocolBlockPacketBandwidthLimitsAcknowledgement;
       );
       RNL_PROTOCOL_BLOCK_PACKET_TYPE_MTU_PROBE:(
        MTUProbe:TRNLProtocolBlockPacketMTUProbe;
       );
       RNL_PROTOCOL_BLOCK_PACKET_TYPE_CHANNEL:(
        Channel:TRNLProtocolBlockPacketChannel;
       );
     end;

     TRNLInstance=class;

     TRNLRawByteDataArray=array of TRNLUInt8;

     PRNLMessageFlag=^TRNLMessageFlag;
     TRNLMessageFlag=
      (
       RNL_MESSAGE_FLAG_NO_ALLOCATE,
       RNL_MESSAGE_FLAG_NO_FREE
      );

     PRNLMessageFlags=^TRNLMessageFlags;
     TRNLMessageFlags=set of TRNLMessageFlag;

     TRNLMessage=class;

     TRNLMessageFreeCallback=procedure(const aMessage:TRNLMessage) of object;

     TRNLMessage=class
      private
       fReferenceCount:TRNLInt32;
       fFlags:TRNLMessageFlags;
       fData:TRNLPointer;
       fDataLength:TRNLUInt32;
       fFreeCallback:TRNLMessageFreeCallback;
       fUserData:TRNLPointer;
       function GetDataAsString:TRNLRawByteString;
      public
       constructor CreateFromMemory(const aData:TRNLPointer;const aDataLength:TRNLUInt32;const aFlags:TRNLMessageFlags=[]); reintroduce; overload;
       constructor CreateFromString(const aData:TRNLRawByteString;const aFlags:TRNLMessageFlags=[]); reintroduce; overload;
       constructor CreateFromStream(const aStream:TStream;const aFlags:TRNLMessageFlags=[]); reintroduce; overload;
       destructor Destroy; override;
       procedure IncRef;
       procedure DecRef;
       procedure Resize(const aDataLength:TRNLUInt32);
       property Data:TRNLPointer read fData write fData;
       property UserData:TRNLPointer read fUserData write fUserData;
      published
       property ReferenceCount:TRNLInt32 read fReferenceCount write fReferenceCount;
       property Flags:TRNLMessageFlags read fFlags write fFlags;
       property DataLength:TRNLUInt32 read fDataLength write fDataLength;
       property FreeCallback:TRNLMessageFreeCallback read fFreeCallback write fFreeCallback;
       property AsString:TRNLRawByteString read GetDataAsString;
     end;

     TRNLMessageQueue=TRNLQueue<TRNLMessage>;

     TRNLCompressor=class
      public
       constructor Create; reintroduce; virtual;
      destructor Destroy; override;
       function Compress(const aInData:TRNLPointer;const aInSize:TRNLSizeUInt;const aOutData:TRNLPointer;const aOutLimit:TRNLSizeUInt):TRNLSizeUInt; virtual;
       function Decompress(const aInData:TRNLPointer;const aInSize:TRNLSizeUInt;const aOutData:TRNLPointer;const aOutLimit:TRNLSizeUInt):TRNLSizeUInt; virtual;
     end;

     TRNLCompressorClass=class of TRNLCompressor;

     TRNLCompressorDeflate=class(TRNLCompressor)
      protected
       const HashBits=16;
             HashSize=1 shl HashBits;
             HashMask=HashSize-1;
             HashShift=32-HashBits;
             WindowSize=32768;
             WindowMask=WindowSize-1;
             MinMatch=3;
             MaxMatch=258;
             MaxOffset=32768;
       const LengthCodes:array[0..28,0..3] of TRNLUInt32=
              ( // Code, ExtraBits, Min, Max
               (257,0,3,3),
               (258,0,4,4),
               (259,0,5,5),
               (260,0,6,6),
               (261,0,7,7),
               (262,0,8,8),
               (263,0,9,9),
               (264,0,10,10),
               (265,1,11,12),
               (266,1,13,14),
               (267,1,15,16),
               (268,1,17,18),
               (269,2,19,22),
               (270,2,23,26),
               (271,2,27,30),
               (272,2,31,34),
               (273,3,35,42),
               (274,3,43,50),
               (275,3,51,58),
               (276,3,59,66),
               (277,4,67,82),
               (278,4,83,98),
               (279,4,99,114),
               (280,4,115,130),
               (281,5,131,162),
               (282,5,163,194),
               (283,5,195,226),
               (284,5,227,257),
               (285,0,258,258)
              );
             DistanceCodes:array[0..29,0..3] of TRNLUInt32=
              ( // Code, ExtraBits, Min, Max
               (0,0,1,1),
               (1,0,2,2),
               (2,0,3,3),
               (3,0,4,4),
               (4,1,5,6),
               (5,1,7,8),
               (6,2,9,12),
               (7,2,13,16),
               (8,3,17,24),
               (9,3,25,32),
               (10,4,33,48),
               (11,4,49,64),
               (12,5,65,96),
               (13,5,97,128),
               (14,6,129,192),
               (15,6,193,256),
               (16,7,257,384),
               (17,7,385,512),
               (18,8,513,768),
               (19,8,769,1024),
               (20,9,1025,1536),
               (21,9,1537,2048),
               (22,10,2049,3072),
               (23,10,3073,4096),
               (24,11,4097,6144),
               (25,11,6145,8192),
               (26,12,8193,12288),
               (27,12,12289,16384),
               (28,13,16385,24576),
               (29,13,24577,32768)
              );
             MirrorBytes:array[TRNLUInt8] of TRNLUInt8=
              (
               $00,$80,$40,$c0,$20,$a0,$60,$e0,
               $10,$90,$50,$d0,$30,$b0,$70,$f0,
               $08,$88,$48,$c8,$28,$a8,$68,$e8,
               $18,$98,$58,$d8,$38,$b8,$78,$f8,
               $04,$84,$44,$c4,$24,$a4,$64,$e4,
               $14,$94,$54,$d4,$34,$b4,$74,$f4,
               $0c,$8c,$4c,$cc,$2c,$ac,$6c,$ec,
               $1c,$9c,$5c,$dc,$3c,$bc,$7c,$fc,
               $02,$82,$42,$c2,$22,$a2,$62,$e2,
               $12,$92,$52,$d2,$32,$b2,$72,$f2,
               $0a,$8a,$4a,$ca,$2a,$aa,$6a,$ea,
               $1a,$9a,$5a,$da,$3a,$ba,$7a,$fa,
               $06,$86,$46,$c6,$26,$a6,$66,$e6,
               $16,$96,$56,$d6,$36,$b6,$76,$f6,
               $0e,$8e,$4e,$ce,$2e,$ae,$6e,$ee,
               $1e,$9e,$5e,$de,$3e,$be,$7e,$fe,
               $01,$81,$41,$c1,$21,$a1,$61,$e1,
               $11,$91,$51,$d1,$31,$b1,$71,$f1,
               $09,$89,$49,$c9,$29,$a9,$69,$e9,
               $19,$99,$59,$d9,$39,$b9,$79,$f9,
               $05,$85,$45,$c5,$25,$a5,$65,$e5,
               $15,$95,$55,$d5,$35,$b5,$75,$f5,
               $0d,$8d,$4d,$cd,$2d,$ad,$6d,$ed,
               $1d,$9d,$5d,$dd,$3d,$bd,$7d,$fd,
               $03,$83,$43,$c3,$23,$a3,$63,$e3,
               $13,$93,$53,$d3,$33,$b3,$73,$f3,
               $0b,$8b,$4b,$cb,$2b,$ab,$6b,$eb,
               $1b,$9b,$5b,$db,$3b,$bb,$7b,$fb,
               $07,$87,$47,$c7,$27,$a7,$67,$e7,
               $17,$97,$57,$d7,$37,$b7,$77,$f7,
               $0f,$8f,$4f,$cf,$2f,$af,$6f,$ef,
               $1f,$9f,$5f,$df,$3f,$bf,$7f,$ff
              );
             CLCIndex:array[0..18] of TRNLUInt8=(16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15);
       type PHashTable=^THashTable;
            THashTable=array[0..HashSize-1] of PRNLUInt8;
            PChainTable=^TChainTable;
            TChainTable=array[0..WindowSize-1] of TRNLPointer;
            PTree=^TTree;
            TTree=packed record
             Table:array[0..15] of TRNLUInt16;
             Translation:array[0..287] of TRNLUInt16;
            end;
            PBuffer=^TBuffer;
            TBuffer=array[0..65535] of TRNLUInt8;
            PLengths=^TLengths;
            TLengths=array[0..288+32-1] of TRNLUInt8;
            POffsets=^TOffsets;
            TOffsets=array[0..15] of TRNLUInt16;
            TBits=array[0..29] of TRNLUInt8;
            PBits=^TBits;
            TBase=array[0..29] of TRNLUInt16;
            PBase=^TBase;
      private
       fHashTable:THashTable;
       fChainTable:TChainTable;
       fLengthCodesLookUpTable:array[0..258] of TRNLInt32;
       fDistanceCodesLookUpTable:array[0..32768] of TRNLInt32;
       fSymbolLengthTree:TTree;
       fDistanceTree:TTree;
       fFixedSymbolLengthTree:TTree;
       fFixedDistanceTree:TTree;
       fLengthBits:TBits;
       fDistanceBits:TBits;
       fLengthBase:TBase;
       fDistanceBase:TBase;
       fCodeTree:TTree;
       fLengths:TLengths;
       fWithHeader:boolean;
       fGreedy:boolean;
       fSkipStrength:TRNLUInt32;
       fMaxSteps:TRNLUInt32;
      public
       constructor Create; override;
       destructor Destroy; override;
       function Compress(const aInData:TRNLPointer;const aInSize:TRNLSizeUInt;const aOutData:TRNLPointer;const aOutLimit:TRNLSizeUInt):TRNLSizeUInt; override;
       function Decompress(const aInData:TRNLPointer;const aInSize:TRNLSizeUInt;const aOutData:TRNLPointer;const aOutLimit:TRNLSizeUInt):TRNLSizeUInt; override;
      published
       property WithHeader:boolean read fWithHeader write fWithHeader;
       property Greedy:boolean read fGreedy write fGreedy;
       property SkipStrength:TRNLUInt32 read fSkipStrength write fSkipStrength;
       property MaxSteps:TRNLUInt32 read fMaxSteps write fMaxSteps;
     end;

     TRNLCompressorLZBRRC=class(TRNLCompressor)
      protected
       const FlagModel=0;
             PreviousMatchModel=2;
             MatchLowModel=3;
             LiteralModel=35;
             Gamma0Model=291;
             Gamma1Model=547;
             SizeModels=803;
             HashBits=12;
             HashSize=1 shl HashBits;
             HashMask=HashSize-1;
             HashShift=32-HashBits;
             WindowSize=32768;
             WindowMask=WindowSize-1;
             MinMatch=2;
             MaxMatch=$20000000;
             MaxOffset=$40000000;
       type PHashTable=^THashTable;
            THashTable=array[0..HashSize-1] of PRNLUInt8;
            PChainTable=^TChainTable;
            TChainTable=array[0..WindowSize-1] of TRNLPointer;
      private
       fHashTable:THashTable;
       fChainTable:TChainTable;
       fGreedy:boolean;
       fSkipStrength:TRNLUInt32;
       fMaxSteps:TRNLUInt32;
      public
       constructor Create; override;
       destructor Destroy; override;
       function Compress(const aInData:TRNLPointer;const aInSize:TRNLSizeUInt;const aOutData:TRNLPointer;const aOutLimit:TRNLSizeUInt):TRNLSizeUInt; override;
       function Decompress(const aInData:TRNLPointer;const aInSize:TRNLSizeUInt;const aOutData:TRNLPointer;const aOutLimit:TRNLSizeUInt):TRNLSizeUInt; override;
      published
       property Greedy:boolean read fGreedy write fGreedy;
       property SkipStrength:TRNLUInt32 read fSkipStrength write fSkipStrength;
       property MaxSteps:TRNLUInt32 read fMaxSteps write fMaxSteps;
     end;

     TRNLCompressorBRRC=class(TRNLCompressor)
      private
       const FlagModel=0;
             LiteralModel=1;
             SizeModels=257;
      private
      public
       constructor Create; override;
       destructor Destroy; override;
       function Compress(const aInData:TRNLPointer;const aInSize:TRNLSizeUInt;const aOutData:TRNLPointer;const aOutLimit:TRNLSizeUInt):TRNLSizeUInt; override;
       function Decompress(const aInData:TRNLPointer;const aInSize:TRNLSizeUInt;const aOutData:TRNLPointer;const aOutLimit:TRNLSizeUInt):TRNLSizeUInt; override;
      published
     end;

     PRNLHostEventType=^TRNLHostEventType;
     TRNLHostEventType=
      (
       RNL_HOST_EVENT_TYPE_NONE,
       RNL_HOST_EVENT_TYPE_CONNECT,
       RNL_HOST_EVENT_TYPE_DISCONNECT,
       RNL_HOST_EVENT_TYPE_APPROVAL,
       RNL_HOST_EVENT_TYPE_DENIAL,
       RNL_HOST_EVENT_TYPE_BANDWIDTH_LIMITS,
       RNL_HOST_EVENT_TYPE_MTU,
       RNL_HOST_EVENT_TYPE_RECEIVE
      );

     PRNLHostEventConnect=^TRNLHostEventConnect;
     TRNLHostEventConnect=record
      Peer:TRNLPeer;
      Data:TRNLUInt64;
     end;

     PRNLHostEventDisconnect=^TRNLHostEventDisconnect;
     TRNLHostEventDisconnect=record
      Peer:TRNLPeer;
      Data:TRNLUInt64;
     end;

     PRNLHostEventApproval=^TRNLHostEventApproval;
     TRNLHostEventApproval=record
      Peer:TRNLPeer;
      Data:TRNLUInt64;
     end;

     PRNLHostEventDenial=^TRNLHostEventDenial;
     TRNLHostEventDenial=record
      Peer:TRNLPeer;
      Reason:TRNLConnectionDenialReason;
     end;

     PRNLHostEventBandwidthLimits=^TRNLHostEventBandwidthLimits;
     TRNLHostEventBandwidthLimits=record
      Peer:TRNLPeer;
     end;

     PRNLHostEventMTU=^TRNLHostEventMTU;
     TRNLHostEventMTU=record
      Peer:TRNLPeer;
      MTU:TRNLUInt16;
     end;

     PRNLHostEventReceive=^TRNLHostEventReceive;
     TRNLHostEventReceive=record
      Peer:TRNLPeer;
      Channel:TRNLUInt8;
      Message:TRNLMessage;
     end;

     PRNLHostEvent=^TRNLHostEvent;
     TRNLHostEvent=record
      case Type_:TRNLHostEventType of
       RNL_HOST_EVENT_TYPE_CONNECT:(
        Connect:TRNLHostEventConnect;
       );
       RNL_HOST_EVENT_TYPE_DISCONNECT:(
        Disconnect:TRNLHostEventDisconnect;
       );
       RNL_HOST_EVENT_TYPE_APPROVAL:(
        Approval:TRNLHostEventApproval;
       );
       RNL_HOST_EVENT_TYPE_DENIAL:(
        Denial:TRNLHostEventDenial;
       );
       RNL_HOST_EVENT_TYPE_BANDWIDTH_LIMITS:(
        BandwidthLimits:TRNLHostEventBandwidthLimits;
       );
       RNL_HOST_EVENT_TYPE_MTU:(
        MTU:TRNLHostEventMTU;
       );
       RNL_HOST_EVENT_TYPE_RECEIVE:(
        Receive:TRNLHostEventReceive;
       );
     end;

     TRNLHostEventQueue=TRNLQueue<TRNLHostEvent>;

     PRNLHostServiceStatus=^TRNLHostServiceStatus;
     TRNLHostServiceStatus=
      (
       RNL_HOST_SERVICE_STATUS_ERROR,
       RNL_HOST_SERVICE_STATUS_TIMEOUT,
       RNL_HOST_SERVICE_STATUS_EVENT
      );

     TRNLHostSockets=array[0..1] of TRNLSocket;

     TRNLHostOnCheckConnectionToken=function(const aHost:TRNLHost;const aAddress:TRNLAddress;const aConnectionToken:TRNLConnectionToken):boolean of object;

     TRNLHostOnCheckAuthenticationToken=function(const aHost:TRNLHost;const aAddress:TRNLAddress;const aAuthenticationToken:TRNLAuthenticationToken):boolean of object;

     TRNLHostNetworkPacketData=TBytes;

     TRNLHostPeerCircularDoublyLinkedListNode=TRNLCircularDoublyLinkedListNode<TRNLPeer>;

     TRNLHostPeerIDMap=TRNLIDMap<TRNLPeer>;

     TRNLHostPeerList=TRNLObjectList<TRNLPeer>;

     TRNLInstance=class
      private
       fTimeBase:TRNLTime;
{$if defined(RNL_DEBUG)}
       fDebugLock:TCriticalSection;
{$ifend}
       class procedure GlobalInitialize;
       class procedure GlobalFinalize;
       function GetTime:TRNLTime;
       procedure SetTime(const aTimeBase:TRNLTime);
      public
       constructor Create; reintroduce;
       destructor Destroy; override;
       property Time:TRNLTime read GetTime write SetTime;
     end;

     PRNLNetworkSendResult=^TRNLNetworkSendResult;
     TRNLNetworkSendResult=
      (
       RNL_NETWORK_SEND_RESULT_ERROR,
       RNL_NETWORK_SEND_RESULT_OK,
       RNL_NETWORK_SEND_RESULT_BANDWIDTH_RATE_LIMITER_DROP
      );

     TRNLNetwork=class
      private
       fInstance:TRNLInstance;
      public
       constructor Create(const aInstance:TRNLInstance); reintroduce; virtual;
       destructor Destroy; override;
       function AddressSetHost(var aAddress:TRNLAddress;const aName:TRNLRawByteString):boolean; virtual;
       function AddressGetHost(const aAddress:TRNLAddress;out aName;const aNameLength:TRNLInt32;const aFlags:TRNLInt32=0):boolean; virtual;
       function AddressGetHostIP(const aAddress:TRNLAddress;out aName;const aNameLength:TRNLInt32):boolean; virtual;
       function SocketCreate(const aType:TRNLSocketType;const aFamily:TRNLAddressFamily):TRNLSocket; virtual;
       procedure SocketDestroy(const aSocket:TRNLSocket); virtual;
       function SocketShutdown(const aSocket:TRNLSocket;const aHow:TRNLSocketShutdown=RNL_SOCKET_SHUTDOWN_READ):boolean; virtual;
       function SocketGetAddress(const aSocket:TRNLSocket;out aAddress:TRNLAddress;const aFamily:TRNLAddressFamily):boolean; virtual;
       function SocketSetOption(const aSocket:TRNLSocket;const aOption:TRNLSocketOption;const aValue:TRNLInt32):boolean; virtual;
       function SocketGetOption(const aSocket:TRNLSocket;const aOption:TRNLSocketOption;out aValue:TRNLInt32):boolean; virtual;
       function SocketBind(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aFamily:TRNLAddressFamily):boolean; virtual;
       function SocketListen(const aSocket:TRNLSocket;const aBackLog:TRNLInt32):boolean; virtual;
       function SocketConnect(const aSocket:TRNLSocket;const aAddress:TRNLAddress;const aFamily:TRNLAddressFamily):boolean; virtual;
       function SocketAccept(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aFamily:TRNLAddressFamily):TRNLSocket; virtual;
       function SocketSelect(const aMaxSocket:TRNLSocket;var aReadSet,aWriteSet:TRNLSocketSet;const aTimeout:TRNLTime):TRNLInt32; virtual;
       function SocketWait(const aSockets:array of TRNLSocket;var aConditions:TRNLSocketWaitConditions;const aTimeout:TRNLTime):boolean; virtual;
       function SendBuffers(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aBuffers;const aCountBuffers:TRNLUInt32;const aFamily:TRNLAddressFamily):TRNLSizeInt; virtual;
       function ReceiveBuffers(const aSocket:TRNLSocket;const aAddress:PRNLAddress;var aBuffers;const aCountBuffers:TRNLUInt32;const aFamily:TRNLAddressFamily):TRNLSizeInt; virtual;
       function Send(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aData;const aDataLength:TRNLSizeInt;const aFamily:TRNLAddressFamily):TRNLSizeInt; virtual;
       function Receive(const aSocket:TRNLSocket;const aAddress:PRNLAddress;var aData;const aDataLength:TRNLSizeInt;const aFamily:TRNLAddressFamily):TRNLSizeInt; virtual;
      published
       property Instance:TRNLInstance read fInstance;
     end;

     TRNLRealNetwork=class(TRNLNetwork)
      private
       class procedure GlobalInitialize;
       class procedure GlobalFinalize;
      public
       constructor Create(const aInstance:TRNLInstance); override;
       destructor Destroy; override;
       function AddressSetHost(var aAddress:TRNLAddress;const aName:TRNLRawByteString):boolean; override;
       function AddressGetHost(const aAddress:TRNLAddress;out aName;const aNameLength:TRNLInt32;const aFlags:TRNLInt32=0):boolean; override;
       function AddressGetHostIP(const aAddress:TRNLAddress;out aName;const aNameLength:TRNLInt32):boolean; override;
       function SocketCreate(const aType:TRNLSocketType;const aFamily:TRNLAddressFamily):TRNLSocket; override;
       procedure SocketDestroy(const aSocket:TRNLSocket); override;
       function SocketShutdown(const aSocket:TRNLSocket;const aHow:TRNLSocketShutdown=RNL_SOCKET_SHUTDOWN_READ):boolean; override;
       function SocketGetAddress(const aSocket:TRNLSocket;out aAddress:TRNLAddress;const aFamily:TRNLAddressFamily):boolean; override;
       function SocketSetOption(const aSocket:TRNLSocket;const aOption:TRNLSocketOption;const aValue:TRNLInt32):boolean; override;
       function SocketGetOption(const aSocket:TRNLSocket;const aOption:TRNLSocketOption;out aValue:TRNLInt32):boolean; override;
       function SocketBind(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aFamily:TRNLAddressFamily):boolean; override;
       function SocketListen(const aSocket:TRNLSocket;const aBackLog:TRNLInt32):boolean; override;
       function SocketConnect(const aSocket:TRNLSocket;const aAddress:TRNLAddress;const aFamily:TRNLAddressFamily):boolean; override;
       function SocketAccept(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aFamily:TRNLAddressFamily):TRNLSocket; override;
       function SocketSelect(const aMaxSocket:TRNLSocket;var aReadSet,aWriteSet:TRNLSocketSet;const aTimeout:TRNLTime):TRNLInt32; override;
       function SocketWait(const aSockets:array of TRNLSocket;var aConditions:TRNLSocketWaitConditions;const aTimeout:TRNLTime):boolean; override;
       function SendBuffers(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aBuffers;const aCountBuffers:TRNLUInt32;const aFamily:TRNLAddressFamily):TRNLSizeInt; override;
       function ReceiveBuffers(const aSocket:TRNLSocket;const aAddress:PRNLAddress;var aBuffers;const aCountBuffers:TRNLUInt32;const aFamily:TRNLAddressFamily):TRNLSizeInt; override;
       function Send(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aData;const aDataLength:TRNLSizeInt;const aFamily:TRNLAddressFamily):TRNLSizeInt; override;
       function Receive(const aSocket:TRNLSocket;const aAddress:PRNLAddress;var aData;const aDataLength:TRNLSizeInt;const aFamily:TRNLAddressFamily):TRNLSizeInt; override;
     end;

     TRNLVirtualNetwork=class(TRNLNetwork)
      private
       const RNL_VIRTUAL_NETWORK_SOCKET_HASH_BITS=12;
             RNL_VIRTUAL_NETWORK_SOCKET_HASH_SIZE=1 shl RNL_VIRTUAL_NETWORK_SOCKET_HASH_BITS;
             RNL_VIRTUAL_NETWORK_SOCKET_HASH_MASK=RNL_VIRTUAL_NETWORK_SOCKET_HASH_SIZE-1;
       type TRNLVirtualNetworkSocketStack=TRNLStack<TRNLSocket>;
            TRNLVirtualNetworkSocketData=record
             Address:TRNLAddress;
             Data:TBytes;
            end;
            TRNLVirtualNetworkSocketDataQueue=TRNLQueue<TRNLVirtualNetworkSocketData>;
            TRNLVirtualNetworkSocketInstance=class;
            TRNLVirtualNetworkSocketInstanceListNode=TRNLCircularDoublyLinkedListNode<TRNLVirtualNetworkSocketInstance>;
            TRNLVirtualNetworkSocketInstance=class(TRNLVirtualNetworkSocketInstanceListNode)
             private
              fNetwork:TRNLVirtualNetwork;
              fSocket:TRNLSocket;
              fAddress:TRNLAddress;
              fAddressHash:TRNLUInt32;
              fAddressListNode:TRNLVirtualNetworkSocketInstanceListNode;
              fSocketInstanceListNode:TRNLVirtualNetworkSocketInstanceListNode;
              fData:TRNLVirtualNetworkSocketDataQueue;
             public
              constructor Create(const aNetwork:TRNLVirtualNetwork;const aSocket:TRNLSocket); reintroduce;
              destructor Destroy; override;
              procedure UpdateAddress;
            end;
            TRNLVirtualNetworkSocketInstanceHashMap=array[0..RNL_VIRTUAL_NETWORK_SOCKET_HASH_SIZE-1] of TRNLVirtualNetworkSocketInstanceListNode;
      private
       fLock:TCriticalSection;
       fNewDataEvent:TEvent;
       fSocketCounter:TRNLSocket;
       fFreeSockets:TRNLVirtualNetworkSocketStack;
       fSocketInstanceList:TRNLVirtualNetworkSocketInstanceListNode;
       fSocketInstanceHashMap:TRNLVirtualNetworkSocketInstanceHashMap;
       fAddressSocketInstanceHashMap:TRNLVirtualNetworkSocketInstanceHashMap;
       class function HashSocket(const aSocket:TRNLSocket):TRNLUInt32; static;
       class function HashAddress(const aAddress:TRNLAddress):TRNLUInt32; static;
       function FindSocketInstance(const aSocket:TRNLSocket;const aCreateIfNotExist:boolean):TRNLVirtualNetworkSocketInstance;
       function FindAddressSocketInstance(const aAddress:TRNLAddress):TRNLVirtualNetworkSocketInstance;
      public
       constructor Create(const aInstance:TRNLInstance); override;
       destructor Destroy; override;
       function AddressSetHost(var aAddress:TRNLAddress;const aName:TRNLRawByteString):boolean; override;
       function AddressGetHost(const aAddress:TRNLAddress;out aName;const aNameLength:TRNLInt32;const aFlags:TRNLInt32=0):boolean; override;
       function AddressGetHostIP(const aAddress:TRNLAddress;out aName;const aNameLength:TRNLInt32):boolean; override;
       function SocketCreate(const aType:TRNLSocketType;const aFamily:TRNLAddressFamily):TRNLSocket; override;
       procedure SocketDestroy(const aSocket:TRNLSocket); override;
       function SocketShutdown(const aSocket:TRNLSocket;const aHow:TRNLSocketShutdown=RNL_SOCKET_SHUTDOWN_READ):boolean; override;
       function SocketGetAddress(const aSocket:TRNLSocket;out aAddress:TRNLAddress;const aFamily:TRNLAddressFamily):boolean; override;
       function SocketSetOption(const aSocket:TRNLSocket;const aOption:TRNLSocketOption;const aValue:TRNLInt32):boolean; override;
       function SocketGetOption(const aSocket:TRNLSocket;const aOption:TRNLSocketOption;out aValue:TRNLInt32):boolean; override;
       function SocketBind(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aFamily:TRNLAddressFamily):boolean; override;
       function SocketListen(const aSocket:TRNLSocket;const aBackLog:TRNLInt32):boolean; override;
       function SocketConnect(const aSocket:TRNLSocket;const aAddress:TRNLAddress;const aFamily:TRNLAddressFamily):boolean; override;
       function SocketAccept(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aFamily:TRNLAddressFamily):TRNLSocket; override;
       function SocketSelect(const aMaxSocket:TRNLSocket;var aReadSet,aWriteSet:TRNLSocketSet;const aTimeout:TRNLTime):TRNLInt32; override;
       function SocketWait(const aSockets:array of TRNLSocket;var aConditions:TRNLSocketWaitConditions;const aTimeout:TRNLTime):boolean; override;
       function SendBuffers(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aBuffers;const aCountBuffers:TRNLUInt32;const aFamily:TRNLAddressFamily):TRNLSizeInt; override;
       function ReceiveBuffers(const aSocket:TRNLSocket;const aAddress:PRNLAddress;var aBuffers;const aCountBuffers:TRNLUInt32;const aFamily:TRNLAddressFamily):TRNLSizeInt; override;
       function Send(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aData;const aDataLength:TRNLSizeInt;const aFamily:TRNLAddressFamily):TRNLSizeInt; override;
       function Receive(const aSocket:TRNLSocket;const aAddress:PRNLAddress;var aData;const aDataLength:TRNLSizeInt;const aFamily:TRNLAddressFamily):TRNLSizeInt; override;
     end;

     TRNLNetworkInterferenceSimulator=class(TRNLNetwork)
      private
       type TRNLNetworkInterferenceSimulatorPacket=class;
            TRNLNetworkInterferenceSimulatorPacketListNode=TRNLCircularDoublyLinkedListNode<TRNLNetworkInterferenceSimulatorPacket>;
            TRNLNetworkInterferenceSimulatorPacket=class(TRNLNetworkInterferenceSimulatorPacketListNode)
             private
              fNetworkInterferenceSimulator:TRNLNetworkInterferenceSimulator;
              fTime:TRNLTime;
              fSocket:TRNLSocket;
              fAddress:TRNLAddress;
              fData:TBytes;
              fFamily:TRNLAddressFamily;
             public
              constructor Create(const aNetworkInterferenceSimulator:TRNLNetworkInterferenceSimulator);
              destructor Destroy; override;
            end;
      private
       fNetwork:TRNLNetwork;
       fLock:TCriticalSection;
       fRandomGenerator:TRNLRandomGenerator;
       fNextTimeout:TRNLTime;
       fIncomingPacketList:TRNLNetworkInterferenceSimulatorPacketListNode;
       fOutgoingPacketList:TRNLNetworkInterferenceSimulatorPacketListNode;
       fSimulatedIncomingPacketLossProbabilityFactor:TRNLUInt32;
       fSimulatedOutgoingPacketLossProbabilityFactor:TRNLUInt32;
       fSimulatedIncomingDuplicatePacketProbabilityFactor:TRNLUInt32;
       fSimulatedOutgoingDuplicatePacketProbabilityFactor:TRNLUInt32;
       fSimulatedIncomingLatency:TRNLUInt32;
       fSimulatedOutgoingLatency:TRNLUInt32;
       fSimulatedIncomingJitter:TRNLUInt32;
       fSimulatedOutgoingJitter:TRNLUInt32;
       function SimulateIncomingPacketLoss:boolean;
       function SimulateOutgoingPacketLoss:boolean;
       function SimulateIncomingDuplicatePacket:boolean;
       function SimulateOutgoingDuplicatePacket:boolean;
       procedure Update;
      public
       constructor Create(const aInstance:TRNLInstance;const aNetwork:TRNLNetwork); reintroduce;
       destructor Destroy; override;
       function AddressSetHost(var aAddress:TRNLAddress;const aName:TRNLRawByteString):boolean; override;
       function AddressGetHost(const aAddress:TRNLAddress;out aName;const aNameLength:TRNLInt32;const aFlags:TRNLInt32=0):boolean; override;
       function AddressGetHostIP(const aAddress:TRNLAddress;out aName;const aNameLength:TRNLInt32):boolean; override;
       function SocketCreate(const aType:TRNLSocketType;const aFamily:TRNLAddressFamily):TRNLSocket; override;
       procedure SocketDestroy(const aSocket:TRNLSocket); override;
       function SocketShutdown(const aSocket:TRNLSocket;const aHow:TRNLSocketShutdown=RNL_SOCKET_SHUTDOWN_READ):boolean; override;
       function SocketGetAddress(const aSocket:TRNLSocket;out aAddress:TRNLAddress;const aFamily:TRNLAddressFamily):boolean; override;
       function SocketSetOption(const aSocket:TRNLSocket;const aOption:TRNLSocketOption;const aValue:TRNLInt32):boolean; override;
       function SocketGetOption(const aSocket:TRNLSocket;const aOption:TRNLSocketOption;out aValue:TRNLInt32):boolean; override;
       function SocketBind(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aFamily:TRNLAddressFamily):boolean; override;
       function SocketListen(const aSocket:TRNLSocket;const aBackLog:TRNLInt32):boolean; override;
       function SocketConnect(const aSocket:TRNLSocket;const aAddress:TRNLAddress;const aFamily:TRNLAddressFamily):boolean; override;
       function SocketAccept(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aFamily:TRNLAddressFamily):TRNLSocket; override;
       function SocketSelect(const aMaxSocket:TRNLSocket;var aReadSet,aWriteSet:TRNLSocketSet;const aTimeout:TRNLTime):TRNLInt32; override;
       function SocketWait(const aSockets:array of TRNLSocket;var aConditions:TRNLSocketWaitConditions;const aTimeout:TRNLTime):boolean; override;
       function SendBuffers(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aBuffers;const aCountBuffers:TRNLUInt32;const aFamily:TRNLAddressFamily):TRNLSizeInt; override;
       function ReceiveBuffers(const aSocket:TRNLSocket;const aAddress:PRNLAddress;var aBuffers;const aCountBuffers:TRNLUInt32;const aFamily:TRNLAddressFamily):TRNLSizeInt; override;
       function Send(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aData;const aDataLength:TRNLSizeInt;const aFamily:TRNLAddressFamily):TRNLSizeInt; override;
       function Receive(const aSocket:TRNLSocket;const aAddress:PRNLAddress;var aData;const aDataLength:TRNLSizeInt;const aFamily:TRNLAddressFamily):TRNLSizeInt; override;
      published
       property SimulatedIncomingPacketLossProbabilityFactor:TRNLUInt32 read fSimulatedIncomingPacketLossProbabilityFactor write fSimulatedIncomingPacketLossProbabilityFactor;
       property SimulatedOutgoingPacketLossProbabilityFactor:TRNLUInt32 read fSimulatedOutgoingPacketLossProbabilityFactor write fSimulatedOutgoingPacketLossProbabilityFactor;
       property SimulatedIncomingDuplicatePacketProbabilityFactor:TRNLUInt32 read fSimulatedIncomingDuplicatePacketProbabilityFactor write fSimulatedIncomingDuplicatePacketProbabilityFactor;
       property SimulatedOutgoingDuplicatePacketProbabilityFactor:TRNLUInt32 read fSimulatedOutgoingDuplicatePacketProbabilityFactor write fSimulatedOutgoingDuplicatePacketProbabilityFactor;
       property SimulatedIncomingLatency:TRNLUInt32 read fSimulatedIncomingLatency write fSimulatedIncomingLatency;
       property SimulatedOutgoingLatency:TRNLUInt32 read fSimulatedOutgoingLatency write fSimulatedOutgoingLatency;
       property SimulatedIncomingJitter:TRNLUInt32 read fSimulatedIncomingJitter write fSimulatedIncomingJitter;
       property SimulatedOutgoingJitter:TRNLUInt32 read fSimulatedOutgoingJitter write fSimulatedOutgoingJitter;
     end;

     PRNLPeerState=^TRNLPeerState;
     TRNLPeerState=
      (
       RNL_PEER_STATE_DISCONNECTED,
       RNL_PEER_STATE_CONNECTION_REQUESTING,
       RNL_PEER_STATE_CONNECTION_CHALLENGING,
       RNL_PEER_STATE_CONNECTION_AUTHENTICATING,
       RNL_PEER_STATE_CONNECTION_APPROVING,
       RNL_PEER_STATE_CONNECTED,
       RNL_PEER_STATE_DISCONNECT_LATER,
       RNL_PEER_STATE_DISCONNECTING,
       RNL_PEER_STATE_DISCONNECTION_ACKNOWLEDGING,
       RNL_PEER_STATE_DISCONNECTION_PENDING
      );

     TRNLPeerPendingConnectionHandshakeSendData=class
      private
       fPeer:TRNLPeer;
       fHandshakePacket:TRNLProtocolHandshakePacket;
      public
       constructor Create(const aPeer:TRNLPeer); reintroduce;
       function Send:boolean;
     end;

     TRNLPeerIncomingEncryptedPacketSequenceBuffer=array of TRNLUInt64;

     TRNLPeerBlockPacketData=TBytes;

     PRNLPeerBlockPacket=^TRNLPeerBlockPacket;

     TRNLPeerBlockPacket=class;

     TRNLPeerBlockPacketCircularDoublyLinkedListNode=TRNLCircularDoublyLinkedListNode<TRNLPeerBlockPacket>;

     TRNLPeerBlockPacket=class(TRNLPeerBlockPacketCircularDoublyLinkedListNode)
      private
       fPeer:TRNLPeer;
       fChannel:TRNLUInt8;
       fSequenceNumber:TRNLSequenceNumber;
       fCountSendAttempts:TRNLUInt32;
       fRoundTripTimeout:TRNLUInt64;
       fRoundTripTimeoutLimit:TRNLUInt64;
       fSentTime:TRNLTime;
       fReceivedTime:TRNLTime;
       fBlockPacket:TRNLProtocolBlockPacket;
       fBlockPacketData:TRNLPeerBlockPacketData;
       fBlockPacketDataLength:TRNLSizeUInt;
       fReferenceCounter:TRNLUInt32;
       fPendingResendOutgoingBlockPacketsList:TRNLPeerBlockPacketCircularDoublyLinkedListNode;
       function GetPointerToBlockPacket:PRNLProtocolBlockPacket; inline;
       function GetSize:TRNLSizeUInt;
      public
       constructor Create(const aPeer:TRNLPeer); reintroduce;
       destructor Destroy; override;
       procedure IncRef;
       procedure DecRef;
       procedure Clear;
       function AppendTo(var aOutgoingPacketBuffer:TRNLOutgoingPacketBuffer):boolean;
       property BlockPacket:PRNLProtocolBlockPacket read GetPointerToBlockPacket;
       property Size:TRNLSizeUInt read GetSize;
     end;

     TRNLPeerBlockPacketQueue=TRNLQueue<TRNLPeerBlockPacket>;

     TRNLPeerBlockPacketStack=TRNLStack<TRNLPeerBlockPacket>;

     TRNLPeerBlockPacketObjectList=TRNLObjectList<TRNLPeerBlockPacket>;

     TRNLPeerChannel=class;

     PRNLPeerChannelType=^TRNLPeerChannelType;
     TRNLPeerChannelType=
      (
       RNL_PEER_RELIABLE_ORDERED_CHANNEL=0,
       RNL_PEER_RELIABLE_UNORDERED_CHANNEL=1,
       RNL_PEER_UNRELIABLE_ORDERED_CHANNEL=2,
       RNL_PEER_UNRELIABLE_UNORDERED_CHANNEL=3
      );

     PRNLPeerChannelTypes=^TRNLPeerChannelTypes;
     TRNLPeerChannelTypes=array[0..RNL_MAXIMUM_PEER_CHANNELS-1] of TRNLPeerChannelType;

     TRNLPeerChannel=class
      private

       fPeer:TRNLPeer;

       fHost:TRNLHost;

       fChannelNumber:TRNLUInt16;

       fIncomingMessageQueue:TRNLMessageQueue;

       fOutgoingMessageQueue:TRNLMessageQueue;

       function GetMaximumUnfragmentedMessageSize:TRNLSizeUInt; virtual;

       procedure DispatchOutgoingBlockPackets; virtual;

       procedure DispatchIncomingBlockPacket(const aBlockPacket:TRNLPeerBlockPacket); virtual;

       procedure DispatchIncomingMessages; virtual;

      public

       constructor Create(const aPeer:TRNLPeer;const aChannelNumber:TRNLUInt16); reintroduce; virtual;
       destructor Destroy; override;

       procedure SendMessage(const aMessage:TRNLMessage);
       procedure SendMessageData(const aData:TRNLPointer;const aDataLength:TRNLUInt32;const aFlags:TRNLMessageFlags=[]);
       procedure SendMessageString(const aString:TRNLRawByteString;const aFlags:TRNLMessageFlags=[]);
       procedure SendMessageStream(const aStream:TStream;const aFlags:TRNLMessageFlags=[]);

       property MaximumUnfragmentedMessageSize:TRNLSizeUInt read GetMaximumUnfragmentedMessageSize;

     end;

     PRNLPeerReliableChannelCommandType=^TRNLPeerReliableChannelCommandType;
     TRNLPeerReliableChannelCommandType=
      (
       RNL_PEER_RELIABLE_CHANNEL_COMMAND_TYPE_SHORT_MESSAGE=0,
       RNL_PEER_RELIABLE_CHANNEL_COMMAND_TYPE_LONG_MESSAGE=1,
       RNL_PEER_RELIABLE_CHANNEL_COMMAND_TYPE_ACKNOWLEDGEMENT=2,
       RNL_PEER_RELIABLE_CHANNEL_COMMAND_TYPE_ACKNOWLEDGEMENTS=3
      );

     PRNLPeerReliableChannelPacketHeader=^TRNLPeerReliableChannelPacketHeader;
     TRNLPeerReliableChannelPacketHeader=packed record
      SequenceNumber:TRNLUInt16;
     end;

     PRNLPeerReliableChannelShortMessagePacketHeader=^TRNLPeerReliableChannelShortMessagePacketHeader;
     TRNLPeerReliableChannelShortMessagePacketHeader=packed record
      Header:TRNLPeerReliableChannelPacketHeader;
     end;

     PRNLPeerReliableChannelLongMessagePacketHeader=^TRNLPeerReliableChannelLongMessagePacketHeader;
     TRNLPeerReliableChannelLongMessagePacketHeader=packed record
      Header:TRNLPeerReliableChannelPacketHeader;
      MessageNumber:TRNLUInt16;
      Offset:TRNLUInt32;
      Length:TRNLUInt32;
     end;

     PRNLPeerReliableChannelAcknowledgementPacketHeader=^TRNLPeerReliableChannelAcknowledgementPacketHeader;
     TRNLPeerReliableChannelAcknowledgementPacketHeader=packed record
      Header:TRNLPeerReliableChannelPacketHeader;
     end;

     PRNLPeerReliableChannelAcknowledgementsPacketHeader=^TRNLPeerReliableChannelAcknowledgementsPacketHeader;
     TRNLPeerReliableChannelAcknowledgementsPacketHeader=packed record
      Header:TRNLPeerReliableChannelPacketHeader;
     end;

     TRNLPeerReliableChannelBlockPacketBufferArray=array of TRNLPeerBlockPacket;

     PRNLPeerReliableChannelAcknowledgement=^TRNLPeerReliableChannelAcknowledgement;
     TRNLPeerReliableChannelAcknowledgement=TRNLInt32;

     TRNLPeerReliableChannelAcknowledgementArray=array of TRNLPeerReliableChannelAcknowledgement;

     TRNLPeerReliableChannel=class(TRNLPeerChannel)
      private

       fOrdered:boolean;

       fIncomingBlockPackets:TRNLPeerReliableChannelBlockPacketBufferArray;
       fIncomingBlockPacketSequenceNumber:TRNLSequenceNumber;

       fIncomingAcknowledgements:TRNLPeerReliableChannelAcknowledgementArray;
       fIncomingAcknowledgementSequenceNumber:TRNLSequenceNumber;

       fOutgoingBlockPackets:TRNLPeerReliableChannelBlockPacketBufferArray;
       fOutgoingBlockPacketSequenceNumber:TRNLSequenceNumber;

       fOutgoingAcknowledgementQueue:TRNLSequenceNumberQueue;

       fOutgoingAcknowledgementArray:TRNLSequenceNumberArray;

       fOutgoingAcknowledgementData:TBytes;

       fOutgoingBlockPacketQueue:TRNLPeerBlockPacketQueue;

       fSentOutgoingBlockPackets:TRNLPeerBlockPacketCircularDoublyLinkedListNode;

       function GetMaximumUnfragmentedMessageSize:TRNLSizeUInt; override;

       procedure DispatchOutgoingBlockPacketsTimeout;

       procedure DispatchOutgoingAcknowledgementBlockPackets;

       procedure DispatchOutgoingMessageBlockPackets; virtual; abstract;

       procedure DispatchOutgoingBlockPackets; override;

       procedure DispatchIncomingMessageBlockPacket(const aBlockPacket:TRNLPeerBlockPacket); virtual; abstract;

       procedure DispatchIncomingBlockPacketAcknowledgement(const aBlockPacketSequenceNumber:TRNLSequenceNumber;const aBlockPacketReceivedTime:TRNLTime);

       procedure DispatchIncomingAcknowledgementsBlockPacket(const aBlockPacket:TRNLPeerBlockPacket);

       procedure DispatchIncomingBlockPacket(const aBlockPacket:TRNLPeerBlockPacket); override;

      public

       constructor Create(const aPeer:TRNLPeer;const aChannelNumber:TRNLUInt16); override;

       destructor Destroy; override;

     end;

     TRNLPeerReliableOrderedChannel=class(TRNLPeerReliableChannel)
      private

       fOutgoingMessageBlockPacketSequenceNumber:TRNLSequenceNumber;

       fOutgoingMessageNumber:TRNLSequenceNumber;

       fIncomingMessageNumber:TRNLSequenceNumber;

       fIncomingMessageLength:TRNLUInt32;

       fIncomingReceivedMessageDataLength:TRNLUInt32;

       fIncomingMessageReceiveBufferData:TRNLPointer;

       procedure DispatchOutgoingMessageBlockPackets; override;

       procedure DispatchIncomingMessageBlockPacket(const aBlockPacket:TRNLPeerBlockPacket); override;

      public

       constructor Create(const aPeer:TRNLPeer;const aChannelNumber:TRNLUInt16); override;

       destructor Destroy; override;

     end;

     TRNLPeerReliableUnorderedChannel=class;

     TRNLPeerReliableUnorderedChannelLongMessage=class;

     TRNLPeerReliableUnorderedChannelLongMessageListNode=TRNLCircularDoublyLinkedListNode<TRNLPeerReliableUnorderedChannelLongMessage>;

     TRNLPeerReliableUnorderedChannelLongMessage=class(TRNLPeerReliableUnorderedChannelLongMessageListNode)
      private

       fChannel:TRNLPeerReliableUnorderedChannel;

       fMessageNumber:TRNLSequenceNumber;

       fIncomingMessageLength:TRNLUInt32;

       fIncomingReceivedMessageDataLength:TRNLUInt32;

       fIncomingMessageReceiveBufferData:TRNLPointer;

       fIncomingMessageReceiveBufferFlagData:TRNLPointer;

       procedure DispatchIncomingData(const aOffset,aLength:TRNLUInt32;const aData:TRNLPointer);

      public

       constructor Create(const aChannel:TRNLPeerReliableUnorderedChannel;const aMessageNumber,aMessageLength:TRNLUInt32); reintroduce;

       destructor Destroy; override;

     end;

     TRNLPeerReliableUnorderedChannel=class(TRNLPeerReliableChannel)
      private

       fIncomingLongMessages:TRNLPeerReliableUnorderedChannelLongMessageListNode;

       fOutgoingMessageBlockPacketSequenceNumber:TRNLSequenceNumber;

       fOutgoingMessageNumber:TRNLSequenceNumber;

       procedure DispatchOutgoingMessageBlockPackets; override;

       procedure DispatchIncomingMessageBlockPacket(const aBlockPacket:TRNLPeerBlockPacket); override;

      public

       constructor Create(const aPeer:TRNLPeer;const aChannelNumber:TRNLUInt16); override;

       destructor Destroy; override;

     end;

     PRNLPeerUnreliableOrderedChannelCommandType=^TRNLPeerUnreliableOrderedChannelCommandType;
     TRNLPeerUnreliableOrderedChannelCommandType=
      (
       RNL_PEER_UNRELIABLE_ORDERED_CHANNEL_COMMAND_TYPE_SHORT_MESSAGE=0,
       RNL_PEER_UNRELIABLE_ORDERED_CHANNEL_COMMAND_TYPE_LONG_MESSAGE=1
      );

     PRNLPeerUnreliableOrderedChannelShortMessagePacketHeader=^TRNLPeerUnreliableOrderedChannelShortMessagePacketHeader;
     TRNLPeerUnreliableOrderedChannelShortMessagePacketHeader=packed record
      SequenceNumber:TRNLUInt16;
     end;

     PRNLPeerUnreliableOrderedChannelLongMessagePacketHeader=^TRNLPeerUnreliableOrderedChannelLongMessagePacketHeader;
     TRNLPeerUnreliableOrderedChannelLongMessagePacketHeader=packed record
      SequenceNumber:TRNLUInt16;
      MessageNumber:TRNLUInt16;
      Offset:TRNLUInt32;
      Length:TRNLUInt32;
     end;

     TRNLPeerUnreliableOrderedChannel=class(TRNLPeerChannel)
      private

       fIncomingSequenceNumber:TRNLSequenceNumber;

       fIncomingMessageNumber:TRNLSequenceNumber;

       fIncomingMessageLength:TRNLUInt32;

       fIncomingReceivedMessageDataLength:TRNLUInt32;

       fIncomingMessageReceiveBufferData:TRNLPointer;

       fOutgoingSequenceNumber:TRNLSequenceNumber;

       fOutgoingMessageNumber:TRNLSequenceNumber;

       function GetMaximumUnfragmentedMessageSize:TRNLSizeUInt; override;

       procedure DispatchOutgoingBlockPackets; override;

       procedure DispatchIncomingBlockPacket(const aBlockPacket:TRNLPeerBlockPacket); override;

      public

       constructor Create(const aPeer:TRNLPeer;const aChannelNumber:TRNLUInt16); override;

       destructor Destroy; override;

     end;

     PRNLPeerUnreliableUnorderedChannelCommandType=^TRNLPeerUnreliableUnorderedChannelCommandType;
     TRNLPeerUnreliableUnorderedChannelCommandType=
      (
       RNL_PEER_UNRELIABLE_UNORDERED_CHANNEL_COMMAND_TYPE_SHORT_MESSAGE=0,
       RNL_PEER_UNRELIABLE_UNORDERED_CHANNEL_COMMAND_TYPE_LONG_MESSAGE=1
      );

     PRNLPeerUnreliableUnorderedChannelShortMessagePacketHeader=^TRNLPeerUnreliableUnorderedChannelShortMessagePacketHeader;
     TRNLPeerUnreliableUnorderedChannelShortMessagePacketHeader=packed record
     end;

     PRNLPeerUnreliableUnorderedChannelLongMessagePacketHeader=^TRNLPeerUnreliableUnorderedChannelLongMessagePacketHeader;
     TRNLPeerUnreliableUnorderedChannelLongMessagePacketHeader=packed record
      MessageNumber:TRNLUInt16;
      Offset:TRNLUInt32;
      Length:TRNLUInt32;
     end;

     TRNLPeerUnreliableUnorderedChannel=class(TRNLPeerChannel)
      private

       fIncomingMessageNumber:TRNLSequenceNumber;

       fIncomingMessageLength:TRNLUInt32;

       fIncomingReceivedMessageDataLength:TRNLUInt32;

       fIncomingMessageReceiveBufferData:TRNLPointer;

       fIncomingMessageReceiveBufferFlagData:TRNLPointer;

       fOutgoingMessageNumber:TRNLSequenceNumber;

       function GetMaximumUnfragmentedMessageSize:TRNLSizeUInt; override;

       procedure DispatchOutgoingBlockPackets; override;

       procedure DispatchIncomingBlockPacket(const aBlockPacket:TRNLPeerBlockPacket); override;

      public

       constructor Create(const aPeer:TRNLPeer;const aChannelNumber:TRNLUInt16); override;

       destructor Destroy; override;

     end;

     TRNLPeerChannelList=TRNLObjectList<TRNLPeerChannel>;

     PRNLPeerKeepAliveTimes=^TRNLPeerKeepAliveTimes;
     TRNLPeerKeepAliveTimes=array[0..RNL_PEER_KEEP_ALIVE_TIME_HISTORY_SIZE-1] of TRNLTime;

     TRNLPeerIncomingPacketQueue=TRNLQueue<TBytes>;

     TRNLPeer=class
      private

       fHost:TRNLHost;

       fCurrentThreadIndex:TRNLInt32;

       fLocalPeerID:TRNLID;

       fRemotePeerID:TRNLID;

       fPeerListIndex:TRNLSizeInt;

       fChannels:TRNLPeerChannelList;

       fAddress:TRNLAddress;
       fPointerToAddress:PRNLAddress;

       fRemoteHostSalt:TRNLUInt64;

       fRemoteMTU:TRNLUInt32;

       fMTU:TRNLSizeUInt;

       fState:TRNLPeerState;

       fRemoteIncomingBandwidthLimit:TRNLUInt32;

       fRemoteOutgoingBandwidthLimit:TRNLUInt32;

       fIncomingPacketQueue:TRNLPeerIncomingPacketQueue;

       fOutgoingEncryptedPacketSequenceNumber:TRNLUInt64;
       fIncomingEncryptedPacketSequenceNumber:TRNLUInt64;
       fIncomingEncryptedPacketSequenceBuffer:TRNLPeerIncomingEncryptedPacketSequenceBuffer;

       fLocalSalt:TRNLUInt64;

       fRemoteSalt:TRNLUInt64;

       fCountChannels:TRNLUInt32;

       fDisconnectData:TRNLUInt64;

       fConnectionData:TRNLUInt64;

       fConnectionSalt:TRNLUInt64;

       fConnectionNonce:TRNLUInt64;

       fChecksumPlaceHolder:TRNLUInt32;

       fLocalShortTermPublicKey:TRNLKey;

       fLocalShortTermPrivateKey:TRNLKey;

       fSharedSecretKey:TRNLKey;

       fConnectionChallengeResponse:PRNLConnectionChallenge;

       fUnacknowlegmentedBlockPackets:TRNLUInt32;

       fRoundTripTime:TRNLInt64;

       fRoundTripTimeVariance:TRNLInt64;

       fRetransmissionTimeOut:TRNLInt64;

       fPacketLoss:TRNLInt64;

       fPacketLossVariance:TRNLInt64;

       fCountPacketLoss:TRNLUInt32;

       fCountSentPackets:TRNLUInt32;

       fLastPacketLossUpdateTime:TRNLTime;

       fLastSentDataTime:TRNLTime;

       fLastReceivedDataTime:TRNLTime;

       fLastPingSentTime:TRNLTime;

       fNextPingSendTime:TRNLTime;

       fOutgoingPingSequenceNumber:TRNLUInt8;

       fKeepAlivePingTimes:TRNLPeerKeepAliveTimes;

       fKeepAlivePongTimes:TRNLPeerKeepAliveTimes;

       fNextCheckTimeoutsTimeout:TRNLTime;

       fNextReliableBlockPacketTimeout:TRNLTime;

       fNextPendingConnectionSendTimeout:TRNLTime;
       fNextPendingDisconnectionSendTimeout:TRNLTime;

       fDisconnectionTimeout:TRNLTime;

       fDisconnectionSequenceNumber:TRNLUInt16;

       fPendingConnectionHandshakeSendData:TRNLPeerPendingConnectionHandshakeSendData;

       fConnectionToken:PRNLConnectionToken;

       fAuthenticationToken:PRNLAuthenticationToken;

       fIncomingBlockPackets:TRNLPeerBlockPacketQueue;

       fOutgoingBlockPackets:TRNLPeerBlockPacketQueue;

       fOutgoingMTUProbeBlockPackets:TRNLPeerBlockPacketQueue;

       fDeferredOutgoingBlockPackets:TRNLPeerBlockPacketQueue;

       fMTUProbeIndex:TRNLInt32;

       fMTUProbeSequenceNumber:TRNLSequenceNumber;

       fMTUProbeTryIterationsPerMTUProbeSize:TRNLUInt32;

       fMTUProbeRemainingTryIterations:TRNLUInt32;

       fMTUProbeInterval:TRNLUInt64;

       fMTUProbeNextTimeout:TRNLTime;

       fSendNewHostBandwidthLimits:boolean;

       fReceivedNewHostBandwidthLimitsSequenceNumber:TRNLUInt8;

       fSendNewHostBandwidthLimitsSequenceNumber:TRNLUInt8;

       fSendNewHostBandwidthLimitsInterval:TRNLUInt64;

       fSendNewHostBandwidthLimitsNextTimeout:TRNLTime;

       fIncomingBandwidthRateTracker:TRNLBandwidthRateTracker;

       fOutgoingBandwidthRateTracker:TRNLBandwidthRateTracker;

       fOutgoingBandwidthRateLimiter:TRNLBandwidthRateLimiter;

       procedure UpdateOutgoingBandwidthRateLimiter;

       function GetIncomingBandwidthRate:TRNLUInt32;

       function GetOutgoingBandwidthRate:TRNLUInt32;

       function GetCountChannels:TRNLSizeInt; inline;

       procedure SetCountChannels(aCountChannels:TRNLSizeInt);

       procedure UpdateRoundTripTime(const aRoundTripTime:TRNLInt64);

       function SendPacket(const aData;const aDataLength:TRNLSizeUInt):TRNLNetworkSendResult;

       function SendBuffers(const aBuffers:array of TRNLBuffer):TRNLNetworkSendResult;

       procedure UpdatePatchLossStatistics;

       procedure DispatchIncomingMTUProbeBlockPacket(const aIncomingBlockPacket:TRNLPeerBlockPacket);

       procedure DispatchIncomingBlockPackets;

       procedure DispatchPacketTimeOuts;

       procedure DispatchStateActions;

       procedure DispatchIncomingChannelMessages;

       procedure DispatchOutgoingChannelPackets;

       function DispatchOutgoingMTUProbeBlockPackets(var aOutgoingPacketBuffer:TRNLOutgoingPacketBuffer):boolean;

       function DispatchOutgoingBlockPackets(var aOutgoingPacketBuffer:TRNLOutgoingPacketBuffer):boolean;

       procedure DispatchNewHostBandwidthLimits;

       procedure DispatchMTUProbe;

       procedure DispatchKeepAlive(var aOutgoingPacketBuffer:TRNLOutgoingPacketBuffer;const aCanDoPingIfNeeded:boolean);

       procedure DispatchIncomingPacket(const aPayloadData;const aPayloadDataLength:TRNLSizeUInt;const aSentTime:TRNLUInt64);

       procedure DispatchIncomingPackets;

       function DispatchOutgoingPackets:boolean;

       function DispatchPeer:boolean;

       procedure SendNewHostBandwidthLimits;

      public
       constructor Create(const aHost:TRNLHost); reintroduce;
       destructor Destroy; override;
       procedure Disconnect(const aData:TRNLUInt64=0;const aDelayed:boolean=false);
       procedure MTUProbe(const aTryIterationsPerMTUProbeSize:TRNLUInt32=5;const aMTUProbeInterval:TRNLUInt64=100);
      public
       property Address:PRNLAddress read fPointerToAddress;
      published
       property LocalPeerID:TRNLID read fLocalPeerID;
       property RemotePeerID:TRNLID read fRemotePeerID;
       property Host:TRNLHost read fHost;
       property RemoteHostSalt:TRNLUInt64 read fRemoteHostSalt write fRemoteHostSalt;
       property Channels:TRNLPeerChannelList read fChannels;
       property CountChannels:TRNLSizeInt read GetCountChannels write SetCountChannels;
       property RemoteIncomingBandwidthLimit:TRNLUInt32 read fRemoteIncomingBandwidthLimit;
       property RemoteOutgoingBandwidthLimit:TRNLUInt32 read fRemoteOutgoingBandwidthLimit;
       property IncomingBandwidthRate:TRNLUInt32 read GetIncomingBandwidthRate;
       property OutgoingBandwidthRate:TRNLUInt32 read GetOutgoingBandwidthRate;
     end;

     TRNLHost=class
      private
       const HostSocketFamilies:array[0..1] of TRNLInt32=
              (
                RNL_IPV4,
                RNL_IPV6
              );
      private

       fInstance:TRNLInstance;

       fNetwork:TRNLNetwork;

       fRandomGenerator:TRNLRandomGenerator;

       fCompressor:TRNLCompressor;

       fPeerIDManager:TRNLIDManager;

       fPeerIDMap:TRNLHostPeerIDMap;

       fPeerList:TRNLHostPeerList;

       fCountPeers:TRNLUInt32;

       fEventQueue:TRNLHostEventQueue;

       fAddress:TRNLAddress;

       fPointerToAddress:PRNLAddress;

       fAllowIncomingConnections:boolean;

       fChannelTypes:TRNLPeerChannelTypes;

       fMaximumCountPeers:TRNLUInt32;

       fMaximumCountChannels:TRNLUInt32;

       fIncomingBandwidthLimit:TRNLUInt32;

       fOutgoingBandwidthLimit:TRNLUInt32;

       fReliableChannelBlockPacketWindowSize:TRNLUInt32;

       fReliableChannelBlockPacketWindowMask:TRNLUInt32;

       fMaximumMessageSize:TRNLSizeUInt;

       fReceiveBufferSize:TRNLUInt32;

       fSendBufferSize:TRNLUInt32;

       fMTU:TRNLSizeUInt;

       fMTUDoFragment:boolean;

       fEncryptedPacketSequenceWindowSize:TRNLUInt32;

       fEncryptedPacketSequenceWindowMask:TRNLUInt32;

       fProtocolID:TRNLUInt64;

       fSalt:TRNLUInt64;

       fLongTermPrivateKey:TRNLKey;

       fLongTermPublicKey:TRNLKey;

       fConnectionTimeout:TRNLTime;

       fPingInterval:TRNLTime;

       fPendingConnectionTimeout:TRNLUInt64;

       fPendingConnectionSendTimeout:TRNLUInt64;

       fPendingDisconnectionTimeout:TRNLUInt64;

       fPendingDisconnectionSendTimeout:TRNLUInt64;

       fPendingSendNewBandwidthLimitsSendTimeout:TRNLUInt64;

       fRateLimiterHostAddressBurst:TRNLInt64;

       fRateLimiterHostAddressPeriod:TRNLUInt64;

       fOnCheckConnectionToken:TRNLHostOnCheckConnectionToken;

       fOnCheckAuthenticationToken:TRNLHostOnCheckAuthenticationToken;

       fSockets:TRNLHostSockets;

       fTime:TRNLTime;

       fNextPeerEventTime:TRNLTime;

       fReceiveBuffer:TRNLPacketBuffer;

       fReceivedBufferLength:TRNLInt32;

       fReceivedAddress:TRNLAddress;

       fTotalReceivedData:TRNLUInt64;

       fTotalReceivedPackets:TRNLUInt64;

       fConnectionChallengeDifficultyLevel:TRNLUInt32;

       fConnectionAttemptsPerSecondChallengeDifficultyFactor:TRNLUInt32;

       fConnectionCandidateHashTable:PRNLConnectionCandidateHashTable;

       fConnectionKnownCandidateHostAddressHashTable:PRNLConnectionKnownCandidateHostAddressHashTable;

       fConnectionAttemptDeltaTime:TRNLTime;
       fConnectionAttemptLastTime:TRNLTime;
       fConnectionAttemptHasLastTime:boolean;

       fConnectionAttemptHistoryDeltaTimes:array[0..RNL_CONNECTION_ATTEMPT_SIZE-1] of TRNLUInt64;
       fConnectionAttemptHistoryTimePoints:array[0..RNL_CONNECTION_ATTEMPT_SIZE-1] of TRNLTIme;

       fConnectionAttemptHistoryReadIndex:TRNLUInt32;
       fConnectionAttemptHistoryWriteIndex:TRNLUInt32;

       fConnectionAttemptsPerSecond:TRNLUInt32;

       fIncomingBandwidthRateTracker:TRNLBandwidthRateTracker;

       fOutgoingBandwidthRateTracker:TRNLBandwidthRateTracker;

       fOutgoingBandwidthRateLimiter:TRNLBandwidthRateLimiter;

       fCompressionBuffer:TRNLPacketBuffer;

       fOutgoingPacketBuffer:TRNLOutgoingPacketBuffer;

       procedure SetReliableChannelBlockPacketWindowSize(const aReliableChannelBlockPacketWindowSize:TRNLUInt32);

       procedure BroadcastNewBandwidthLimits;

       procedure SetIncomingBandwidthLimit(const aIncomingBandwidthLimit:TRNLUInt32);

       procedure SetOutgoingBandwidthLimit(const aOutgoingBandwidthLimit:TRNLUInt32);

       function GetIncomingBandwidthRate:TRNLUInt32;

       function GetOutgoingBandwidthRate:TRNLUInt32;

       function GetChannelType(const aIndex:TRNLUInt32):TRNLPeerChannelType;

       procedure SetChannelType(const aIndex:TRNLUInt32;const aChannelType:TRNLPeerChannelType);

       procedure SetMaximumCountChannels(const aMaximumCountChannels:TRNLUInt32);

       procedure SetMTU(const aMTU:TRNLSizeUInt);

       procedure SetConnectionTimeout(const aConnectionTimeout:TRNLTime);

       procedure SetPingInterval(const aPingInterval:TRNLTime);

       procedure SetEncryptedPacketSequenceWindowSize(const aEncryptedPacketSequenceWindowSize:TRNLUInt32);

       function SendPacket(const aAddress:TRNLAddress;const aData;const aDataLength:TRNLSizeUInt):TRNLNetworkSendResult;

       function SendBuffers(const aAddress:TRNLAddress;const aBuffers:array of TRNLBuffer):TRNLNetworkSendResult;

       procedure ResetConnectionAttemptHistory;

       procedure UpdateConnectionAttemptHistory(const aTime:TRNLTime);

       procedure AddHandshakePacketChecksum(var aHandshakePacket);

       function VerifyHandshakePacketChecksum(var aHandshakePacket):boolean;

       procedure DispatchReceivedHandshakePacketConnectionRequest(const aIncomingPacket:PRNLProtocolHandshakePacketConnectionRequest);

       procedure DispatchReceivedHandshakePacketConnectionChallengeRequest(const aIncomingPacket:PRNLProtocolHandshakePacketConnectionChallengeRequest);

       procedure DispatchReceivedHandshakePacketConnectionChallengeResponse(const aIncomingPacket:PRNLProtocolHandshakePacketConnectionChallengeResponse);

       procedure DispatchReceivedHandshakePacketConnectionAuthenticationRequest(const aIncomingPacket:PRNLProtocolHandshakePacketConnectionAuthenticationRequest);

       procedure DispatchReceivedHandshakePacketConnectionAuthenticationResponse(const aIncomingPacket:PRNLProtocolHandshakePacketConnectionAuthenticationResponse);

       procedure DispatchReceivedHandshakePacketConnectionApprovalResponse(const aIncomingPacket:PRNLProtocolHandshakePacketConnectionApprovalResponse);

       procedure DispatchReceivedHandshakePacketConnectionDenialResponse(const aIncomingPacket:PRNLProtocolHandshakePacketConnectionDenialResponse);

       procedure DispatchReceivedHandshakePacketConnectionApprovalAcknowledge(const aIncomingPacket:PRNLProtocolHandshakePacketConnectionApprovalAcknowledge);

       procedure DispatchReceivedHandshakePacketData(var aPacketData;const aPacketDataLength:TRNLSizeUInt);

       procedure DispatchReceivedNormalPacketData(var aPacketData;const aPacketDataLength:TRNLSizeUInt);

       procedure DispatchReceivedPacketData(var aPacketData;const aPacketDataLength:TRNLSizeUInt);

       function DispatchPeers(var aNextTimeout:TRNLTime):boolean;

       function ReceivePackets(const aTimeout:TRNLTime):boolean;

      public
       constructor Create(const aInstance:TRNLInstance;const aNetwork:TRNLNetwork); reintroduce;
       destructor Destroy; override;
       procedure Start;
       function Connect(const aAddress:TRNLAddress;
                        const aCountChannels:TRNLUInt32=1;
                        const aData:TRNLUInt64=0;
                        const aConnectionToken:PRNLConnectionToken=nil;
                        const aAuthenticationToken:PRNLAuthenticationToken=nil):TRNLPeer;
       procedure BroadcastMessage(const aChannel:TRNLUInt8;const aMessage:TRNLMessage);
       procedure BroadcastMessageData(const aChannel:TRNLUInt8;const aData:TRNLPointer;const aDataLength:TRNLUInt32;const aFlags:TRNLMessageFlags=[]);
       procedure BroadcastMessageString(const aChannel:TRNLUInt8;const aString:TRNLRawByteString;const aFlags:TRNLMessageFlags=[]);
       procedure BroadcastMessageStream(const aChannel:TRNLUInt8;const aStream:TStream;const aFlags:TRNLMessageFlags=[]);
       procedure FreeEvent(var aEvent:TRNLHostEvent);
       function Service(const aEvent:PRNLHostEvent=nil;
                        const aTimeout:TRNLInt64=1000):TRNLHostServiceStatus;
       function CheckEvents(var aEvent:TRNLHostEvent):boolean;
       function Flush:boolean;
      public
       property Address:PRNLAddress read fPointerToAddress;
       property ProtocolID:TRNLUInt64 read fProtocolID write fProtocolID;
       property ChannelTypes[const aIndex:TRNLUInt32]:TRNLPeerChannelType read GetChannelType write SetChannelType;
       property LongTermPrivateKey:TRNLKey read fLongTermPrivateKey write fLongTermPrivateKey;
       property LongTermPublicKey:TRNLKey read fLongTermPublicKey write fLongTermPublicKey;
       property ConnectionTimeout:TRNLTime read fConnectionTimeout write SetConnectionTimeout;
       property PingInterval:TRNLTime read fPingInterval write SetPingInterval;
       property PendingConnectionTimeout:TRNLUInt64 read fPendingConnectionTimeout write fPendingConnectionTimeout;
       property PendingConnectionSendTimeout:TRNLUInt64 read fPendingConnectionSendTimeout write fPendingConnectionSendTimeout;
       property PendingDisconnectionTimeout:TRNLUInt64 read fPendingDisconnectionTimeout write fPendingDisconnectionTimeout;
       property PendingDisconnectionSendTimeout:TRNLUInt64 read fPendingDisconnectionSendTimeout write fPendingDisconnectionSendTimeout;
       property PendingSendNewBandwidthLimitsSendTimeout:TRNLUInt64 read fPendingSendNewBandwidthLimitsSendTimeout write fPendingSendNewBandwidthLimitsSendTimeout;
       property RateLimiterHostAddressBurst:TRNLInt64 read fRateLimiterHostAddressBurst write fRateLimiterHostAddressBurst;
       property RateLimiterHostAddressPeriod:TRNLUInt64 read fRateLimiterHostAddressPeriod write fRateLimiterHostAddressPeriod;
      published
       property Instance:TRNLInstance read fInstance;
       property Network:TRNLNetwork read fNetwork;
       property Compressor:TRNLCompressor read fCompressor write fCompressor;
       property AllowIncomingConnections:boolean read fAllowIncomingConnections write fAllowIncomingConnections;
       property MaximumCountPeers:TRNLUInt32 read fMaximumCountPeers write fMaximumCountPeers;
       property MaximumCountChannels:TRNLUInt32 read fMaximumCountChannels write SetMaximumCountChannels;
       property IncomingBandwidthLimit:TRNLUInt32 read fIncomingBandwidthLimit write SetIncomingBandwidthLimit;
       property OutgoingBandwidthLimit:TRNLUInt32 read fOutgoingBandwidthLimit write SetOutgoingBandwidthLimit;
       property IncomingBandwidthRate:TRNLUInt32 read GetIncomingBandwidthRate;
       property OutgoingBandwidthRate:TRNLUInt32 read GetOutgoingBandwidthRate;
       property ReliableChannelBlockPacketWindowSize:TRNLUInt32 read fReliableChannelBlockPacketWindowSize write SetReliableChannelBlockPacketWindowSize;
       property EncryptedPacketSequenceWindowSize:TRNLUInt32 read fEncryptedPacketSequenceWindowSize write SetEncryptedPacketSequenceWindowSize;
       property ReceiveBufferSize:TRNLUInt32 read fReceiveBufferSize write fReceiveBufferSize;
       property SendBufferSize:TRNLUInt32 read fSendBufferSize write fSendBufferSize;
       property MTU:TRNLSizeUInt read fMTU write SetMTU;
       property MTUDoFragment:boolean read fMTUDoFragment write fMTUDoFragment;
       property OnCheckConnectionToken:TRNLHostOnCheckConnectionToken read fOnCheckConnectionToken write fOnCheckConnectionToken;
       property OnCheckAuthenticationToken:TRNLHostOnCheckAuthenticationToken read fOnCheckAuthenticationToken write fOnCheckAuthenticationToken;
     end;

const RNL_HOST_ANY_INIT:TRNLHostAddress=(Addr:(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0));
      RNL_HOST_ANY:TRNLHostAddress=(Addr:(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0));
      RNL_HOST_IPV4_LOCALHOST:TRNLHostAddress=(Addr:(0,0,0,0,0,0,0,0,0,0,255,255,127,0,0,1));
      RNL_IPV4MAPPED_PREFIX_INIT:TRNLHostAddress=(Addr:(0,0,0,0,0,0,0,0,0,0,255,255,0,0,0,0));
      RNL_IPV4MAPPED_PREFIX:TRNLHostAddress=(Addr:(0,0,0,0,0,0,0,0,0,0,255,255,0,0,0,0));
      RNL_HOST_BROADCAST_INIT:TRNLHostAddress=(Addr:(0,0,0,0,0,0,0,0,0,0,255,255,255,255,255,255));
      RNL_HOST_BROADCAST_:TRNLHostAddress=(Addr:(0,0,0,0,0,0,0,0,0,0,255,255,255,255,255,255));

{$ifdef Unix}
      RNL_INVALID_SOCKET=-1;
{$else}
      RNL_INVALID_SOCKET=TRNLSocket(not(0));
{$endif}

      RNL_SOCKET_NULL={$ifdef Unix}-1{$else}RNL_INVALID_SOCKET{$endif};

{$ifndef fpc}
function BSRDWord(Value:TRNLUInt32):TRNLUInt32; {$if defined(CPU386) or defined(CPUX64)}assembler; register;{$ifend}
function SARLongint(Value,Shift:TRNLInt32):TRNLInt32;
function SARInt64(Value:TRNLInt64;Shift:TRNLInt32):TRNLInt64;
{$endif}

implementation

const RNLProtocolHandshakePacketHeaderSignature:TRNLProtocolHandshakePacketHeaderSignature=
       (TRNLUInt8(ord('R')),
        TRNLUInt8(ord('N')),
        TRNLUInt8(ord('L')),
        $ff
       );

      RNLProtocolHandshakePacketSizes:array[TRNLProtocolHandshakePacketType] of TRNLSizeUInt=
       (
        SizeOf(TRNLProtocolHandshakePacketHeader),
        SizeOf(TRNLProtocolHandshakePacketConnectionRequest),
        SizeOf(TRNLProtocolHandshakePacketConnectionChallengeRequest),
        SizeOf(TRNLProtocolHandshakePacketConnectionChallengeResponse),
        SizeOf(TRNLProtocolHandshakePacketConnectionAuthenticationRequest),
        SizeOf(TRNLProtocolHandshakePacketConnectionAuthenticationResponse),
        SizeOf(TRNLProtocolHandshakePacketConnectionApprovalResponse),
        SizeOf(TRNLProtocolHandshakePacketConnectionDenialResponse),
        SizeOf(TRNLProtocolHandshakePacketConnectionApprovalAcknowledge),
        SizeOf(TRNLProtocolHandshakePacketConnectionDenialAcknowledge)
       );

      RNLProtocolBlockPacketSizes:array[TRNLProtocolBlockPacketType] of TRNLSizeUInt=
       (
        SizeOf(TRNLProtocolBlockPacketHeader),
        SizeOf(TRNLProtocolBlockPacketPing),
        SizeOf(TRNLProtocolBlockPacketPong),
        SizeOf(TRNLProtocolBlockPacketDisconnect),
        SizeOf(TRNLProtocolBlockPacketDisconnectAcknowledgement),
        SizeOf(TRNLProtocolBlockPacketBandwidthLimits),
        SizeOf(TRNLProtocolBlockPacketBandwidthLimitsAcknowledgement),
        SizeOf(TRNLProtocolBlockPacketMTUProbe),
        SizeOf(TRNLProtocolBlockPacketChannel)
       );

      RNLNormalPacketPeerStates=
       [
        RNL_PEER_STATE_CONNECTED,
        RNL_PEER_STATE_DISCONNECT_LATER,
        RNL_PEER_STATE_DISCONNECTING,
        RNL_PEER_STATE_DISCONNECTION_ACKNOWLEDGING,
        RNL_PEER_STATE_DISCONNECTION_PENDING
       ];

      RNLKnownCommonMTUSizes:array[0..19] of TRNLUInt16=
       (
        576,  // Internet Path MTU for X.25 (RFC 879)
        1024, // 1/64 of maximum
        1280, // IPv6 path MTU
        1452, // DS-Lite over PPPoE, Ethernet v2 MTU (1500) - PPPoE header (8) - IPv6 header (40)
        1492, // Ethernet with LLC and SNAP, PPPoE (RFC 1042)
        1493, // Minimum Ethernet Jumbo Frame MTU (1501 - 9198) - PPPoE header (8)
        1500, // Ethernet II (RFC 1191)
        1501, // Minimum Ethernet Jumbo Frame MTU (1501 - 9198)
        2048, // 1/32 of maximum
        2304, // WLAN (802.11), the maximum MSDU size is 2304 before encryption. WEP will add 8 bytes, WPA-TKIP 20 bytes, and WPA2-CCMP 16 bytes.
        4096, // 1/16 of maximum
        4352, // FDDI
        4464, // Token ring
        7981, // WLAN
        8192, // 1/8 of maximum
        9190, // Maximum Ethernet Jumbo Frame MTU (1501 - 9198) - PPPoE header (8)
        9198, // Maximum Ethernet Jumbo Frame MTU (1501 - 9198)
        16384, // 1/4 of maximum
        32768, // Half maximum
        65535 // Maximum minus one (minus one because 0..65535 range of the 16-bit unsigned integer data fields here)
       );

      OneDiv32Bit=1.0/TRNLInt64($100000000);

{$ifndef BIG_ENDIAN}
      MultiplyDeBruijnBytePosition:array[0..31] of TRNLUInt8=(0,0,3,0,3,1,3,0,
                                                              3,2,2,1,3,2,0,1,
                                                              3,3,1,2,2,2,2,0,
                                                              3,1,2,0,1,0,1,1);
{$endif}

class function TRNLMath.RoundUpToPowerOfTwo32(Value:TRNLUInt32):TRNLUInt32;
begin
 dec(Value);
 Value:=Value or (Value shr 1);
 Value:=Value or (Value shr 2);
 Value:=Value or (Value shr 4);
 Value:=Value or (Value shr 8);
 Value:=Value or (Value shr 16);
 result:=Value+1;
end;

class function TRNLMath.RoundUpToPowerOfTwo64(Value:TRNLUInt64):TRNLUInt64;
begin
 dec(Value);
 Value:=Value or (Value shr 1);
 Value:=Value or (Value shr 2);
 Value:=Value or (Value shr 4);
 Value:=Value or (Value shr 8);
 Value:=Value or (Value shr 16);
 Value:=Value or (Value shr 32);
 result:=Value+1;
end;

class function TRNLMath.RoundUpToPowerOfTwo(Value:TRNLPtrUInt):TRNLPtrUInt;
begin
 dec(Value);
 Value:=Value or (Value shr 1);
 Value:=Value or (Value shr 2);
 Value:=Value or (Value shr 4);
 Value:=Value or (Value shr 8);
 Value:=Value or (Value shr 16);
{$ifdef CPU64}
 Value:=Value or (Value shr 32);
{$endif}
 result:=Value+1;
end;

{$ifndef fpc}

function BSRDWord(Value:TRNLUInt32):TRNLUInt32;{$if defined(CPU386)}assembler; register;
asm
 bsr eax,eax
 jnz @Done
 mov eax,255
@Done:
end;
{$elseif defined(CPUX64)}assembler; register; {$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .NOFRAME
{$endif}
{$ifdef Windows}
 bsr eax,ecx
{$else}
 bsr eax,edi
{$endif}
 jnz @Done
 mov eax,255
@Done:
end;
{$else}
const BSRDebruijn32Multiplicator=TRNLUInt32($07c4acdd);
      BSRDebruijn32Shift=27;
      BSRDebruijn32Mask=31;
      BSRDebruijn32Table:array[0..31] of TRNLInt32=(0,9,1,10,13,21,2,29,11,14,16,18,22,25,3,30,8,12,20,28,15,17,24,7,19,27,23,6,26,5,4,31);
begin
 if Value=0 then begin
  Value:=255;
 end else begin
  Value:=Value or (Value shr 1);
  Value:=Value or (Value shr 2);
  Value:=Value or (Value shr 4);
  Value:=Value or (Value shr 8);
  Value:=Value or (Value shr 16);
  result:=BSRDebruijn32Table[((Value*BSRDebruijn32Multiplicator) shr BSRDebruijn32Shift) and BSRDebruijn32Mask];
 end;
end;
{$ifend}

function SARLongint(Value,Shift:TRNLInt32):TRNLInt32;
{$if defined(CPU386)}assembler; register;
asm
 mov ecx,edx
 sar eax,cl
end;
{$elseif defined(CPUX64)}assembler; register; {$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .noframe
{$endif}
{$ifdef Win64}
 // Win64 ABI: rcx, rdx, r8, r9, rest on stack (scratch registers: rax, rcx, rdx, r8, r9, r10, r11)
 mov eax,ecx
 mov ecx,edx
{$else}
 // SystemV ABI: rdi, rsi, rdx, rcx, r8, r9, rest on stack (scratch registers: rax, rdi, rsi, rdx, rcx, r8, r9, r10, r11)
 mov eax,edi
 mov ecx,esi
{$endif}
 sar eax,cl
end;
{$elseif defined(CPUARM) and defined(fpc)}assembler; register;
asm
 mov r0,r0,asr R1
end {$ifdef fpc}['r0','R1']{$endif};
{$else}
begin
 Shift:=Shift and 31;
 result:=(TRNLUInt32(Value) shr Shift) or (TRNLUInt32(TRNLInt32(TRNLUInt32(-TRNLUInt32(TRNLUInt32(Value) shr 31)) and TRNLUInt32(-TRNLUInt32(ord(Shift<>0) and 1)))) shl (32-Shift));
end;
{$ifend}

function SARInt64(Value:TRNLInt64;Shift:TRNLInt32):TRNLInt64;
{$if defined(CPU386)}assembler; register;
asm
 mov ecx,eax
 and cl,63
 cmp cl,32
 jc @Full
  mov eax,dword ptr [Value+4]
  sar eax,cl
  bt eax,31
  sbb edx,eax
  jmp @Done
 @Full:
  mov eax,dword ptr [Value+0]
  mov edx,dword ptr [Value+4]
  shrd eax,edx,cl
  sar edx,cl
@Done:
 mov dword ptr [result+0],eax
 mov dword ptr [result+4],edx
end;
{$elseif defined(CPUX64)}assembler; register; {$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .noframe
{$endif}
{$ifdef Win64}
 // Win64 ABI: rcx, rdx, r8, r9, rest on stack (scratch registers: rax, rcx, rdx, r8, r9, r10, r11)
 mov rax,rcx
 mov rcx,rdx
{$else}
 // SystemV ABI: rdi, rsi, rdx, rcx, r8, r9, rest on stack (scratch registers: rax, rdi, rsi, rdx, rcx, r8, r9, r10, r11)
 mov rax,rdi
 mov rcx,rsi
{$endif}
 sar rax,cl
end;
{$else}
begin
 Shift:=Shift and 63;
 result:=(TRNLInt64(Value) shr Shift) or (TRNLInt64(TRNLInt64(TRNLInt64(-TRNLInt64(TRNLInt64(Value) shr 63)) and TRNLInt64(-TRNLInt64(ord(Shift<>0) and 1)))) shl (63-Shift));
end;
{$ifend}

{$endif}

{$if defined(CPU386) or defined(CPUX64)}
function x86_rdrand_support:boolean; assembler; register;
asm
{$ifdef CPUX64}
 push rbx
{$else}
 push ebx
{$endif}
 xor eax,eax
 cpuid
 cmp ebx,$756e6547
 je @CheckIntel
 cmp ebx,$68747541
 je @CheckAMD
 jmp @NoSupport
@CheckIntel:
 cmp ecx,$6c65746e
 jne @NoSupport
 cmp edx,$49656e69
 jne @NoSupport
 jmp @HasSupport
@CheckAMD:
 cmp ecx,$444d4163
 jne @NoSupport
 cmp edx,$69746e65
 jne @NoSupport
@HasSupport:
 mov eax,1
 cpuid
 mov eax,ecx
 shr eax,30
 and eax,1
 jmp @Done
@NoSupport:
 xor eax,eax
@Done:
{$ifdef CPUX64}
 pop rbx
{$else}
 pop ebx
{$endif}
end;

function x86_rdrand_ui32:TRNLUInt32; assembler; register;
asm
 mov ecx,16
@Loop:
 db $0f,$c7,$f0 // rdrand eax
 jc @Done
 dec ecx
 jnz @Loop
@Done:
end;

function x86_rdrand_ui64:TRNLUInt64; assembler; register;
asm
{$if defined(CPUX64)}
 mov ecx,16
@Loop:
 db $48,$0f,$c7,$f0 // rdrand rax
 jc @Done
 dec ecx
 jnz @Loop
@Done:
{$else}
 call x86_rdrand_ui32
 mov edx,eax
 push edx
 call x86_rdrand_ui32
 pop edx
{$ifend}
end;

function x86_rdseed_support:boolean; assembler; register;
asm
 xor eax,eax
 cpuid
 cmp ebx,$756e6547
 jne @NoSupport
 cmp edx,$49656e69
 jne @NoSupport
 cmp ecx,$6c65746e
 jne @NoSupport
 mov eax,7
 cpuid
 mov eax,ebx
 shr eax,18
 and eax,1
 jmp @Done
@NoSupport:
 xor eax,eax
@Done:
end;

function x86_rdseed_ui32:TRNLUInt32; assembler; register;
asm
 mov ecx,16
@Loop:
 db $0f,$c7,$f8 // rdseed eax
 jc @Done
 dec ecx
 jnz @Loop
@Done:
end;

function x86_rdseed_ui64:TRNLUInt64; assembler; register;
asm
{$if defined(CPUX64)}
 mov ecx,16
@Loop:
 db $48,$0f,$c7,$f8 // rdseed rax
 jc @Done
 dec ecx
 jnz @Loop
@Done:
{$else}
 call x86_rdseed_ui32
 mov edx,eax
 push edx
 call x86_rdseed_ui32
 push eax
{$ifend}
end;
{$ifend}

function PopFirstOneBitUInt32(var Value:TRNLUInt32):TRNLUInt32;{$ifdef cpu386}assembler; register; {$ifdef fpc}nostackframe;{$endif}
asm
 push esi
 mov esi,Value
 xor eax,eax
 bsf ecx,dword ptr [esi]
 jz @Found
 xor eax,ecx
 xor edx,edx
 inc edx
 shl edx,cl
 xor dword ptr [esi],edx
 @Found:
 pop esi
end;
{$else}
{$ifdef cpux64}assembler; register; {$ifdef fpc}nostackframe;{$endif}
asm
{$ifdef win64}
 mov eax,dword ptr [rcx]
{$else}
 mov eax,dword ptr [rdi]
{$endif}
 lea edx,[eax-1]
 bsf eax,eax
{$ifdef win64}
 and dword ptr [rcx],edx
{$else}
 and dword ptr [rdi],edx
{$endif}
end;
{$else}
begin
{$ifdef fpc}
 result:=BSFDWord(Value);
{$else}
 result:=(Value and (-Value))-1;
 result:=result-((result shr 1) and $55555555);
 result:=(result and $33333333)+((result shr 2) and $33333333);
 result:=(result+(result shr 4)) and $0f0f0f0f;
 inc(result,result shr 8);
 inc(result,result shr 16);
 result:=result and $1f;
{$endif}
 Value:=Value and (Value-1);
end;
{$endif}
{$endif}

function BitScanForwardUInt32(Value:TRNLUInt32):TRNLUInt32;{$ifdef cpu386}assembler; register; {$ifdef fpc}nostackframe;{$endif}
asm
 bsf eax,eax
 jnz @NotFound
 mov eax,255
@NotFound:
end;
{$else}
{$ifdef cpux64}assembler; register; {$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .NOFRAME
{$endif}
{$ifdef win64}
 bsf eax,ecx
{$else}
 bsf eax,edi
{$endif}
 jnz @NotFound
 mov eax,255
@NotFound:
end;
{$else}
{$ifndef fpc}
const Debruijn32Multiplicator=TRNLUInt32($077cb531);
      Debruijn32Shift=27;
      Debruijn32Mask=31;
      Debruijn32Table:array[0..31] of TRNLInt32=(0,1,28,2,29,14,24,3,30,22,20,15,25,17,4,8,31,27,13,23,21,19,16,7,26,12,18,6,11,5,10,9);
{$endif}
begin
 if Value=0 then begin
  result:=255;
 end else begin
{$ifdef fpc}
  result:=BsfDWord(Value);
{$else}
  result:=Debruijn32Table[(((Value and not (Value-1))*Debruijn32Multiplicator) shr Debruijn32Shift) and Debruijn32Mask];
{$endif}
 end;
end;
{$endif}
{$endif}

function RawBitScanForwardUInt32(Value:TRNLUInt32):TRNLUInt32;{$ifdef cpu386}assembler; register; {$ifdef fpc}nostackframe;{$endif}
asm
 bsf eax,eax
end;
{$else}
{$ifdef cpux64}assembler; register; {$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .NOFRAME
{$endif}
{$ifdef win64}
 bsf eax,ecx
{$else}
 bsf eax,edi
{$endif}
end;
{$else}
{$ifdef fpc}inline;
begin
 result:=BsfDWord(Value);
end;
{$else}
const Debruijn32Multiplicator=TRNLUInt32($077cb531);
      Debruijn32Shift=27;
      Debruijn32Mask=31;
      Debruijn32Table:array[0..31] of TRNLInt32=(0,1,28,2,29,14,24,3,30,22,20,15,25,17,4,8,31,27,13,23,21,19,16,7,26,12,18,6,11,5,10,9);
begin
  result:=Debruijn32Table[(((Value and not (Value-1))*Debruijn32Multiplicator) shr Debruijn32Shift) and Debruijn32Mask];
 end;
end;
{$endif}
{$endif}
{$endif}

procedure BytewiseMemoryMove(const aSource;var aDestination;const aLength:TRNLSizeUInt);{$if defined(CPU386)} register; assembler; {$ifdef fpc}nostackframe;{$endif}
asm
 push esi
 push edi
 mov esi,eax
 mov edi,edx
 cld
 rep movsb
 pop edi
 pop esi
end;
{$elseif defined(CPUX64)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .noframe
{$endif}
{$ifdef Win64}
 // Win64 ABI: rcx, rdx, r8, r9, rest on stack (scratch registers: rax, rcx, rdx, r8, r9, r10, r11)
 push rdi
 push rsi
 mov rsi,rcx
 mov rdi,rdx
 mov rcx,r8
{$else}
 // SystemV ABI: rdi, rsi, rdx, rcx, r8, r9, rest on stack (scratch registers: rax, rdi, rsi, rdx, rcx, r8, r9, r10, r11)
 xchg rsi,rdi
 mov rcx,rdx
{$endif}
 cld
 rep movsb
{$ifdef win64}
 pop rsi
 pop rdi
{$endif}
end;
{$else}
var Index:TRNLSizeUInt;
    Source,Destination:PRNLUInt8Array;
begin
 if aLength>0 then begin
  Source:=TRNLPointer(@aSource);
  Destination:=TRNLPointer(@aDestination);
  for Index:=0 to aLength-1 do begin
   Destination^[Index]:=Source^[Index];
  end;
 end;
end;
{$ifend}

procedure RLELikeSideEffectAwareMemoryMove(const aSource;var aDestination;const aLength:TRNLSizeUInt);
begin
 if aLength>0 then begin
  if ({%H-}TRNLSizeUInt(TRNLPointer(@aSource))+aLength)<={%H-}TRNLSizeUInt(TRNLPointer(@aDestination)) then begin
   // Non-overlapping, so we an use an optimized memory move function
   Move(aSource,aDestination,aLength);
  end else begin
   // Overlapping, so we must do copy byte-wise for to get the free RLE-like side-effect included
   BytewiseMemoryMove(aSource,aDestination,aLength);
  end;
 end;
end;

class function TRNLEndianness.Swap16(const aValue:TRNLUInt16):TRNLUInt16;
{$if defined(CPU386)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
 xchg al,ah
end;
{$elseif defined(CPUX64)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .noframe
{$endif}
{$ifdef Win64}
 movzx eax,cx
{$else}
 movzx eax,di
{$endif}
 xchg al,ah
end;
{$else}
begin
 result:=(aValue shr 8) or (aValue shl 8);
end;
{$ifend}

class function TRNLEndianness.Swap32(const aValue:TRNLUInt32):TRNLUInt32;
{$if defined(CPU386)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
 bswap eax
end;
{$elseif defined(CPUX64)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .noframe
{$endif}
{$ifdef Win64}
 mov eax,ecx
{$else}
 mov eax,edi
{$endif}
 bswap eax
end;
{$else}
begin
 result:=(aValue shr 24) or
         ((aValue and TRNLUInt32($00ff0000)) shr 8) or
         ((aValue and TRNLUInt32($0000ff00)) shl 8) or
         (aValue shl 24);
end;
{$ifend}

class function TRNLEndianness.Swap64(const aValue:TRNLUInt64):TRNLUInt64;
{$if defined(CPU386)}assembler;
asm
 mov edx,dword ptr [aValue+0]
 mov eax,dword ptr [aValue+4]
 bswap eax
 bswap edx
end;
{$elseif defined(CPUX64)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .noframe
{$endif}
{$ifdef Win64}
 mov rax,rcx
{$else}
 mov rax,rdi
{$endif}
 bswap rax
end;
{$else}
begin
 result:=(aValue shr 32) or (aValue shl 32);
 result:=((result and TRNLUInt64($ffff0000ffff0000)) shr 16) or
         ((result and TRNLUInt64($0000ffff0000ffff)) shl 16);
 result:=((result and TRNLUInt64($ff00ff00ff00ff00)) shr 8) or
         ((result and TRNLUInt64($00ff00ff00ff00ff)) shl 8);
end;
{$ifend}

class function TRNLEndianness.HostToNet16(const aValue:TRNLUInt16):TRNLUInt16;
{$if defined(CPU386)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
 xchg al,ah
end;
{$elseif defined(CPUX64)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .noframe
{$endif}
{$ifdef Win64}
 mov al,ch
 mov ah,cl
{$else}
 mov ax,di
 xchg al,ah
{$endif}
end;
{$elseif defined(BIG_ENDIAN)}
begin
 result:=aValue;
end;
{$else}
begin
 result:=(aValue shr 8) or (aValue shl 8);
end;
{$ifend}

class function TRNLEndianness.HostToNet32(const aValue:TRNLUInt32):TRNLUInt32;
{$if defined(CPU386)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
 bswap eax
end;
{$elseif defined(CPUX64)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .noframe
{$endif}
{$ifdef Win64}
 mov eax,ecx
{$else}
 mov eax,edi
{$endif}
 bswap eax
end;
{$elseif defined(BIG_ENDIAN)}
begin
 result:=aValue;
end;
{$else}
begin
 result:=(aValue shr 24) or
         ((aValue and TRNLUInt32($00ff0000)) shr 8) or
         ((aValue and TRNLUInt32($0000ff00)) shl 8) or
         (aValue shl 24);
end;
{$ifend}

class function TRNLEndianness.HostToNet64(const aValue:TRNLUInt64):TRNLUInt64;
{$if defined(CPU386)}assembler;
asm
 mov edx,dword ptr [aValue+0]
 mov eax,dword ptr [aValue+4]
 bswap eax
 bswap edx
end;
{$elseif defined(CPUX64)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .noframe
{$endif}
{$ifdef Win64}
 mov rax,rcx
{$else}
 mov rax,rdi
{$endif}
 bswap rax
end;
{$elseif defined(BIG_ENDIAN)}
begin
 result:=aValue;
end;
{$else}
begin
 result:=(aValue shr 32) or (aValue shl 32);
 result:=((result and TRNLUInt64($ffff0000ffff0000)) shr 16) or
         ((result and TRNLUInt64($0000ffff0000ffff)) shl 16);
 result:=((result and TRNLUInt64($ff00ff00ff00ff00)) shr 8) or
         ((result and TRNLUInt64($00ff00ff00ff00ff)) shl 8);
end;
{$ifend}

class function TRNLEndianness.NetToHost16(const aValue:TRNLUInt16):TRNLUInt16;
{$if defined(CPU386)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
 xchg al,ah
end;
{$elseif defined(CPUX64)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .noframe
{$endif}
{$ifdef Win64}
 mov al,ch
 mov ah,cl
{$else}
 mov ax,di
 xchg al,ah
{$endif}
end;
{$elseif defined(BIG_ENDIAN)}
begin
 result:=aValue;
end;
{$else}
begin
 result:=(aValue shr 8) or (aValue shl 8);
end;
{$ifend}

class function TRNLEndianness.NetToHost32(const aValue:TRNLUInt32):TRNLUInt32;
{$if defined(CPU386)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
 bswap eax
end;
{$elseif defined(CPUX64)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .noframe
{$endif}
{$ifdef Win64}
 mov eax,ecx
{$else}
 mov eax,edi
{$endif}
 bswap eax
end;
{$elseif defined(BIG_ENDIAN)}
begin
 result:=aValue;
end;
{$else}
begin
 result:=(aValue shr 24) or
         ((aValue and TRNLUInt32($00ff0000)) shr 8) or
         ((aValue and TRNLUInt32($0000ff00)) shl 8) or
         (aValue shl 24);
end;
{$ifend}

class function TRNLEndianness.NetToHost64(const aValue:TRNLUInt64):TRNLUInt64;
{$if defined(CPU386)}assembler;
asm
 mov edx,dword ptr [aValue+0]
 mov eax,dword ptr [aValue+4]
 bswap eax
 bswap edx
end;
{$elseif defined(CPUX64)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .noframe
{$endif}
{$ifdef Win64}
 mov rax,rcx
{$else}
 mov rax,rdi
{$endif}
 bswap rax
end;
{$elseif defined(BIG_ENDIAN)}
begin
 result:=aValue;
end;
{$else}
begin
 result:=(aValue shr 32) or (aValue shl 32);
 result:=((result and TRNLUInt64($ffff0000ffff0000)) shr 16) or
         ((result and TRNLUInt64($0000ffff0000ffff)) shl 16);
 result:=((result and TRNLUInt64($ff00ff00ff00ff00)) shr 8) or
         ((result and TRNLUInt64($00ff00ff00ff00ff)) shl 8);
end;
{$ifend}

class function TRNLEndianness.HostToLittleEndian16(const aValue:TRNLUInt16):TRNLUInt16;
{$if not defined(BIG_ENDIAN)}
begin
 result:=aValue;
end;
{$else}
begin
 result:=(aValue shr 8) or (aValue shl 8);
end;
{$ifend}

class function TRNLEndianness.HostToLittleEndian32(const aValue:TRNLUInt32):TRNLUInt32;
{$if not defined(BIG_ENDIAN)}
begin
 result:=aValue;
end;
{$else}
begin
 result:=(aValue shr 24) or
         ((aValue and TRNLUInt32($00ff0000)) shr 8) or
         ((aValue and TRNLUInt32($0000ff00)) shl 8) or
         (aValue shl 24);
end;
{$ifend}

class function TRNLEndianness.HostToLittleEndian64(const aValue:TRNLUInt64):TRNLUInt64;
{$if not defined(BIG_ENDIAN)}
begin
 result:=aValue;
end;
{$else}
begin
 result:=(aValue shr 32) or (aValue shl 32);
 result:=((result and TRNLUInt64($ffff0000ffff0000)) shr 16) or
         ((result and TRNLUInt64($0000ffff0000ffff)) shl 16);
 result:=((result and TRNLUInt64($ff00ff00ff00ff00)) shr 8) or
         ((result and TRNLUInt64($00ff00ff00ff00ff)) shl 8);
end;
{$ifend}

class function TRNLEndianness.LittleEndianToHost16(const aValue:TRNLUInt16):TRNLUInt16;
{$if not defined(BIG_ENDIAN)}
begin
 result:=aValue;
end;
{$else}
begin
 result:=(aValue shr 8) or (aValue shl 8);
end;
{$ifend}

class function TRNLEndianness.LittleEndianToHost32(const aValue:TRNLUInt32):TRNLUInt32;
{$if not defined(BIG_ENDIAN)}
begin
 result:=aValue;
end;
{$else}
begin
 result:=(aValue shr 24) or
         ((aValue and TRNLUInt32($00ff0000)) shr 8) or
         ((aValue and TRNLUInt32($0000ff00)) shl 8) or
         (aValue shl 24);
end;
{$ifend}

class function TRNLEndianness.LittleEndianToHost64(const aValue:TRNLUInt64):TRNLUInt64;
{$if not defined(BIG_ENDIAN)}
begin
 result:=aValue;
end;
{$else}
begin
 result:=(aValue shr 32) or (aValue shl 32);
 result:=((result and TRNLUInt64($ffff0000ffff0000)) shr 16) or
         ((result and TRNLUInt64($0000ffff0000ffff)) shl 16);
 result:=((result and TRNLUInt64($ff00ff00ff00ff00)) shr 8) or
         ((result and TRNLUInt64($00ff00ff00ff00ff)) shl 8);
end;
{$ifend}

class function TRNLMemoryAccess.LoadBigEndianInt8(const aLocation):TRNLInt8;
begin
 result:=TRNLInt8(aLocation);
end;

class function TRNLMemoryAccess.LoadBigEndianUInt8(const aLocation):TRNLUInt8;
begin
 result:=TRNLUInt8(aLocation);
end;

class function TRNLMemoryAccess.LoadBigEndianInt16(const aLocation):TRNLInt16;
{$if defined(CPU386)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
 movzx eax,word ptr [eax]
 xchg al,ah
end;
{$elseif defined(CPUX64)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .noframe
{$endif}
{$ifdef Win64}
 movzx eax,word ptr [rcx]
{$else}
 movzx eax,word ptr [rdi]
{$endif}
 xchg al,ah
end;
{$else}
begin
 result:=TRNLInt16(aLocation);
{$ifndef BIG_ENDIAN}
 result:=TRNLInt16(TRNLUInt16((TRNLUInt16(result) shr 8) or
                              (TRNLUInt16(result) shl 8)));
{$endif}
end;
{$ifend}

class function TRNLMemoryAccess.LoadBigEndianUInt16(const aLocation):TRNLUInt16;
{$if defined(CPU386)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
 movzx eax,word ptr [eax]
 xchg al,ah
end;
{$elseif defined(CPUX64)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .noframe
{$endif}
{$ifdef Win64}
 movzx eax,word ptr [rcx]
{$else}
 movzx eax,word ptr [rdi]
{$endif}
 xchg al,ah
end;
{$else}
begin
 result:=TRNLUInt16(aLocation);
{$ifndef BIG_ENDIAN}
 result:=TRNLUInt16(TRNLUInt16((TRNLUInt16(result) shr 8) or
                               (TRNLUInt16(result) shl 8)));
{$endif}
end;
{$ifend}

class function TRNLMemoryAccess.LoadBigEndianInt32(const aLocation):TRNLInt32;
{$if defined(CPU386)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
 mov eax,dword ptr [eax]
 bswap eax
end;
{$elseif defined(CPUX64)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .noframe
{$endif}
{$ifdef Win64}
 mov eax,dword ptr [rcx]
{$else}
 mov eax,dword ptr [rdi]
{$endif}
 bswap eax
end;
{$else}
begin
 result:=TRNLInt32(aLocation);
{$ifndef BIG_ENDIAN}
 result:=TRNLInt32(TRNLUInt32((TRNLUInt32(result) shr 24) or
                              ((TRNLUInt32(result) and TRNLUInt32($00ff0000)) shr 8) or
                              ((TRNLUInt32(result) and TRNLUInt32($0000ff00)) shl 8) or
                              (TRNLUInt32(result) shl 24)));
{$endif}
end;
{$ifend}

class function TRNLMemoryAccess.LoadBigEndianUInt32(const aLocation):TRNLUInt32;
{$if defined(CPU386)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
 mov eax,dword ptr [eax]
 bswap eax
end;
{$elseif defined(CPUX64)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .noframe
{$endif}
{$ifdef Win64}
 mov eax,dword ptr [rcx]
{$else}
 mov eax,dword ptr [rdi]
{$endif}
 bswap eax
end;
{$else}
begin
 result:=TRNLInt32(aLocation);
{$ifndef BIG_ENDIAN}
 result:=TRNLUInt32(TRNLUInt32((TRNLUInt32(result) shr 24) or
                               ((TRNLUInt32(result) and TRNLUInt32($00ff0000)) shr 8) or
                               ((TRNLUInt32(result) and TRNLUInt32($0000ff00)) shl 8) or
                               (TRNLUInt32(result) shl 24)));
{$endif}
end;
{$ifend}

class function TRNLMemoryAccess.LoadBigEndianInt64(const aLocation):TRNLInt64;
{$if defined(CPU386)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
 mov edx,dword ptr [eax]
 mov eax,dword ptr [eax+4]
 bswap eax
 bswap edx
end;
{$elseif defined(CPUX64)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .noframe
{$endif}
{$ifdef Win64}
 mov rax,qword ptr [rcx]
{$else}
 mov rax,qword ptr [rdi]
{$endif}
 bswap rax
end;
{$else}
begin
 result:=TRNLInt64(aLocation);
{$ifndef BIG_ENDIAN}
 result:=TRNLInt64(TRNLUInt64((TRNLUInt64(result) shr 32) or (TRNLUInt64(result) shl 32)));
 result:=TRNLInt64(TRNLUInt64(((TRNLUInt64(result) and TRNLUInt64($ffff0000ffff0000)) shr 16) or
                              ((TRNLUInt64(result) and TRNLUInt64($0000ffff0000ffff)) shl 16)));
 result:=TRNLInt64(TRNLUInt64(((TRNLUInt64(result) and TRNLUInt64($ff00ff00ff00ff00)) shr 8) or
                              ((TRNLUInt64(result) and TRNLUInt64($00ff00ff00ff00ff)) shl 8)));
{$endif}
end;
{$ifend}

class function TRNLMemoryAccess.LoadBigEndianUInt64(const aLocation):TRNLUInt64;
{$if defined(CPU386)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
 mov edx,dword ptr [eax]
 mov eax,dword ptr [eax+4]
 bswap eax
 bswap edx
end;
{$elseif defined(CPUX64)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .noframe
{$endif}
{$ifdef Win64}
 mov rax,qword ptr [rcx]
{$else}
 mov rax,qword ptr [rdi]
{$endif}
 bswap rax
end;
{$else}
begin
 result:=TRNLUInt64(aLocation);
{$ifndef BIG_ENDIAN}
 result:=TRNLUInt64(TRNLUInt64((TRNLUInt64(result) shr 32) or (TRNLUInt64(result) shl 32)));
 result:=TRNLUInt64(TRNLUInt64(((TRNLUInt64(result) and TRNLUInt64($ffff0000ffff0000)) shr 16) or
                               ((TRNLUInt64(result) and TRNLUInt64($0000ffff0000ffff)) shl 16)));
 result:=TRNLUInt64(TRNLUInt64(((TRNLUInt64(result) and TRNLUInt64($ff00ff00ff00ff00)) shr 8) or
                               ((TRNLUInt64(result) and TRNLUInt64($00ff00ff00ff00ff)) shl 8)));
{$endif}
end;
{$ifend}

class function TRNLMemoryAccess.LoadLittleEndianInt8(const aLocation):TRNLInt8;
begin
 result:=TRNLInt8(aLocation);
end;

class function TRNLMemoryAccess.LoadLittleEndianUInt8(const aLocation):TRNLUInt8;
begin
 result:=TRNLUInt8(aLocation);
end;

class function TRNLMemoryAccess.LoadLittleEndianInt16(const aLocation):TRNLInt16;
begin
 result:=TRNLInt16(aLocation);
{$ifdef BIG_ENDIAN}
 result:=TRNLInt16(TRNLUInt16((TRNLUInt16(result) shr 8) or
                              (TRNLUInt16(result) shl 8)));
{$endif}
end;

class function TRNLMemoryAccess.LoadLittleEndianUInt16(const aLocation):TRNLUInt16;
begin
 result:=TRNLUInt16(aLocation);
{$ifdef BIG_ENDIAN}
 result:=TRNLUInt16(TRNLUInt16((TRNLUInt16(result) shr 8) or
                               (TRNLUInt16(result) shl 8)));
{$endif}
end;

class function TRNLMemoryAccess.LoadLittleEndianUInt24(const aLocation):TRNLUInt32;
begin
 result:=(TRNLUInt32(PRNLUInt8Array(TRNLPointer(@aLocation))^[0]) shl 0) or
         (TRNLUInt32(PRNLUInt8Array(TRNLPointer(@aLocation))^[1]) shl 8) or
         (TRNLUInt32(PRNLUInt8Array(TRNLPointer(@aLocation))^[2]) shl 16);
end;

class function TRNLMemoryAccess.LoadLittleEndianInt32(const aLocation):TRNLInt32;
begin
 result:=TRNLInt32(aLocation);
{$ifdef BIG_ENDIAN}
 result:=TRNLInt32(TRNLUInt32((TRNLUInt32(result) shr 24) or
                              ((TRNLUInt32(result) and TRNLUInt32($00ff0000)) shr 8) or
                              ((TRNLUInt32(result) and TRNLUInt32($0000ff00)) shl 8) or
                              (TRNLUInt32(result) shl 24)));
{$endif}
end;

class function TRNLMemoryAccess.LoadLittleEndianUInt32(const aLocation):TRNLUInt32;
begin
 result:=TRNLUInt32(aLocation);
{$ifdef BIG_ENDIAN}
 result:=TRNLUInt32(TRNLUInt32((TRNLUInt32(result) shr 24) or
                               ((TRNLUInt32(result) and TRNLUInt32($00ff0000)) shr 8) or
                               ((TRNLUInt32(result) and TRNLUInt32($0000ff00)) shl 8) or
                               (TRNLUInt32(result) shl 24)));
{$endif}
end;

class function TRNLMemoryAccess.LoadLittleEndianInt64(const aLocation):TRNLInt64;
begin
 result:=TRNLInt64(aLocation);
{$ifdef BIG_ENDIAN}
 result:=TRNLInt64(TRNLUInt64((TRNLUInt64(result) shr 32) or (TRNLUInt64(result) shl 32)));
 result:=TRNLInt64(TRNLUInt64(((TRNLUInt64(result) and TRNLUInt64($ffff0000ffff0000)) shr 16) or
                              ((TRNLUInt64(result) and TRNLUInt64($0000ffff0000ffff)) shl 16)));
 result:=TRNLInt64(TRNLUInt64(((TRNLUInt64(result) and TRNLUInt64($ff00ff00ff00ff00)) shr 8) or
                              ((TRNLUInt64(result) and TRNLUInt64($00ff00ff00ff00ff)) shl 8)));
{$endif}
end;

class function TRNLMemoryAccess.LoadLittleEndianUInt64(const aLocation):TRNLUInt64;
begin
 result:=TRNLUInt64(aLocation);
{$ifdef BIG_ENDIAN}
 result:=TRNLUInt64(TRNLUInt64((TRNLUInt64(result) shr 32) or (TRNLUInt64(result) shl 32)));
 result:=TRNLUInt64(TRNLUInt64(((TRNLUInt64(result) and TRNLUInt64($ffff0000ffff0000)) shr 16) or
                               ((TRNLUInt64(result) and TRNLUInt64($0000ffff0000ffff)) shl 16)));
 result:=TRNLUInt64(TRNLUInt64(((TRNLUInt64(result) and TRNLUInt64($ff00ff00ff00ff00)) shr 8) or
                               ((TRNLUInt64(result) and TRNLUInt64($00ff00ff00ff00ff)) shl 8)));
{$endif}
end;

class procedure TRNLMemoryAccess.StoreBigEndianInt8(out aLocation;const aValue:TRNLInt8);
begin
 TRNLInt8(aLocation):=aValue;
end;

class procedure TRNLMemoryAccess.StoreBigEndianUInt8(out aLocation;const aValue:TRNLUInt8);
begin
 TRNLUInt8(aLocation):=aValue;
end;

class procedure TRNLMemoryAccess.StoreBigEndianInt16(out aLocation;const aValue:TRNLInt16);
{$if defined(CPU386)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
 xchg dl,dh
 mov word ptr [eax],dx
end;
{$elseif defined(CPUX64)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .noframe
{$endif}
{$ifdef Win64}
 xchg dl,dh
 mov word ptr [rcx],dx
{$else}
 mov ax,si
 xchg al,ah
 mov word ptr [rdi],ax
{$endif}
end;
{$elseif not defined(BIG_ENDIAN)}
begin
 TRNLInt16(aLocation):=TRNLInt16(TRNLUInt16((TRNLUInt16(aValue) shr 8) or
                                            (TRNLUInt16(aValue) shl 8)));
end;
{$else}
begin
 TRNLInt16(aLocation):=aValue;
end;
{$ifend}

class procedure TRNLMemoryAccess.StoreBigEndianUInt16(out aLocation;const aValue:TRNLUInt16);
{$if defined(CPU386)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
 xchg dl,dh
 mov word ptr [eax],dx
end;
{$elseif defined(CPUX64)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .noframe
{$endif}
{$ifdef Win64}
 xchg dl,dh
 mov word ptr [rcx],dx
{$else}
 mov ax,si
 xchg al,ah
 mov word ptr [rdi],ax
{$endif}
end;
{$elseif not defined(BIG_ENDIAN)}
begin
 TRNLUInt16(aLocation):=TRNLUInt16(TRNLUInt16((TRNLUInt16(aValue) shr 8) or
                                              (TRNLUInt16(aValue) shl 8)));
end;
{$else}
begin
 TRNLUInt16(aLocation):=aValue;
end;
{$ifend}

class procedure TRNLMemoryAccess.StoreBigEndianInt32(out aLocation;const aValue:TRNLInt32);
{$if defined(CPU386)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
 bswap edx
 mov dword ptr [eax],edx
end;
{$elseif defined(CPUX64)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .noframe
{$endif}
{$ifdef Win64}
 bswap edx
 mov dword ptr [rcx],edx
{$else}
 bswap esi
 mov dword ptr [rdi],esi
{$endif}
end;
{$elseif not defined(BIG_ENDIAN)}
begin
 TRNLInt32(aLocation):=TRNLInt32(TRNLUInt32((TRNLUInt32(aValue) shr 24) or
                                            ((TRNLUInt32(aValue) and TRNLUInt32($00ff0000)) shr 8) or
                                            ((TRNLUInt32(aValue) and TRNLUInt32($0000ff00)) shl 8) or
                                            (TRNLUInt32(aValue) shl 24)));
end;
{$else}
begin
 TRNLInt32(aLocation):=aValue;
end;
{$ifend}

class procedure TRNLMemoryAccess.StoreBigEndianUInt32(out aLocation;const aValue:TRNLUInt32);
{$if defined(CPU386)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
 bswap edx
 mov dword ptr [eax],edx
end;
{$elseif defined(CPUX64)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .noframe
{$endif}
{$ifdef Win64}
 bswap edx
 mov dword ptr [rcx],edx
{$else}
 bswap esi
 mov dword ptr [rdi],esi
{$endif}
end;
{$elseif not defined(BIG_ENDIAN)}
begin
 TRNLUInt32(aLocation):=TRNLUInt32(TRNLUInt32((TRNLUInt32(aValue) shr 24) or
                                              ((TRNLUInt32(aValue) and TRNLUInt32($00ff0000)) shr 8) or
                                              ((TRNLUInt32(aValue) and TRNLUInt32($0000ff00)) shl 8) or
                                              (TRNLUInt32(aValue) shl 24)));
end;
{$else}
begin
 TRNLUInt32(aLocation):=aValue;
end;
{$ifend}

class procedure TRNLMemoryAccess.StoreBigEndianInt64(out aLocation;const aValue:TRNLInt64);
{$if defined(CPU386)}assembler;
asm
 mov edx,dword ptr [aValue]
 mov ecx,dword ptr [aValue+4]
 bswap ecx
 bswap edx
 mov dword ptr [eax],ecx
 mov dword ptr [eax+4],edx
end;
{$elseif defined(CPUX64)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .noframe
{$endif}
{$ifdef Win64}
 bswap rdx
 mov qword ptr [rcx],rdx
{$else}
 bswap rsi
 mov qword ptr [rdi],rsi
{$endif}
end;
{$elseif not defined(BIG_ENDIAN)}
var Value:TRNLUInt64;
begin
 Value:=(TRNLUInt64(aValue) shr 32) or (TRNLUInt64(aValue) shl 32);
 Value:=((Value and TRNLUInt64($ffff0000ffff0000)) shr 16) or
        ((Value and TRNLUInt64($0000ffff0000ffff)) shl 16);
 TRNLUInt64(aLocation):=((Value and TRNLUInt64($ff00ff00ff00ff00)) shr 8) or
                        ((Value and TRNLUInt64($00ff00ff00ff00ff)) shl 8);
end;
{$else}
begin
 TRNLInt64(aLocation):=aValue;
end;
{$ifend}

class procedure TRNLMemoryAccess.StoreBigEndianUInt64(out aLocation;const aValue:TRNLUInt64);
{$if defined(CPU386)}assembler;
asm
 mov edx,dword ptr [aValue]
 mov ecx,dword ptr [aValue+4]
 bswap ecx
 bswap edx
 mov dword ptr [eax],ecx
 mov dword ptr [eax+4],edx
end;
{$elseif defined(CPUX64)}assembler;{$ifdef fpc}nostackframe;{$endif}
asm
{$ifndef fpc}
 .noframe
{$endif}
{$ifdef Win64}
 bswap rdx
 mov qword ptr [rcx],rdx
{$else}
 bswap rsi
 mov qword ptr [rdi],rsi
{$endif}
end;
{$elseif not defined(BIG_ENDIAN)}
var Value:TRNLUInt64;
begin
 Value:=(aValue shr 32) or (aValue shl 32);
 Value:=((Value and TRNLUInt64($ffff0000ffff0000)) shr 16) or
        ((Value and TRNLUInt64($0000ffff0000ffff)) shl 16);
 TRNLUInt64(aLocation):=((Value and TRNLUInt64($ff00ff00ff00ff00)) shr 8) or
                        ((Value and TRNLUInt64($00ff00ff00ff00ff)) shl 8);
end;
{$else}
begin
 TRNLUInt64(aLocation):=aValue;
end;
{$ifend}

class procedure TRNLMemoryAccess.StoreLittleEndianInt8(out aLocation;const aValue:TRNLInt8);
begin
 TRNLInt8(aLocation):=aValue;
end;

class procedure TRNLMemoryAccess.StoreLittleEndianUInt8(out aLocation;const aValue:TRNLUInt8);
begin
 TRNLUInt8(aLocation):=aValue;
end;

class procedure TRNLMemoryAccess.StoreLittleEndianInt16(out aLocation;const aValue:TRNLInt16);
{$ifdef BIG_ENDIAN}
begin
 TRNLInt16(aLocation):=TRNLInt16(TRNLUInt16((TRNLUInt16(aValue) shr 8) or
                                            (TRNLUInt16(aValue) shl 8)));
end;
{$else}
begin
 TRNLInt16(aLocation):=aValue;
end;
{$endif}

class procedure TRNLMemoryAccess.StoreLittleEndianUInt16(out aLocation;const aValue:TRNLUInt16);
{$ifdef BIG_ENDIAN}
begin
 TRNLUInt16(aLocation):=TRNLUInt16(TRNLUInt16((TRNLUInt16(aValue) shr 8) or
                                              (TRNLUInt16(aValue) shl 8)));
end;
{$else}
begin
 TRNLUInt16(aLocation):=aValue;
end;
{$endif}

class procedure TRNLMemoryAccess.StoreLittleEndianInt32(out aLocation;const aValue:TRNLInt32);
{$ifdef BIG_ENDIAN}
begin
 TRNLInt32(aLocation):=TRNLInt32(TRNLUInt32((TRNLUInt32(aValue) shr 24) or
                                            ((TRNLUInt32(aValue) and TRNLUInt32($00ff0000)) shr 8) or
                                            ((TRNLUInt32(aValue) and TRNLUInt32($0000ff00)) shl 8) or
                                            (TRNLUInt32(aValue) shl 24)));
end;
{$else}
begin
 TRNLInt32(aLocation):=aValue;
end;
{$endif}

class procedure TRNLMemoryAccess.StoreLittleEndianUInt32(out aLocation;const aValue:TRNLUInt32);
{$ifdef BIG_ENDIAN}
begin
 TRNLUInt32(aLocation):=TRNLUInt32(TRNLUInt32((TRNLUInt32(aValue) shr 24) or
                                              ((TRNLUInt32(aValue) and TRNLUInt32($00ff0000)) shr 8) or
                                              ((TRNLUInt32(aValue) and TRNLUInt32($0000ff00)) shl 8) or
                                              (TRNLUInt32(aValue) shl 24)));
end;
{$else}
begin
 TRNLUInt32(aLocation):=aValue;
end;
{$endif}

class procedure TRNLMemoryAccess.StoreLittleEndianInt64(out aLocation;const aValue:TRNLInt64);
{$ifdef BIG_ENDIAN}
var Value:TRNLUInt64;
begin
 Value:=(TRNLUInt64(aValue) shr 32) or (TRNLUInt64(aValue) shl 32);
 Value:=((Value and TRNLUInt64($ffff0000ffff0000)) shr 16) or
        ((Value and TRNLUInt64($0000ffff0000ffff)) shl 16);
 TRNLUInt64(aLocation):=((Value and TRNLUInt64($ff00ff00ff00ff00)) shr 8) or
                        ((Value and TRNLUInt64($00ff00ff00ff00ff)) shl 8);
end;
{$else}
begin
 TRNLInt64(aLocation):=aValue;
end;
{$endif}

class procedure TRNLMemoryAccess.StoreLittleEndianUInt64(out aLocation;const aValue:TRNLUInt64);
{$ifdef BIG_ENDIAN}
var Value:TRNLUInt64;
begin
 Value:=(aValue shr 32) or (aValue shl 32);
 Value:=((Value and TRNLUInt64($ffff0000ffff0000)) shr 16) or
        ((Value and TRNLUInt64($0000ffff0000ffff)) shl 16);
 TRNLUInt64(aLocation):=((Value and TRNLUInt64($ff00ff00ff00ff00)) shr 8) or
                        ((Value and TRNLUInt64($00ff00ff00ff00ff)) shl 8);
end;
{$else}
begin
 TRNLUInt64(aLocation):=aValue;
end;
{$endif}

class function TRNLMemory.SecureIsEqual(const aLocationA,aLocationB;const aSize:TRNLSizeUInt):boolean;
var Index,Position:TRNLSizeUInt;
    Temporary:TRNLUInt32;
begin
 Temporary:=0;
 for Index:=1 to aSize do begin
  Position:=Index-1;
  Temporary:=Temporary or (PRNLUInt8Array(TRNLPointer(@aLocationA))^[Position] xor PRNLUInt8Array(TRNLPointer(@aLocationB))^[Position]);
 end;
 result:=Temporary=0;
end;

class function TRNLMemory.SecureIsNonEqual(const aLocationA,aLocationB;const aSize:TRNLSizeUInt):boolean;
var Index,Position:TRNLSizeUInt;
    Temporary:TRNLUInt32;
begin
 Temporary:=0;
 for Index:=1 to aSize do begin
  Position:=Index-1;
  Temporary:=Temporary or (PRNLUInt8Array(TRNLPointer(@aLocationA))^[Position] xor PRNLUInt8Array(TRNLPointer(@aLocationB))^[Position]);
 end;
 result:=Temporary<>0;
end;

class function TRNLMemory.SecureIsZero(const aLocation;const aSize:TRNLSizeUInt):boolean;
var Index:TRNLSizeUInt;
    Temporary:TRNLUInt32;
begin
 Temporary:=0;
 for Index:=1 to aSize do begin
  Temporary:=Temporary or PRNLUInt8Array(TRNLPointer(@aLocation))^[Index-1];
 end;
 result:=Temporary=0;
end;

class function TRNLMemory.SecureIsNonZero(const aLocation;const aSize:TRNLSizeUInt):boolean;
var Index:TRNLSizeUInt;
    Temporary:TRNLUInt32;
begin
 Temporary:=0;
 for Index:=1 to aSize do begin
  Temporary:=Temporary or PRNLUInt8Array(TRNLPointer(@aLocation))^[Index-1];
 end;
 result:=Temporary<>0;
end;

class procedure TRNLTypedSort<T>.IntroSort(const pItems:TRNLPointer;const pLeft,pRight:TRNLInt32;const pCompareFunc:TRNLTypedSortCompareFunction);
type TItem=T;
     PItem=^TItem;
     TItemArray=array[0..65535] of TItem;
     PItemArray=^TItemArray;
     TStackItem=record
      Left,Right,Depth:TRNLInt32;
     end;
     PStackItem=^TStackItem;
var Left,Right,Depth,i,j,Middle,Size,Parent,Child,Pivot,iA,iB,iC:TRNLInt32;
    StackItem:PStackItem;
    Stack:array[0..31] of TStackItem;
    Temp:T;
begin
 if pLeft<pRight then begin
  StackItem:=@Stack[0];
  StackItem^.Left:=pLeft;
  StackItem^.Right:=pRight;
  StackItem^.Depth:=BSRDWord((pRight-pLeft)+1) shl 1;
  inc(StackItem);
  while {%H-}TRNLPtrUInt(TRNLPointer(StackItem))>TRNLPtrUInt(TRNLPointer(@Stack[0])) do begin
   dec(StackItem);
   Left:=StackItem^.Left;
   Right:=StackItem^.Right;
   Depth:=StackItem^.Depth;
   Size:=(Right-Left)+1;
   if Size<16 then begin
    // Insertion sort
    iA:=Left;
    iB:=iA+1;
    while iB<=Right do begin
     iC:=iB;
     while (iA>=Left) and
           (iC>=Left) and
           (pCompareFunc(PItemArray(pItems)^[iA],PItemArray(pItems)^[iC])>0) do begin
      Temp:=PItemArray(pItems)^[iA];
      PItemArray(pItems)^[iA]:=PItemArray(pItems)^[iC];
      PItemArray(pItems)^[iC]:=Temp;
      dec(iA);
      dec(iC);
     end;
     iA:=iB;
     inc(iB);
    end;
   end else begin
    if (Depth=0) or ({%H-}TRNLPtrUInt(TRNLPointer(StackItem))>=TRNLPtrUInt(TRNLPointer(@Stack[high(Stack)-1]))) then begin
     // Heap sort
     i:=Size div 2;
     repeat
      if i>0 then begin
       dec(i);
      end else begin
       dec(Size);
       if Size>0 then begin
        Temp:=PItemArray(pItems)^[Left+Size];
        PItemArray(pItems)^[Left+Size]:=PItemArray(pItems)^[Left];
        PItemArray(pItems)^[Left]:=Temp;
       end else begin
        break;
       end;
      end;
      Parent:=i;
      repeat
       Child:=(Parent*2)+1;
       if Child<Size then begin
        if (Child<(Size-1)) and (pCompareFunc(PItemArray(pItems)^[Left+Child],PItemArray(pItems)^[Left+Child+1])<0) then begin
         inc(Child);
        end;
        if pCompareFunc(PItemArray(pItems)^[Left+Parent],PItemArray(pItems)^[Left+Child])<0 then begin
         Temp:=PItemArray(pItems)^[Left+Parent];
         PItemArray(pItems)^[Left+Parent]:=PItemArray(pItems)^[Left+Child];
         PItemArray(pItems)^[Left+Child]:=Temp;
         Parent:=Child;
         continue;
        end;
       end;
       break;
      until false;
     until false;
    end else begin
     // Quick sort width median-of-three optimization
     Middle:=Left+((Right-Left) shr 1);
     if (Right-Left)>3 then begin
      if pCompareFunc(PItemArray(pItems)^[Left],PItemArray(pItems)^[Middle])>0 then begin
       Temp:=PItemArray(pItems)^[Left];
       PItemArray(pItems)^[Left]:=PItemArray(pItems)^[Middle];
       PItemArray(pItems)^[Middle]:=Temp;
      end;
      if pCompareFunc(PItemArray(pItems)^[Left],PItemArray(pItems)^[Right])>0 then begin
       Temp:=PItemArray(pItems)^[Left];
       PItemArray(pItems)^[Left]:=PItemArray(pItems)^[Right];
       PItemArray(pItems)^[Right]:=Temp;
      end;
      if pCompareFunc(PItemArray(pItems)^[Middle],PItemArray(pItems)^[Right])>0 then begin
       Temp:=PItemArray(pItems)^[Middle];
       PItemArray(pItems)^[Middle]:=PItemArray(pItems)^[Right];
       PItemArray(pItems)^[Right]:=Temp;
      end;
     end;
     Pivot:=Middle;
     i:=Left;
     j:=Right;
     repeat
      while (i<Right) and (pCompareFunc(PItemArray(pItems)^[i],PItemArray(pItems)^[Pivot])<0) do begin
       inc(i);
      end;
      while (j>=i) and (pCompareFunc(PItemArray(pItems)^[j],PItemArray(pItems)^[Pivot])>0) do begin
       dec(j);
      end;
      if i>j then begin
       break;
      end else begin
       if i<>j then begin
        Temp:=PItemArray(pItems)^[i];
        PItemArray(pItems)^[i]:=PItemArray(pItems)^[j];
        PItemArray(pItems)^[j]:=Temp;
        if Pivot=i then begin
         Pivot:=j;
        end else if Pivot=j then begin
         Pivot:=i;
        end;
       end;
       inc(i);
       dec(j);
      end;
     until false;
     if i<Right then begin
      StackItem^.Left:=i;
      StackItem^.Right:=Right;
      StackItem^.Depth:=Depth-1;
      inc(StackItem);
     end;
     if Left<j then begin
      StackItem^.Left:=Left;
      StackItem^.Right:=j;
      StackItem^.Depth:=Depth-1;
      inc(StackItem);
     end;
    end;
   end;
  end;
 end;
end;

class function TRNLHashUtils.Hash32(const aLocation;const aSize:TRNLSizeUInt):TRNLUInt32;
var b:PRNLUInt8;
    Remaining:TRNLSizeUInt;
    h,i:TRNLUInt32;
begin
 result:=2166136261;
 Remaining:=aSize;
 h:=Remaining;
 if Remaining>0 then begin
  b:=@aLocation;
  while Remaining>3 do begin
   i:=TRNLUInt32(TRNLPointer(b)^);
   h:=(h xor i) xor $2e63823a;
   inc(h,(h shl 15) or (h shr (32-15)));
   dec(h,(h shl 9) or (h shr (32-9)));
   inc(h,(h shl 4) or (h shr (32-4)));
   dec(h,(h shl 1) or (h shr (32-1)));
   h:=h xor (h shl 2) or (h shr (32-2));
   result:=result xor i;
   inc(result,(result shl 1)+(result shl 4)+(result shl 7)+(result shl 8)+(result shl 24));
   inc(b,4);
   dec(Remaining,4);
  end;
  if Remaining>1 then begin
   i:=TRNLUInt16(TRNLPointer(b)^);
   h:=(h xor i) xor $2e63823a;
   inc(h,(h shl 15) or (h shr (32-15)));
   dec(h,(h shl 9) or (h shr (32-9)));
   inc(h,(h shl 4) or (h shr (32-4)));
   dec(h,(h shl 1) or (h shr (32-1)));
   h:=h xor (h shl 2) or (h shr (32-2));
   result:=result xor i;
   inc(result,(result shl 1)+(result shl 4)+(result shl 7)+(result shl 8)+(result shl 24));
   inc(b,2);
   dec(Remaining,2);
  end;
  if Remaining>0 then begin
   i:=TRNLUInt8(b^);
   h:=(h xor i) xor $2e63823a;
   inc(h,(h shl 15) or (h shr (32-15)));
   dec(h,(h shl 9) or (h shr (32-9)));
   inc(h,(h shl 4) or (h shr (32-4)));
   dec(h,(h shl 1) or (h shr (32-1)));
   h:=h xor (h shl 2) or (h shr (32-2));
   result:=result xor i;
   inc(result,(result shl 1)+(result shl 4)+(result shl 7)+(result shl 8)+(result shl 24));
  end;
 end;
 result:=result xor h;
 if result=0 then begin
  result:=$ffffffff;
 end;
end;

{$if defined(Windows)}
type HCRYPTPROV=PRNLUInt32;

const PROV_RSA_FULL=1;
      CRYPT_VERIFYCONTEXT=$f0000000;
      CRYPT_SILENT=$00000040;
      CRYPT_NEWKEYSET=$00000008;

function CryptAcquireContext(var phProv:HCRYPTPROV;pszContainer:PAnsiChar;pszProvider:PAnsiChar;dwProvType:TRNLUInt32;dwFlags:TRNLUInt32):LONGBOOL; stdcall; external advapi32 name 'CryptAcquireContextA';
function CryptReleaseContext(hProv:HCRYPTPROV;dwFlags:TRNLUInt32):BOOL; stdcall; external advapi32 name 'CryptReleaseContext';
function CryptGenRandom(hProv:HCRYPTPROV;dwLen:TRNLUInt32;pbBuffer:Pointer):BOOL; stdcall; external advapi32 name 'CryptGenRandom';

function CoCreateGuid(var aGuid:TGUID):HResult; stdcall; external 'ole32.dll';
{$ifend}

constructor TRNLRandomGenerator.Create;
begin
 inherited Create;
{$if defined(Windows)}
 fWindowsCryptProviderInitialized:=false;
 if CryptAcquireContext(HCRYPTPROV(fWindowsCryptProvider),nil,nil,PROV_RSA_FULL,CRYPT_VERIFYCONTEXT) then begin
  fWindowsCryptProviderInitialized:=true;
 end else if GetLastError=TRNLUInt32(NTE_BAD_KEYSET) then begin
  if CryptAcquireContext(HCRYPTPROV(fWindowsCryptProvider),nil,nil,PROV_RSA_FULL,CRYPT_NEWKEYSET) then begin
   fWindowsCryptProviderInitialized:=true;
  end;
 end;
{$ifend}
 fPosition:=0;
 fHave:=0;
 fInitialized:=false;
 fGuassianFloatUseLast:=false;
 fGuassianDoubleUseLast:=false;
end;

destructor TRNLRandomGenerator.Destroy;
begin
{$if defined(Windows)}
 if fWindowsCryptProviderInitialized then begin
  fWindowsCryptProviderInitialized:=false;
  CryptReleaseContext(HCRYPTPROV(fWindowsCryptProvider),0);
 end;
{$ifend}
 inherited Destroy;
end;

procedure TRNLRandomGenerator.Initialize(const aData;const aDataLength:TRNLSizeUInt);
begin
 if aDataLength>=SizeOf(TRNLRandomGeneratorSeed) then begin
  fChaCha20Context.XChaCha20Initialize(PRNLRandomGeneratorSeed(TRNLPointer(@aData))^.Key,
                                       PRNLRandomGeneratorSeed(TRNLPointer(@aData))^.Nonce,
                                       0);
 end;
end;

procedure TRNLRandomGenerator.Rekey(const aData;const aDataLength:TRNLSizeUInt);
var Index:TRNLSizeUInt;
begin
 fChaCha20Context.Process(fBuffer,fBuffer,SizeOf(TRNLRandomGeneratorBuffer));
 if aDataLength>0 then begin
  for Index:=1 to Min(aDataLength,SizeOf(TRNLRandomGeneratorSeed)) do begin
   fBuffer[Index]:=fBuffer[Index] xor PRNLUInt8Array(TRNLPointer(@aData))^[Index];
  end;
 end;
 Initialize(fBuffer[0],SizeOf(TRNLRandomGeneratorSeed));
 FillChar(fBuffer[0],SizeOf(TRNLRandomGeneratorSeed),#0);
 fPosition:=SizeOf(TRNLRandomGeneratorSeed);
 fHave:=SizeOf(TRNLRandomGeneratorBuffer)-SizeOf(TRNLRandomGeneratorSeed);
end;

procedure TRNLRandomGenerator.Reseed;
var EntropyData:TRNLRandomGeneratorEntropyData;
 procedure GetEntropyData;
{$if defined(Windows)}
  function WindowsGetEntropyData(out aBuffer;const aSize:TRNLSizeUInt):boolean;
  begin
   if fWindowsCryptProviderInitialized then begin
    FillChar(aBuffer,aSize,#0);
    result:=CryptGenRandom(HCRYPTPROV(fWindowsCryptProvider),aSize,@aBuffer);
   end else begin
    result:=false;
   end;
  end;
  function WindowsEnvironmentStringsGetEntropyData(out aBuffer;const aSize:TRNLSizeUInt):boolean;
  var Index,SubIndex:TRNLSizeUInt;
      HashState:TRNLUInt64;
      pp,p:PWideChar;
  begin
   result:=false;
   HashState:=TRNLUInt64(4695981039346656037);
   pp:=GetEnvironmentStringsW;
   if assigned(pp) then begin
    p:=pp;
    try
     FillChar(aBuffer,aSize,#0);
     Index:=0;
     while assigned(p) and (p^<>#0) do begin
      while assigned(p) and (p^<>#0) do begin
       HashState:=(HashState xor TRNLUInt16(WideChar(p^)))*TRNLUInt64(1099511628211);
       for SubIndex:=0 to SizeOf(TRNLUInt64)-1 do begin
        PRNLUInt8Array(TRNLPointer(@aBuffer))^[Index]:=HashState shr (SubIndex shl 3);
        inc(Index);
        if Index>=aSize then begin
         Index:=0;
        end;
       end;
       inc(p);
      end;
      inc(p);
     end;
     result:=true;
    finally
     FreeEnvironmentStringsW(TRNLPointer(p));
    end;
   end;
  end;
  function WindowsCommandLineGetEntropyData(out aBuffer;const aSize:TRNLSizeUInt):boolean;
  var Index,SubIndex:TRNLSizeUInt;
      HashState:TRNLUInt64;
      pp,p:PWideChar;
  begin
   result:=false;
   HashState:=TRNLUInt64(91734284728269012);
   pp:=GetCommandLineW;
   if assigned(pp) then begin
    p:=pp;
    try
     FillChar(aBuffer,aSize,#0);
     Index:=0;
     while assigned(p) and (p^<>#0) do begin
      while assigned(p) and (p^<>#0) do begin
       HashState:=(HashState xor TRNLUInt16(WideChar(p^)))*TRNLUInt64(1099511628211);
       for SubIndex:=0 to SizeOf(TRNLUInt64)-1 do begin
        PRNLUInt8Array(TRNLPointer(@aBuffer))^[Index]:=HashState shr (SubIndex shl 3);
        inc(Index);
        if Index>=aSize then begin
         Index:=0;
        end;
       end;
       inc(p);
      end;
      inc(p);
     end;
     result:=true;
    finally
     FreeEnvironmentStringsW(TRNLPointer(p));
    end;
   end;
  end;
{$elseif defined(Unix) or defined(Posix)}
  function PosixGetEntropyData(out aBuffer;const aSize:TRNLInt32):boolean;
  const Paths:array[0..2] of string=('/dev/srandom','/dev/urandom','/dev/random');
  var Index:TRNLSizeUInt;
      Path:string;
 {$ifdef fpc}
      fd:TRNLInt32;
 {$else}
      FileStream:TFileStream;
 {$endif}
  begin
   result:=false;
   FillChar(aBuffer,aSize,#0);
   for Index:=low(Paths) to high(Paths) do begin
    Path:=Paths[Index];
    try
 {$ifdef fpc}
     fd:=fpopen(Path,O_RDONLY);
     if fd>=0 then begin
      try
       result:=fpread(fd,aBuffer,aSize)=aSize;
      finally
       fpclose(fd);
      end;
     end;
 {$else}
     if FileExists(Path) then begin
      FileStream:=TFileStream.Create(Path,fmOpenRead or fmShareDenyNone);
      try
       result:=FileStream.Read(aBuffer,aSize)=aSize;
      finally
       FileStream.Free;
      end;
     end;
 {$endif}
    except
    end;
    if result then begin
     break;
    end;
   end;
  end;
{$ifend}
  function GetAdditionalEntropyData(out aBuffer;const aSize:TRNLInt32):boolean;
  type PRNLRandomGeneratorPCG32=^TRNLRandomGeneratorPCG32;
       TRNLRandomGeneratorPCG32=record
        State:TRNLUInt64;
        Increment:TRNLUInt64;
       end;
       PRNLRandomGeneratorSplitMix64=^TRNLRandomGeneratorSplitMix64;
       TRNLRandomGeneratorSplitMix64=TRNLUInt64;
       PRNLRandomGeneratorLCG64=^TRNLRandomGeneratorLCG64;
       TRNLRandomGeneratorLCG64=TRNLUInt64;
       PRNLRandomGeneratorMWC=^TRNLRandomGeneratorMWC;
       TRNLRandomGeneratorMWC=record
        x:TRNLUInt32;
        y:TRNLUInt32;
        c:TRNLUInt32;
       end;
       PRNLRandomGeneratorXorShift128=^TRNLRandomGeneratorXorShift128;
       TRNLRandomGeneratorXorShift128=record
        x,y,z,w:TRNLUInt32;
       end;
       PRNLRandomGeneratorXorShift128Plus=^TRNLRandomGeneratorXorShift128Plus;
       TRNLRandomGeneratorXorShift128Plus=record
        s:array[0..1] of TRNLUInt64;
       end;
       PRNLRandomGeneratorXorShift1024=^TRNLRandomGeneratorXorShift1024;
       TRNLRandomGeneratorXorShift1024=record
        s:array[0..15] of TRNLUInt64;
        p:TRNLInt32;
       end;
       PRNLRandomGeneratorCMWC4096=^TRNLRandomGeneratorCMWC4096;
       TRNLRandomGeneratorCMWC4096=record
        Q:array[0..4095] of TRNLUInt64;
        QC:TRNLUInt64;
        QJ:TRNLUInt64;
       end;
       PRNLRandomGeneratorState=^TRNLRandomGeneratorState;
       TRNLRandomGeneratorState=record
        LCG64:TRNLRandomGeneratorLCG64;
        XorShift1024:TRNLRandomGeneratorXorShift1024;
        CMWC4096:TRNLRandomGeneratorCMWC4096;
        PCG32:TRNLRandomGeneratorPCG32;
       end;
   function PCG32Next(var State:TRNLRandomGeneratorPCG32):TRNLUInt64; {$ifdef caninline}inline;{$endif}
   var OldState:TRNLUInt64;
       XorShifted,Rot:TRNLUInt32;
   begin
    OldState:=State.State;
    State.State:=(OldState*TRNLUInt64(6364136223846793005))+(State.Increment or 1);
    XorShifted:=TRNLUInt64((OldState shr 18) xor OldState) shr 27;
    Rot:=OldState shr 59;
    result:=(XorShifted shr rot) or (TRNLUInt64(XorShifted) shl ((-Rot) and 31));
   end;
   function SplitMix64Next(var State:TRNLRandomGeneratorSplitMix64):TRNLUInt64; {$ifdef caninline}inline;{$endif}
   var z:TRNLUInt64;
   begin
    State:=State+{$ifndef fpc}TRNLUInt64{$endif}($9e3779b97f4a7c15);
    z:=State;
    z:=(z xor (z shr 30))*{$ifndef fpc}TRNLUInt64{$endif}($bf58476d1ce4e5b9);
    z:=(z xor (z shr 27))*{$ifndef fpc}TRNLUInt64{$endif}($94d049bb133111eb);
    result:=z xor (z shr 31);
   end;
   function LCG64Next(var State:TRNLRandomGeneratorLCG64):TRNLUInt64; {$ifdef caninline}inline;{$endif}
   begin
    State:=(State*TRNLUInt64(2862933555777941757))+TRNLUInt64(3037000493);
    result:=State;
   end;
   function XorShift128Next(var State:TRNLRandomGeneratorXorShift128):TRNLUInt32; {$ifdef caninline}inline;{$endif}
   var t:TRNLUInt32;
   begin
    t:=State.x xor (State.x shl 11);
    State.x:=State.y;
    State.y:=State.z;
    State.z:=State.w;
    State.w:=(State.w xor (State.w shr 19)) xor (t xor (t shr 8));
    result:=State.w;
   end;
   function XorShift128PlusNext(var State:TRNLRandomGeneratorXorShift128Plus):TRNLUInt64; {$ifdef caninline}inline;{$endif}
   var s0,s1:TRNLUInt64;
   begin
    s1:=State.s[0];
    s0:=State.s[1];
    State.s[0]:=s0;
    s1:=s1 xor (s1 shl 23);
    State.s[1]:=((s1 xor s0) xor (s1 shr 18)) xor (s0 shr 5);
    result:=State.s[1]+s0;
   end;
   procedure XorShift128PlusJump(var State:TRNLRandomGeneratorXorShift128Plus);
   const Jump:array[0..1] of TRNLUInt64=
          (TRNLUInt64($8a5cd789635d2dff),
           TRNLUInt64($121fd2155c472f96));
   var i,b:TRNLSizeInt;
       s0,s1:TRNLUInt64;
   begin
    s0:=0;
    s1:=0;
    for i:=0 to 1 do begin
     for b:=0 to 63 do begin
      if (Jump[i] and TRNLUInt64(TRNLUInt64(1) shl b))<>0 then begin
       s0:=s0 xor State.s[0];
       s1:=s1 xor State.s[1];
      end;
      XorShift128PlusNext(State);
     end;
    end;
    State.s[0]:=s0;
    State.s[1]:=s1;
   end;
   function XorShift1024Next(var State:TRNLRandomGeneratorXorShift1024):TRNLUInt64; {$ifdef caninline}inline;{$endif}
   var s0,s1:TRNLUInt64;
   begin
    s0:=State.s[State.p and 15];
    State.p:=(State.p+1) and 15;
    s1:=State.s[State.p];
    s1:=s1 xor (s1 shl 31);
    State.s[State.p]:=((s1 xor s0) xor (s1 shr 11)) xor (s0 shr 30);
    result:=State.s[State.p]*TRNLUInt64(1181783497276652981);
   end;
   procedure XorShift1024Jump(var State:TRNLRandomGeneratorXorShift1024);
   const Jump:array[0..15] of TRNLUInt64=
          (TRNLUInt64($84242f96eca9c41d),
           TRNLUInt64($a3c65b8776f96855),
           TRNLUInt64($5b34a39f070b5837),
           TRNLUInt64($4489affce4f31a1e),
           TRNLUInt64($2ffeeb0a48316f40),
           TRNLUInt64($dc2d9891fe68c022),
           TRNLUInt64($3659132bb12fea70),
           TRNLUInt64($aac17d8efa43cab8),
           TRNLUInt64($c4cb815590989b13),
           TRNLUInt64($5ee975283d71c93b),
           TRNLUInt64($691548c86c1bd540),
           TRNLUInt64($7910c41d10a1e6a5),
           TRNLUInt64($0b5fc64563b3e2a8),
           TRNLUInt64($047f7684e9fc949d),
           TRNLUInt64($b99181f2d8f685ca),
           TRNLUInt64($284600e3f30e38c3));
   var i,b,j:TRNLSizeInt;
       t:array[0..15] of TRNLUInt64;
   begin
    for i:=0 to 15 do begin
     t[i]:=0;
    end;
    for i:=0 to 15 do begin
     for b:=0 to 63 do begin
      if (Jump[i] and TRNLUInt64(TRNLUInt64(1) shl b))<>0 then begin
       for j:=0 to 15 do begin
        t[j]:=t[j] xor State.s[(j+State.p) and 15];
       end;
      end;
      XorShift1024Next(State);
     end;
    end;
    for i:=0 to 15 do begin
     State.s[(i+State.p) and 15]:=t[i];
    end;
   end;
   function CMWC4096Next(var State:TRNLRandomGeneratorCMWC4096):TRNLUInt64; {$ifdef caninline}inline;{$endif}
   var x,t:TRNLUInt64;
   begin
    State.QJ:=(State.QJ+1) and high(State.Q);
    x:=State.Q[State.QJ];
    t:=(x shl 58)+State.QC;
    State.QC:=x shr 6;
    inc(t,x);
    if x<t then begin
     inc(State.QC);
    end;
    State.Q[State.QJ]:=t;
    result:=t;
   end;
  const CountStateQWords=(SizeOf(TRNLRandomGeneratorState) div SizeOf(TRNLUInt64));
  type PStateQWords=^TStateQWords;
       TStateQWords=array[0..CountStateQWords-1] of TRNLUInt64;
  var Index,Remain,ToDo:TRNLSizeUInt;
      UnixTimeInMilliSeconds:TRNLInt64;
      SplitMix64,Value:TRNLUInt64;
      State:PRNLRandomGeneratorState;
  begin
   GetMem(State,SizeOf(TRNLRandomGeneratorState));
   try
    FillChar(State^,SizeOf(TRNLRandomGeneratorState),#0);
    UnixTimeInMilliSeconds:=round((SysUtils.Now-25569.0)*86400000.0);
    SplitMix64:=TRNLUInt64(UnixTimeInMilliSeconds) xor TRNLUInt64(TRNLUInt64($7a5cde814c2a9d21){$ifdef Windows}+TRNLUInt64(GetTickCount64){$endif});
{$if defined(Windows)}
    QueryPerformanceFrequency(TRNLInt64(PStateQWords(TRNLPointer(State))^[0]));
    for Index:=1 to CountStateQWords-1 do begin
     QueryPerformanceCounter(TRNLInt64(PStateQWords(TRNLPointer(State))^[Index]));
    end;
{$else}
    for Index:=0 to CountStateQWords-1 do begin
     PStateQWords(TRNLPointer(State))^[Index]:=0;
    end;
{$ifend}
{$if defined(CPU386)or defined(CPUX64)}
    if x86_rdseed_support then begin
     for Index:=0 to CountStateQWords-1 do begin
      PStateQWords(TRNLPointer(State))^[Index]:=PStateQWords(TRNLPointer(State))^[Index] xor
                                                x86_rdseed_ui64;
     end;
    end else if x86_rdrand_support then begin
     for Index:=0 to CountStateQWords-1 do begin
      PStateQWords(TRNLPointer(State))^[Index]:=PStateQWords(TRNLPointer(State))^[Index] xor
                                                x86_rdrand_ui64;
     end;
    end;
{$ifend}
    for Index:=0 to CountStateQWords-1 do begin
     PStateQWords(TRNLPointer(State))^[Index]:=PStateQWords(TRNLPointer(State))^[Index] xor
                                               SplitMix64Next(SplitMix64);
    end;
    XorShift1024Jump(State^.XorShift1024);
    FillChar(aBuffer,aSize,#0);
    Index:=0;
    Remain:=aSize;
    while Remain>0 do begin
     if Remain<SizeOf(TRNLUInt64) then begin
      ToDo:=Remain;
     end else begin
      ToDo:=SizeOf(TRNLUInt64);
     end;
     Value:=(LCG64Next(State^.LCG64)+
             XorShift1024Next(State^.XorShift1024)+
             CMWC4096Next(State^.CMWC4096)) xor
            PCG32Next(State^.PCG32);
{$if defined(CPU386) or defined(CPUX64)}
     if x86_rdrand_support then begin
      Value:=Value xor x86_rdrand_ui64;
     end;
{$ifend}
     Move(Value,PRNLUInt8Array(TRNLPointer(@aBuffer))^[Index],ToDo);
     inc(Index,ToDo);
     dec(Remain,ToDo);
    end;
   finally
    FillChar(State^,SizeOf(TRNLRandomGeneratorState),#0);
    FreeMem(State);
   end;
   result:=true;
  end;
  function GUIDGetEntropyData(out aBuffer;const aSize:TRNLSizeUInt):boolean;
  var Index,Remain,ToDo:TRNLSizeUInt;
      Value:TGUID;
{$if not (defined(Windows) or defined(fpc))}
      OK:boolean;
      fs:TFileStream;
      s:TRNLRawByteString;
{$ifend}
  begin
   FillChar(aBuffer,aSize,#0);
   Index:=0;
   Remain:=aSize;
   while Remain>0 do begin
    if Remain<SizeOf(TGUID) then begin
     ToDo:=Remain;
    end else begin
     ToDo:=SizeOf(TGUID);
    end;
{$if defined(fpc)}
    // FPC's RTL is doing already the right thing
    CreateGUID(Value);
{$elseif defined(Windows)}
    CoCreateGUID(Value);
{$else}
    OK:=false;
    if (not OK) and FileExists('/proc/sys/kernel/random/uuid') then begin
     try
      fs:=TFileStream.Create('/proc/sys/kernel/random/uuid',fmOpenRead or fmShareDenyNone);
      s:='';
      try
       SetLength(s,36);
       if fs.Read(s[1],36)=36 then begin
        Value:=StringToGUID('{'+s+'}');
        OK:=true;
       end;
      finally
       SetLength(s,0);
      end;
     except
     end;
    end;
    if not OK then begin
     CreateGUID(Value);
    end;
{$ifend}
    Move(Value,PRNLUInt8Array(TRNLPointer(@aBuffer))^[Index],ToDo);
    inc(Index,ToDo);
    dec(Remain,ToDo);
   end;
   result:=true;
  end;
 var TemporaryEntropyData:TRNLRandomGeneratorEntropyData;
  procedure MixEntropyData;
  var Index:TRNLSizeUInt;
  begin
   for Index:=0 to SizeOf(TRNLRandomGeneratorEntropyData)-1 do begin
    EntropyData[Index]:=EntropyData[Index] xor TemporaryEntropyData[Index];
   end;
  end;
 begin
  FillChar(EntropyData,SizeOf(TRNLRandomGeneratorEntropyData),#0);
  FillChar(TemporaryEntropyData,SizeOf(TRNLRandomGeneratorEntropyData),#0);
{$if defined(Windows)}
  if WindowsGetEntropyData(TemporaryEntropyData,SizeOf(TRNLRandomGeneratorEntropyData)) then begin
   MixEntropyData;
  end else begin
   if WindowsEnvironmentStringsGetEntropyData(TemporaryEntropyData,SizeOf(TRNLRandomGeneratorEntropyData)) then begin
    MixEntropyData;
   end;
   if WindowsCommandLineGetEntropyData(TemporaryEntropyData,SizeOf(TRNLRandomGeneratorEntropyData)) then begin
    MixEntropyData;
   end;
   if GUIDGetEntropyData(TemporaryEntropyData,SizeOf(TRNLRandomGeneratorEntropyData)) then begin
    MixEntropyData;
   end;
  end;
{$elseif defined(Unix) or defined(Posix)}
  if PosixGetEntropyData(TemporaryEntropyData,SizeOf(TRNLRandomGeneratorEntropyData)) then begin
   MixEntropyData;
  end;
  if GUIDGetEntropyData(TemporaryEntropyData,SizeOf(TRNLRandomGeneratorEntropyData)) then begin
   MixEntropyData;
  end;
{$else}
  if GUIDGetEntropyData(TemporaryEntropyData,SizeOf(TRNLRandomGeneratorEntropyData)) then begin
   MixEntropyData;
  end;
{$ifend}
  if GetAdditionalEntropyData(TemporaryEntropyData,SizeOf(TRNLRandomGeneratorEntropyData)) then begin
   MixEntropyData;
  end;
  FillChar(TemporaryEntropyData,SizeOf(TRNLRandomGeneratorEntropyData),#0);
 end;
begin
 EntropyData[0]:=0;
 GetEntropyData;
 if not fInitialized then begin
  fInitialized:=true;
  Initialize(EntropyData,SizeOf(TRNLRandomGeneratorEntropyData));
 end else begin
  Rekey(EntropyData,SizeOf(TRNLRandomGeneratorEntropyData));
 end;
 FillChar(EntropyData,SizeOf(TRNLRandomGeneratorEntropyData),#0);
 FillChar(fBuffer,SizeOf(TRNLRandomGeneratorBuffer),#0);
 fPosition:=SizeOf(TRNLRandomGeneratorSeed);
 fHave:=0;
 fCount:=1600000;
end;

procedure TRNLRandomGenerator.ReseedIfNeeded(const aCount:TRNLSizeUInt);
begin
 if (fCount<=aCount) or not fInitialized then begin
  Reseed;
 end;
 if fCount<=aCount then begin
  fCount:=0;
 end else begin
  dec(fCount,aCount);
 end;
end;

procedure TRNLRandomGenerator.GetRandomBytes(out aLocation;const aCount:TRNLSizeUInt);
var Index,Remain,ToDo:TRNLSizeUInt;
begin
 ReseedIfNeeded(aCount);
 Index:=0;
 Remain:=aCount;
 while Remain>0 do begin
  if fHave>0 then begin
   if Remain<fHave then begin
    ToDo:=Remain;
   end else begin
    ToDo:=fHave;
   end;
   Move(PRNLUInt8Array(TRNLPointer(@fBuffer))^[fPosition],
        PRNLUInt8Array(TRNLPointer(@aLocation))^[Index],
        ToDo);
   inc(fPosition,ToDo);
   dec(fHave,ToDo);
   inc(Index,ToDo);
   dec(Remain,ToDo);
  end;
  if fHave=0 then begin
   Rekey(TRNLPointer(nil)^,0);
  end;
 end;
end;

function TRNLRandomGenerator.GetUInt32:TRNLUInt32;
begin
 GetRandomBytes(result,SizeOf(TRNLUInt32));
end;

function TRNLRandomGenerator.GetUInt64:TRNLUInt64;
begin
 GetRandomBytes(result,SizeOf(TRNLUInt64));
end;

function TRNLRandomGenerator.GetBoundedUInt32(const aBound:TRNLUInt32):TRNLUInt32;
begin
 if (aBound and TRNLUInt32($ffff0000))=0 then begin
  result:=((GetUInt32 shr 16)*aBound) shr 16;
 end else begin
  result:=(TRNLUInt64(GetUInt32)*aBound) shr 32;
 end;
end;

function TRNLRandomGenerator.GetUniformBoundedUInt32(const aBound:TRNLUInt32):TRNLUInt32;
var Minimum:TRNLUInt32;
begin
 if aBound>1 then begin
  Minimum:=TRNLUInt64($100000000) mod aBound;
  repeat
   result:=GetUInt32;
  until result>=Minimum;
  result:=result mod aBound;
 end else begin
  result:=0;
 end;
end;

function TRNLRandomGenerator.GetFloat:single; // -1.0 .. 1.0
var t:TRNLUInt32;
begin
 t:=GetUInt32;
 t:=(((t shr 9) and $7fffff)+((t shr 8) and 1)) or $40000000;
 result:=single(TRNLPointer(@t)^)-3.0;
end;

function TRNLRandomGenerator.GetAbsoluteFloat:single; // 0.0 .. 1.0
var t:TRNLUInt32;
begin
 t:=GetUInt32;
 t:=(((t shr 10) and $3fffff)+((t shr 9) and 1)) or $40000000;
 result:=single(TRNLPointer(@t)^)-2.0;
end;

function TRNLRandomGenerator.GetDouble:double; // -1.0 .. 1.0
var t:TRNLUInt64;
begin
 t:=GetUInt64;
 t:=(((t shr 12) and $fffffffffffff)+((t shr 11) and 1)) or $4000000000000000;
 result:=double(TRNLPointer(@t)^)-3.0;
end;

function TRNLRandomGenerator.GetAbsoluteDouble:double; // 0.0 .. 1.0
var t:int64;
begin
 t:=GetUInt64;
 t:=(((t shr 13) and $7ffffffffffff)+((t shr 12) and 1)) or $4000000000000000;
 result:=double(TRNLPointer(@t)^)-2.0;
end;

function TRNLRandomGenerator.GetGuassianFloat:single; // -1.0 .. 1.0
var x1,x2,w:single;
    i:TRNLUInt32;
begin
 if fGuassianFloatUseLast then begin
  fGuassianFloatUseLast:=false;
  result:=fGuassianFloatLast;
 end else begin
  i:=0;
  repeat
   x1:=GetFloat;
   x2:=GetFloat;
   w:=sqr(x1)+sqr(x2);
   inc(i);
  until ((i and $80000000)<>0) or (w<1.0);
  if (i and $80000000)<>0 then begin
   result:=x1;
   fGuassianFloatLast:=x2;
   fGuassianFloatUseLast:=true;
  end else if abs(w)<1e-18 then begin
   result:=0.0;
  end else begin
   w:=sqrt(((-2.0)*ln(w))/w);
   result:=x1*w;
   fGuassianFloatLast:=x2*w;
   fGuassianFloatUseLast:=true;
  end;
 end;
 if result<-1.0 then begin
  result:=-1.0;
 end else if result>1.0 then begin
  result:=1.0;
 end;
end;

function TRNLRandomGenerator.GetAbsoluteGuassianFloat:single; // 0.0 .. 1.0
begin
 result:=(GetGuassianFloat+1.0)*0.5;
 if result<0.0 then begin
  result:=0.0;
 end else if result>1.0 then begin
  result:=1.0;
 end;
end;

function TRNLRandomGenerator.GetGuassianDouble:double; // -1.0 .. 1.0
var x1,x2,w:double;
    i:TRNLUInt32;
begin
 if fGuassianDoubleUseLast then begin
  fGuassianDoubleUseLast:=false;
  result:=fGuassianDoubleLast;
 end else begin
  i:=0;
  repeat
   x1:=GetDouble;
   x2:=GetDouble;
   w:=sqr(x1)+sqr(x2);
   inc(i);
  until ((i and $80000000)<>0) or (w<1.0);
  if (i and $80000000)<>0 then begin
   result:=x1;
   fGuassianDoubleLast:=x2;
   fGuassianDoubleUseLast:=true;
  end else if abs(w)<1e-18 then begin
   result:=0.0;
  end else begin
   w:=sqrt(((-2.0)*ln(w))/w);
   result:=x1*w;
   fGuassianDoubleLast:=x2*w;
   fGuassianDoubleUseLast:=true;
  end;
 end;
 if result<-1.0 then begin
  result:=-1.0;
 end else if result>1.0 then begin
  result:=1.0;
 end;
end;

function TRNLRandomGenerator.GetAbsoluteGuassianDouble:double; // 0.0 .. 1.0
begin
 result:=(GetGuassianDouble+1.0)*0.5;
 if result<0.0 then begin
  result:=0.0;
 end else if result>1.0 then begin
  result:=1.0;
 end;
end;

function TRNLRandomGenerator.GetGuassian(const aBound:TRNLUInt32):TRNLUInt32;
begin
 result:=round(GetAbsoluteGuassianDouble*(aBound-0.98725));
end;

class operator TRNLTime.Implicit(const a:TRNLUInt64):TRNLTime;
begin
 result.fValue:=a;
end;

class operator TRNLTime.Explicit(const a:TRNLUInt64):TRNLTime;
begin
 result.fValue:=a;
end;

class operator TRNLTime.Implicit(const a:TRNLTime):TRNLUInt64;
begin
 result:=a.fValue;
end;

class operator TRNLTime.Explicit(const a:TRNLTime):TRNLUInt64;
begin
 result:=a.fValue;
end;

class operator TRNLTime.Equal(const a,b:TRNLTime):boolean;
begin
 result:=a.fValue=b.fValue;
end;

class operator TRNLTime.NotEqual(const a,b:TRNLTime):boolean;
begin
 result:=a.fValue<>b.fValue;
end;

class operator TRNLTime.GreaterThan(const a,b:TRNLTime):boolean;
var t:TRNLInt64;
begin
 t:=b.fValue-a.fValue;
 result:=(t<0) or (t>=RNL_TIME_OVERFLOW);
end;

class operator TRNLTime.GreaterThanOrEqual(const a,b:TRNLTime):boolean;
var t:TRNLInt64;
begin
 t:=a.fValue-b.fValue;
 result:=not ((t<0) or (t>=RNL_TIME_OVERFLOW));
end;

class operator TRNLTime.LessThan(const a,b:TRNLTime):boolean;
var t:TRNLInt64;
begin
 t:=a.fValue-b.fValue;
 result:=(t<0) or (t>=RNL_TIME_OVERFLOW);
end;

class operator TRNLTime.LessThanOrEqual(const a,b:TRNLTime):boolean;
var t:TRNLInt64;
begin
 t:=b.fValue-a.fValue;
 result:=not ((t<0) or (t>=RNL_TIME_OVERFLOW));
end;

class operator TRNLTime.Inc(const a:TRNLTime):TRNLTime;
begin
 result.fValue:=a.fValue+1;
end;

class operator TRNLTime.Dec(const a:TRNLTime):TRNLTime;
begin
 result.fValue:=a.fValue-1;
end;

class operator TRNLTime.LogicalNot(const a:TRNLTime):TRNLTime;
begin
 result.fValue:=not a.fValue;
end;

class operator TRNLTime.Add(const a,b:TRNLTime):TRNLTime;
begin
 result.fValue:=a.fValue+b.fValue;
end;

class operator TRNLTime.Add(const a:TRNLTime;const b:TRNLUInt64):TRNLUInt64;
begin
 result:=a.fValue+b;
end;

class operator TRNLTime.Add(const a:TRNLUInt64;const b:TRNLTime):TRNLUInt64;
begin
 result:=a+b.fValue;
end;

class operator TRNLTime.Subtract(const a,b:TRNLTime):TRNLTime;
begin
 result.fValue:=a.fValue-b.fValue;
end;

class operator TRNLTime.Subtract(const a:TRNLTime;const b:TRNLUInt64):TRNLUInt64;
begin
 result:=a.fValue-b;
end;

class operator TRNLTime.Subtract(const a:TRNLUInt64;const b:TRNLTime):TRNLUInt64;
begin
 result:=a-b.fValue;
end;

class operator TRNLTime.Multiply(const a,b:TRNLTime):TRNLTime;
begin
 result.fValue:=a.fValue*b.fValue;
end;

class operator TRNLTime.Multiply(const a:TRNLTime;const b:TRNLUInt64):TRNLUInt64;
begin
 result:=a.fValue*b;
end;

class operator TRNLTime.Multiply(const a:TRNLUInt64;const b:TRNLTime):TRNLUInt64;
begin
 result:=a*b.fValue;
end;

class operator TRNLTime.Divide(const a,b:TRNLTime):TRNLTime;
begin
 result.fValue:=a.fValue div b.fValue;
end;

class operator TRNLTime.Divide(const a:TRNLTime;const b:TRNLUInt64):TRNLUInt64;
begin
 result:=a.fValue div b;
end;

class operator TRNLTime.Divide(const a:TRNLUInt64;const b:TRNLTime):TRNLUInt64;
begin
 result:=a div b.fValue;
end;

class operator TRNLTime.IntDivide(const a,b:TRNLTime):TRNLTime;
begin
 result.fValue:=a.fValue div b.fValue;
end;

class operator TRNLTime.IntDivide(const a:TRNLTime;const b:TRNLUInt64):TRNLUInt64;
begin
 result:=a.fValue div b;
end;

class operator TRNLTime.IntDivide(const a:TRNLUInt64;const b:TRNLTime):TRNLUInt64;
begin
 result:=a div b.fValue;
end;

class operator TRNLTime.Modulus(const a,b:TRNLTime):TRNLTime;
begin
 result.fValue:=a.fValue mod b.fValue;
end;

class operator TRNLTime.LeftShift(const a:TRNLTime;const b:TRNLInt32):TRNLTime;
begin
 result.fValue:=a.fValue shl b;
end;

class operator TRNLTime.RightShift(const a:TRNLTime;const b:TRNLInt32):TRNLTime;
begin
 result.fValue:=a.fValue shr b;
end;

class operator TRNLTime.BitwiseAnd(const a,b:TRNLTime):TRNLTime;
begin
 result.fValue:=a.fValue and b.fValue;
end;

class operator TRNLTime.BitwiseOr(const a,b:TRNLTime):TRNLTime;
begin
 result.fValue:=a.fValue or b.fValue;
end;

class operator TRNLTime.BitwiseXor(const a,b:TRNLTime):TRNLTime;
begin
 result.fValue:=a.fValue xor b.fValue;
end;

class operator TRNLTime.Negative(const a:TRNLTime):TRNLTime;
begin
 result.fValue:=-a.fValue;
end;

class operator TRNLTime.Positive(const a:TRNLTime):TRNLTime;
begin
 result.fValue:=a.fValue;
end;

class function TRNLTime.RelativeDifference(const a,b:TRNLTime):TRNLInt64;
begin
 result:=TRNLInt64(TRNLUInt64(a.fValue-b.fValue));
end;

class function TRNLTime.Difference(const a,b:TRNLTime):TRNLInt64;
begin
 result:=a.fValue-b.fValue;
 if (result<0) or (result>=RNL_TIME_OVERFLOW) then begin
  result:=b.fValue-a.fValue;
 end;
end;

class function TRNLTime.Minimum(const a,b:TRNLTime):TRNLTime;
begin
 if a.fValue<b.fValue then begin
  result.fValue:=a.fValue;
 end else begin
  result.fValue:=b.fValue;
 end;
end;

class operator TRNLSequenceNumber.Implicit(const a:TRNLUInt16):TRNLSequenceNumber;
begin
 result.fValue:=a;
end;

class operator TRNLSequenceNumber.Explicit(const a:TRNLUInt16):TRNLSequenceNumber;
begin
 result.fValue:=a;
end;

class operator TRNLSequenceNumber.Implicit(const a:TRNLSequenceNumber):TRNLUInt16;
begin
 result:=a.fValue;
end;

class operator TRNLSequenceNumber.Explicit(const a:TRNLSequenceNumber):TRNLUInt16;
begin
 result:=a.fValue;
end;

class operator TRNLSequenceNumber.Equal(const a,b:TRNLSequenceNumber):boolean;
begin
 result:=a.fValue=b.fValue;
end;

class operator TRNLSequenceNumber.NotEqual(const a,b:TRNLSequenceNumber):boolean;
begin
 result:=a.fValue<>b.fValue;
end;

class operator TRNLSequenceNumber.GreaterThan(const a,b:TRNLSequenceNumber):boolean;
begin
{$if defined(CPU386) or defined(CPUX64)}
 result:=TRNLInt16(TRNLUInt16(a.fValue-b.fValue))>0;
{$else}
 result:=((((a.fValue-b.fValue)+32768) and $ffff)-32768)>0;
{$ifend}
end;

class operator TRNLSequenceNumber.GreaterThanOrEqual(const a,b:TRNLSequenceNumber):boolean;
begin
{$if defined(CPU386) or defined(CPUX64)}
 result:=TRNLInt16(TRNLUInt16(a.fValue-b.fValue))>=0;
{$else}
 result:=((((a.fValue-b.fValue)+32768) and $ffff)-32768)>=0;
{$ifend}
end;

class operator TRNLSequenceNumber.LessThan(const a,b:TRNLSequenceNumber):boolean;
begin
{$if defined(CPU386) or defined(CPUX64)}
 result:=TRNLInt16(TRNLUInt16(a.fValue-b.fValue))<0;
{$else}
 result:=((((a.fValue-b.fValue)+32768) and $ffff)-32768)<0;
{$ifend}
end;

class operator TRNLSequenceNumber.LessThanOrEqual(const a,b:TRNLSequenceNumber):boolean;
begin
{$if defined(CPU386) or defined(CPUX64)}
 result:=TRNLInt16(TRNLUInt16(a.fValue-b.fValue))<=0;
{$else}
 result:=((((a.fValue-b.fValue)+32768) and $ffff)-32768)<=0;
{$ifend}
end;

class operator TRNLSequenceNumber.Inc(const a:TRNLSequenceNumber):TRNLSequenceNumber;
begin
 result.fValue:=a.fValue+1;
end;

class operator TRNLSequenceNumber.Dec(const a:TRNLSequenceNumber):TRNLSequenceNumber;
begin
 result.fValue:=a.fValue-1;
end;

class operator TRNLSequenceNumber.LogicalNot(const a:TRNLSequenceNumber):TRNLSequenceNumber;
begin
 result.fValue:=not a.fValue;
end;

class operator TRNLSequenceNumber.Add(const a,b:TRNLSequenceNumber):TRNLSequenceNumber;
begin
 result.fValue:=a.fValue+b.fValue;
end;

class operator TRNLSequenceNumber.Add(const a:TRNLSequenceNumber;const b:TRNLUInt16):TRNLUInt16;
begin
 result:=a.fValue+b;
end;

class operator TRNLSequenceNumber.Add(const a:TRNLUInt16;const b:TRNLSequenceNumber):TRNLUInt16;
begin
 result:=a+b.fValue;
end;

class operator TRNLSequenceNumber.Subtract(const a,b:TRNLSequenceNumber):TRNLSequenceNumber;
begin
 result.fValue:=a.fValue-b.fValue;
end;

class operator TRNLSequenceNumber.Subtract(const a:TRNLSequenceNumber;const b:TRNLUInt16):TRNLUInt16;
begin
 result:=a.fValue-b;
end;

class operator TRNLSequenceNumber.Subtract(const a:TRNLUInt16;const b:TRNLSequenceNumber):TRNLUInt16;
begin
 result:=a-b.fValue;
end;

class operator TRNLSequenceNumber.Multiply(const a,b:TRNLSequenceNumber):TRNLSequenceNumber;
begin
 result.fValue:=a.fValue*b.fValue;
end;

class operator TRNLSequenceNumber.Multiply(const a:TRNLSequenceNumber;const b:TRNLUInt16):TRNLUInt16;
begin
 result:=a.fValue*b;
end;

class operator TRNLSequenceNumber.Multiply(const a:TRNLUInt16;const b:TRNLSequenceNumber):TRNLUInt16;
begin
 result:=a*b.fValue;
end;

class operator TRNLSequenceNumber.Divide(const a,b:TRNLSequenceNumber):TRNLSequenceNumber;
begin
 result.fValue:=a.fValue div b.fValue;
end;

class operator TRNLSequenceNumber.Divide(const a:TRNLSequenceNumber;const b:TRNLUInt16):TRNLUInt16;
begin
 result:=a.fValue div b;
end;

class operator TRNLSequenceNumber.Divide(const a:TRNLUInt16;const b:TRNLSequenceNumber):TRNLUInt16;
begin
 result:=a div b.fValue;
end;

class operator TRNLSequenceNumber.IntDivide(const a,b:TRNLSequenceNumber):TRNLSequenceNumber;
begin
 result.fValue:=a.fValue div b.fValue;
end;

class operator TRNLSequenceNumber.IntDivide(const a:TRNLSequenceNumber;const b:TRNLUInt16):TRNLUInt16;
begin
 result:=a.fValue div b;
end;

class operator TRNLSequenceNumber.IntDivide(const a:TRNLUInt16;const b:TRNLSequenceNumber):TRNLUInt16;
begin
 result:=a div b.fValue;
end;

class operator TRNLSequenceNumber.Modulus(const a,b:TRNLSequenceNumber):TRNLSequenceNumber;
begin
 result.fValue:=a.fValue mod b.fValue;
end;

class operator TRNLSequenceNumber.LeftShift(const a:TRNLSequenceNumber;const b:TRNLInt32):TRNLSequenceNumber;
begin
 result.fValue:=a.fValue shl b;
end;

class operator TRNLSequenceNumber.RightShift(const a:TRNLSequenceNumber;const b:TRNLInt32):TRNLSequenceNumber;
begin
 result.fValue:=a.fValue shr b;
end;

class operator TRNLSequenceNumber.BitwiseAnd(const a,b:TRNLSequenceNumber):TRNLSequenceNumber;
begin
 result.fValue:=a.fValue and b.fValue;
end;

class operator TRNLSequenceNumber.BitwiseOr(const a,b:TRNLSequenceNumber):TRNLSequenceNumber;
begin
 result.fValue:=a.fValue or b.fValue;
end;

class operator TRNLSequenceNumber.BitwiseXor(const a,b:TRNLSequenceNumber):TRNLSequenceNumber;
begin
 result.fValue:=a.fValue xor b.fValue;
end;

class operator TRNLSequenceNumber.Negative(const a:TRNLSequenceNumber):TRNLSequenceNumber;
begin
 result.fValue:=-a.fValue;
end;

class operator TRNLSequenceNumber.Positive(const a:TRNLSequenceNumber):TRNLSequenceNumber;
begin
 result.fValue:=a.fValue;
end;

class function TRNLSequenceNumber.RelativeDifference(const a,b:TRNLSequenceNumber):TRNLInt32;
begin
{$if defined(CPU386) or defined(CPUX64)}
 result:=TRNLInt16(TRNLUInt16(a.fValue-b.fValue));
{$else}
 result:=(((a.fValue-b.fValue)+32768) and $ffff)-32768;
{$ifend}
end;

class function TRNLSequenceNumber.Difference(const a,b:TRNLSequenceNumber):TRNLInt32;
begin
{$if defined(CPU386) or defined(CPUX64)}
 result:=abs(TRNLInt16(TRNLUInt16(a.fValue-b.fValue)));
{$else}
 result:=abs((((a.fValue-b.fValue)+32768) and $ffff)-32768);
{$ifend}
end;

class function TRNLSequenceNumber.Minimum(const a,b:TRNLSequenceNumber):TRNLSequenceNumber;
begin
 if a.fValue<b.fValue then begin
  result.fValue:=a.fValue;
 end else begin
  result.fValue:=b.fValue;
 end;
end;

class operator TRNLKey.Implicit(const a:TRNLUInt64):TRNLKey;
var Index:TRNLInt32;
begin
 for Index:=0 to 7 do begin
  result.ui8[Index]:=(a shr (Index shl 3)) and $ff;
 end;
 for Index:=8 to 31 do begin
  result.ui8[Index]:=0;
 end;
end;

class operator TRNLKey.Explicit(const a:TRNLUInt64):TRNLKey;
var Index:TRNLInt32;
begin
 for Index:=0 to 7 do begin
  result.ui8[Index]:=(a shr (Index shl 3)) and $ff;
 end;
 for Index:=8 to 31 do begin
  result.ui8[Index]:=0;
 end;
end;

class operator TRNLKey.Implicit(const a:TRNLKey):TRNLUInt64;
var Index:TRNLInt32;
begin
 result:=0;
 for Index:=0 to 7 do begin
  result:=result or (TRNLUInt64(a.ui8[Index]) shl (Index shl 3));
 end;
end;

class operator TRNLKey.Explicit(const a:TRNLKey):TRNLUInt64;
var Index:TRNLInt32;
begin
 result:=0;
 for Index:=0 to 7 do begin
  result:=result or (TRNLUInt64(a.ui8[Index]) shl (Index shl 3));
 end;
end;

class operator TRNLKey.Equal(const a,b:TRNLKey):boolean;
begin
 result:=(a.ui64[0]=b.ui64[0]) and
         (a.ui64[1]=b.ui64[1]) and
         (a.ui64[2]=b.ui64[2]) and
         (a.ui64[3]=b.ui64[3]);
end;

class operator TRNLKey.NotEqual(const a,b:TRNLKey):boolean;
begin
 result:=(a.ui64[0]<>b.ui64[0]) or
         (a.ui64[1]<>b.ui64[1]) or
         (a.ui64[2]<>b.ui64[2]) or
         (a.ui64[3]<>b.ui64[3]);
end;

function TRNLKey.ClampForCurve25519:TRNLKey;
begin
 result:=self;
 result.ui8[0]:=ui8[0] and $f8;
 result.ui8[31]:=(ui8[31] and $7f) or $40;
end;

class function TRNLKey.CreateRandom(const aRandomGenerator:TRNLRandomGenerator):TRNLKey;
var Index:TRNLInt32;
begin
 for Index:=0 to 31 do begin
  result.ui8[Index]:=aRandomGenerator.GetUInt32 and $ff;
 end;
 result:=result.ClampForCurve25519;
end;

constructor TRNLValue25519.Create(const aValue:TRNLInt32);
begin
 Limbs[0]:=aValue;
 Limbs[1]:=0;
 Limbs[2]:=0;
 Limbs[3]:=0;
 Limbs[4]:=0;
 Limbs[5]:=0;
 Limbs[6]:=0;
 Limbs[7]:=0;
 Limbs[8]:=0;
 Limbs[9]:=0;
end;

class operator TRNLValue25519.Implicit(const a:TRNLInt32):TRNLValue25519;
begin
 result.Limbs[0]:=a;
 result.Limbs[1]:=0;
 result.Limbs[2]:=0;
 result.Limbs[3]:=0;
 result.Limbs[4]:=0;
 result.Limbs[5]:=0;
 result.Limbs[6]:=0;
 result.Limbs[7]:=0;
 result.Limbs[8]:=0;
 result.Limbs[9]:=0;
end;

class operator TRNLValue25519.Explicit(const a:TRNLInt32):TRNLValue25519;
begin
 result.Limbs[0]:=a;
 result.Limbs[1]:=0;
 result.Limbs[2]:=0;
 result.Limbs[3]:=0;
 result.Limbs[4]:=0;
 result.Limbs[5]:=0;
 result.Limbs[6]:=0;
 result.Limbs[7]:=0;
 result.Limbs[8]:=0;
 result.Limbs[9]:=0;
end;

class operator TRNLValue25519.Add(const a,b:TRNLValue25519):TRNLValue25519;
begin
 result.Limbs[0]:=a.Limbs[0]+b.Limbs[0];
 result.Limbs[1]:=a.Limbs[1]+b.Limbs[1];
 result.Limbs[2]:=a.Limbs[2]+b.Limbs[2];
 result.Limbs[3]:=a.Limbs[3]+b.Limbs[3];
 result.Limbs[4]:=a.Limbs[4]+b.Limbs[4];
 result.Limbs[5]:=a.Limbs[5]+b.Limbs[5];
 result.Limbs[6]:=a.Limbs[6]+b.Limbs[6];
 result.Limbs[7]:=a.Limbs[7]+b.Limbs[7];
 result.Limbs[8]:=a.Limbs[8]+b.Limbs[8];
 result.Limbs[9]:=a.Limbs[9]+b.Limbs[9];
end;

class operator TRNLValue25519.Subtract(const a,b:TRNLValue25519):TRNLValue25519;
begin
 result.Limbs[0]:=a.Limbs[0]-b.Limbs[0];
 result.Limbs[1]:=a.Limbs[1]-b.Limbs[1];
 result.Limbs[2]:=a.Limbs[2]-b.Limbs[2];
 result.Limbs[3]:=a.Limbs[3]-b.Limbs[3];
 result.Limbs[4]:=a.Limbs[4]-b.Limbs[4];
 result.Limbs[5]:=a.Limbs[5]-b.Limbs[5];
 result.Limbs[6]:=a.Limbs[6]-b.Limbs[6];
 result.Limbs[7]:=a.Limbs[7]-b.Limbs[7];
 result.Limbs[8]:=a.Limbs[8]-b.Limbs[8];
 result.Limbs[9]:=a.Limbs[9]-b.Limbs[9];
end;

class operator TRNLValue25519.Multiply(const a,b:TRNLValue25519):TRNLValue25519;
var f0,f1,f2,f3,f4,f5,f6,f7,f8,f9,g0,g1,g2,g3,g4,g5,g6,g7,g8,g9,
    x1,x3,x5,x7,x9,y1,y2,y3,y4,y5,y6,y7,y8,y9:TRNLInt32;
    h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9:TRNLInt64;
begin
 f0:=a.Limbs[0];
 f1:=a.Limbs[1];
 f2:=a.Limbs[2];
 f3:=a.Limbs[3];
 f4:=a.Limbs[4];
 f5:=a.Limbs[5];
 f6:=a.Limbs[6];
 f7:=a.Limbs[7];
 f8:=a.Limbs[8];
 f9:=a.Limbs[9];
 g0:=b.Limbs[0];
 g1:=b.Limbs[1];
 g2:=b.Limbs[2];
 g3:=b.Limbs[3];
 g4:=b.Limbs[4];
 g5:=b.Limbs[5];
 g6:=b.Limbs[6];
 g7:=b.Limbs[7];
 g8:=b.Limbs[8];
 g9:=b.Limbs[9];
 x1:=f1*2;
 x3:=f3*2;
 x5:=f5*2;
 x7:=f7*2;
 x9:=f9*2;
 y1:=g1*19;
 y2:=g2*19;
 y3:=g3*19;
 y4:=g4*19;
 y5:=g5*19;
 y6:=g6*19;
 y7:=g7*19;
 y8:=g8*19;
 y9:=g9*19;
 h0:=(f0*TRNLInt64(g0))+(x1*TRNLInt64(y9))+(f2*TRNLInt64(y8))+(x3*TRNLInt64(y7))+(f4*TRNLInt64(y6))+(x5*TRNLInt64(y5))+(f6*TRNLInt64(y4))+(x7*TRNLInt64(y3))+(f8*TRNLInt64(y2))+(x9*TRNLInt64(y1));
 h1:=(f0*TRNLInt64(g1))+(f1*TRNLInt64(g0))+(f2*TRNLInt64(y9))+(f3*TRNLInt64(y8))+(f4*TRNLInt64(y7))+(f5*TRNLInt64(y6))+(f6*TRNLInt64(y5))+(f7*TRNLInt64(y4))+(f8*TRNLInt64(y3))+(f9*TRNLInt64(y2));
 h2:=(f0*TRNLInt64(g2))+(x1*TRNLInt64(g1))+(f2*TRNLInt64(g0))+(x3*TRNLInt64(y9))+(f4*TRNLInt64(y8))+(x5*TRNLInt64(y7))+(f6*TRNLInt64(y6))+(x7*TRNLInt64(y5))+(f8*TRNLInt64(y4))+(x9*TRNLInt64(y3));
 h3:=(f0*TRNLInt64(g3))+(f1*TRNLInt64(g2))+(f2*TRNLInt64(g1))+(f3*TRNLInt64(g0))+(f4*TRNLInt64(y9))+(f5*TRNLInt64(y8))+(f6*TRNLInt64(y7))+(f7*TRNLInt64(y6))+(f8*TRNLInt64(y5))+(f9*TRNLInt64(y4));
 h4:=(f0*TRNLInt64(g4))+(x1*TRNLInt64(g3))+(f2*TRNLInt64(g2))+(x3*TRNLInt64(g1))+(f4*TRNLInt64(g0))+(x5*TRNLInt64(y9))+(f6*TRNLInt64(y8))+(x7*TRNLInt64(y7))+(f8*TRNLInt64(y6))+(x9*TRNLInt64(y5));
 h5:=(f0*TRNLInt64(g5))+(f1*TRNLInt64(g4))+(f2*TRNLInt64(g3))+(f3*TRNLInt64(g2))+(f4*TRNLInt64(g1))+(f5*TRNLInt64(g0))+(f6*TRNLInt64(y9))+(f7*TRNLInt64(y8))+(f8*TRNLInt64(y7))+(f9*TRNLInt64(y6));
 h6:=(f0*TRNLInt64(g6))+(x1*TRNLInt64(g5))+(f2*TRNLInt64(g4))+(x3*TRNLInt64(g3))+(f4*TRNLInt64(g2))+(x5*TRNLInt64(g1))+(f6*TRNLInt64(g0))+(x7*TRNLInt64(y9))+(f8*TRNLInt64(y8))+(x9*TRNLInt64(y7));
 h7:=(f0*TRNLInt64(g7))+(f1*TRNLInt64(g6))+(f2*TRNLInt64(g5))+(f3*TRNLInt64(g4))+(f4*TRNLInt64(g3))+(f5*TRNLInt64(g2))+(f6*TRNLInt64(g1))+(f7*TRNLInt64(g0))+(f8*TRNLInt64(y9))+(f9*TRNLInt64(y8));
 h8:=(f0*TRNLInt64(g8))+(x1*TRNLInt64(g7))+(f2*TRNLInt64(g6))+(x3*TRNLInt64(g5))+(f4*TRNLInt64(g4))+(x5*TRNLInt64(g3))+(f6*TRNLInt64(g2))+(x7*TRNLInt64(g1))+(f8*TRNLInt64(g0))+(x9*TRNLInt64(y9));
 h9:=(f0*TRNLInt64(g9))+(f1*TRNLInt64(g8))+(f2*TRNLInt64(g7))+(f3*TRNLInt64(g6))+(f4*TRNLInt64(g5))+(f5*TRNLInt64(g4))+(f6*TRNLInt64(g3))+(f7*TRNLInt64(g2))+(f8*TRNLInt64(g1))+(f9*TRNLInt64(g0));
 c0:=SARInt64(h0+TRNLInt64(1 shl 25),26);
 inc(h1,c0);
 dec(h0,c0 shl 26);
 c4:=SARInt64(h4+TRNLInt64(1 shl 25),26);
 inc(h5,c4);
 dec(h4,c4 shl 26);
 c1:=SARInt64(h1+TRNLInt64(1 shl 24),25);
 inc(h2,c1);
 dec(h1,c1 shl 25);
 c5:=SARInt64(h5+TRNLInt64(1 shl 24),25);
 inc(h6,c5);
 dec(h5,c5 shl 25);
 c2:=SARInt64(h2+TRNLInt64(1 shl 25),26);
 inc(h3,c2);
 dec(h2,c2 shl 26);
 c6:=SARInt64(h6+TRNLInt64(1 shl 25),26);
 inc(h7,c6);
 dec(h6,c6 shl 26);
 c3:=SARInt64(h3+TRNLInt64(1 shl 24),25);
 inc(h4,c3);
 dec(h3,c3 shl 25);
 c7:=SARInt64(h7+TRNLInt64(1 shl 24),25);
 inc(h8,c7);
 dec(h7,c7 shl 25);
 c4:=SARInt64(h4+TRNLInt64(1 shl 25),26);
 inc(h5,c4);
 dec(h4,c4 shl 26);
 c8:=SARInt64(h8+TRNLInt64(1 shl 25),26);
 inc(h9,c8);
 dec(h8,c8 shl 26);
 c9:=SARInt64(h9+TRNLInt64(1 shl 24),25);
 inc(h0,c9*19);
 dec(h9,c9 shl 25);
 c0:=SARInt64(h0+TRNLInt64(1 shl 25),26);
 inc(h1,c0);
 dec(h0,c0 shl 26);
 result.Limbs[0]:=h0;
 result.Limbs[1]:=h1;
 result.Limbs[2]:=h2;
 result.Limbs[3]:=h3;
 result.Limbs[4]:=h4;
 result.Limbs[5]:=h5;
 result.Limbs[6]:=h6;
 result.Limbs[7]:=h7;
 result.Limbs[8]:=h8;
 result.Limbs[9]:=h9;
end;

class operator TRNLValue25519.Negative(const a:TRNLValue25519):TRNLValue25519;
begin
 result.Limbs[0]:=-a.Limbs[0];
 result.Limbs[1]:=-a.Limbs[1];
 result.Limbs[2]:=-a.Limbs[2];
 result.Limbs[3]:=-a.Limbs[3];
 result.Limbs[4]:=-a.Limbs[4];
 result.Limbs[5]:=-a.Limbs[5];
 result.Limbs[6]:=-a.Limbs[6];
 result.Limbs[7]:=-a.Limbs[7];
 result.Limbs[8]:=-a.Limbs[8];
 result.Limbs[9]:=-a.Limbs[9];
end;

class operator TRNLValue25519.Positive(const a:TRNLValue25519):TRNLValue25519;
begin
 result:=a;
end;

class operator TRNLValue25519.Equal(const a,b:TRNLValue25519):boolean;
begin
 result:=(a.Limbs[0]=b.Limbs[0]) and
         (a.Limbs[1]=b.Limbs[1]) and
         (a.Limbs[2]=b.Limbs[2]) and
         (a.Limbs[3]=b.Limbs[3]) and
         (a.Limbs[4]=b.Limbs[4]) and
         (a.Limbs[5]=b.Limbs[5]) and
         (a.Limbs[6]=b.Limbs[6]) and
         (a.Limbs[7]=b.Limbs[7]) and
         (a.Limbs[8]=b.Limbs[8]) and
         (a.Limbs[9]=b.Limbs[9]);
end;

class operator TRNLValue25519.NotEqual(const a,b:TRNLValue25519):boolean;
begin
 result:=(a.Limbs[0]<>b.Limbs[0]) or
         (a.Limbs[1]<>b.Limbs[1]) or
         (a.Limbs[2]<>b.Limbs[2]) or
         (a.Limbs[3]<>b.Limbs[3]) or
         (a.Limbs[4]<>b.Limbs[4]) or
         (a.Limbs[5]<>b.Limbs[5]) or
         (a.Limbs[6]<>b.Limbs[6]) or
         (a.Limbs[7]<>b.Limbs[7]) or
         (a.Limbs[8]<>b.Limbs[8]) or
         (a.Limbs[9]<>b.Limbs[9]);
end;

function TRNLValue25519.Square:TRNLValue25519;
var f0,f1,f2,f3,f4,f5,f6,f7,f8,f9,f0_2,f1_2,f2_2,f3_2,f4_2,f5_2,f6_2,f7_2,
    f5_38,f6_19,f7_38,f8_19,f9_38:TRNLInt32;
    h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9:TRNLInt64;
begin
 f0:=Limbs[0];
 f1:=Limbs[1];
 f2:=Limbs[2];
 f3:=Limbs[3];
 f4:=Limbs[4];
 f5:=Limbs[5];
 f6:=Limbs[6];
 f7:=Limbs[7];
 f8:=Limbs[8];
 f9:=Limbs[9];
 f0_2:=f0*2;
 f1_2:=f1*2;
 f2_2:=f2*2;
 f3_2:=f3*2;
 f4_2:=f4*2;
 f5_2:=f5*2;
 f6_2:=f6*2;
 f7_2:=f7*2;
 f5_38:=f5*38;
 f6_19:=f6*19;
 f7_38:=f7*38;
 f8_19:=f8*19;
 f9_38:=f9*38;
 h0:=(f0*TRNLInt64(f0))+(f1_2*TRNLInt64(f9_38))+(f2_2*TRNLInt64(f8_19))+(f3_2*TRNLInt64(f7_38))+(f4_2*TRNLInt64(f6_19))+(f5*TRNLInt64(f5_38));
 h1:=(f0_2*TRNLInt64(f1))+(f2*TRNLInt64(f9_38))+(f3_2*TRNLInt64(f8_19))+(f4*TRNLInt64(f7_38))+(f5_2*TRNLInt64(f6_19));
 h2:=(f0_2*TRNLInt64(f2))+(f1_2*TRNLInt64(f1))+(f3_2*TRNLInt64(f9_38))+(f4_2*TRNLInt64(f8_19))+(f5_2*TRNLInt64(f7_38))+(f6*TRNLInt64(f6_19));
 h3:=(f0_2*TRNLInt64(f3))+(f1_2*TRNLInt64(f2))+(f4*TRNLInt64(f9_38))+(f5_2*TRNLInt64(f8_19))+(f6*TRNLInt64(f7_38));
 h4:=(f0_2*TRNLInt64(f4))+(f1_2*TRNLInt64(f3_2))+(f2*TRNLInt64(f2))+(f5_2*TRNLInt64(f9_38))+(f6_2*TRNLInt64(f8_19))+(f7*TRNLInt64(f7_38));
 h5:=(f0_2*TRNLInt64(f5))+(f1_2*TRNLInt64(f4))+(f2_2*TRNLInt64(f3))+(f6*TRNLInt64(f9_38))+(f7_2*TRNLInt64(f8_19));
 h6:=(f0_2*TRNLInt64(f6))+(f1_2*TRNLInt64(f5_2))+(f2_2*TRNLInt64(f4))+(f3_2*TRNLInt64(f3))+(f7_2*TRNLInt64(f9_38))+(f8*TRNLInt64(f8_19));
 h7:=(f0_2*TRNLInt64(f7))+(f1_2*TRNLInt64(f6))+(f2_2*TRNLInt64(f5))+(f3_2*TRNLInt64(f4))+(f8*TRNLInt64(f9_38));
 h8:=(f0_2*TRNLInt64(f8))+(f1_2*TRNLInt64(f7_2))+(f2_2*TRNLInt64(f6))+(f3_2*TRNLInt64(f5_2))+(f4*TRNLInt64(f4))+(f9*TRNLInt64(f9_38));
 h9:=(f0_2*TRNLInt64(f9))+(f1_2*TRNLInt64(f8))+(f2_2*TRNLInt64(f7))+(f3_2*TRNLInt64(f6))+(f4*TRNLInt64(f5_2));
 c0:=SARInt64(h0+TRNLInt64(1 shl 25),26);
 inc(h1,c0);
 dec(h0,c0 shl 26);
 c4:=SARInt64(h4+TRNLInt64(1 shl 25),26);
 inc(h5,c4);
 dec(h4,c4 shl 26);
 c1:=SARInt64(h1+TRNLInt64(1 shl 24),25);
 inc(h2,c1);
 dec(h1,c1 shl 25);
 c5:=SARInt64(h5+TRNLInt64(1 shl 24),25);
 inc(h6,c5);
 dec(h5,c5 shl 25);
 c2:=SARInt64(h2+TRNLInt64(1 shl 25),26);
 inc(h3,c2);
 dec(h2,c2 shl 26);
 c6:=SARInt64(h6+TRNLInt64(1 shl 25),26);
 inc(h7,c6);
 dec(h6,c6 shl 26);
 c3:=SARInt64(h3+TRNLInt64(1 shl 24),25);
 inc(h4,c3);
 dec(h3,c3 shl 25);
 c7:=SARInt64(h7+TRNLInt64(1 shl 24),25);
 inc(h8,c7);
 dec(h7,c7 shl 25);
 c4:=SARInt64(h4+TRNLInt64(1 shl 25),26);
 inc(h5,c4);
 dec(h4,c4 shl 26);
 c8:=SARInt64(h8+TRNLInt64(1 shl 25),26);
 inc(h9,c8);
 dec(h8,c8 shl 26);
 c9:=SARInt64(h9+TRNLInt64(1 shl 24),25);
 inc(h0,c9*19);
 dec(h9,c9 shl 25);
 c0:=SARInt64(h0+TRNLInt64(1 shl 25),26);
 inc(h1,c0);
 dec(h0,c0 shl 26);
 result.Limbs[0]:=h0;
 result.Limbs[1]:=h1;
 result.Limbs[2]:=h2;
 result.Limbs[3]:=h3;
 result.Limbs[4]:=h4;
 result.Limbs[5]:=h5;
 result.Limbs[6]:=h6;
 result.Limbs[7]:=h7;
 result.Limbs[8]:=h8;
 result.Limbs[9]:=h9;
end;

function TRNLValue25519.Square(const aCount:TRNLInt32):TRNLValue25519;
var i:TRNLInt32;
begin
 if aCount>0 then begin
  result:=Square;
  if aCount>1 then begin
   for i:=1 to aCount do begin
    result:=result.Square;
   end;
  end;
 end else begin
  result:=self;
 end;
end;

class procedure TRNLValue25519.ConditionalSwap(var a,b:TRNLValue25519;const aSelect:TRNLInt32);
var x,m,i:TRNLInt32;
begin
 m:=-(aSelect and 1);
 for i:=0 to 9 do begin
  x:=(a.Limbs[i] xor b.Limbs[i]) and m;
  a.Limbs[i]:=a.Limbs[i] xor x;
  b.Limbs[i]:=b.Limbs[i] xor x;
 end;
end;

function TRNLValue25519.Carry:TRNLValue25519;
var c0,c1,c2,c3,c4,c5,c6,c7,c8,c9:TRNLInt64;
begin
 result:=self;
 c9:=SARInt64(result.Limbs[9]+TRNLInt64(1 shl 24),25);
 inc(result.Limbs[0],c9*19);
 dec(result.Limbs[9],c9 shl 25);
 c1:=SARInt64(result.Limbs[1]+TRNLInt64(1 shl 24),25);
 inc(result.Limbs[2],c1);
 dec(result.Limbs[1],c1 shl 25);
 c3:=SARInt64(result.Limbs[3]+TRNLInt64(1 shl 24),25);
 inc(result.Limbs[4],c3);
 dec(result.Limbs[3],c3 shl 25);
 c5:=SARInt64(result.Limbs[5]+TRNLInt64(1 shl 24),25);
 inc(result.Limbs[6],c5);
 dec(result.Limbs[5],c5 shl 25);
 c7:=SARInt64(result.Limbs[7]+TRNLInt64(1 shl 24),25);
 inc(result.Limbs[8],c7);
 dec(result.Limbs[7],c7 shl 25);
 c0:=SARInt64(result.Limbs[0]+TRNLInt64(1 shl 25),26);
 inc(result.Limbs[1],c0);
 dec(result.Limbs[0],c0 shl 26);
 c2:=SARInt64(result.Limbs[2]+TRNLInt64(1 shl 25),26);
 inc(result.Limbs[3],c2);
 dec(result.Limbs[2],c2 shl 26);
 c4:=SARInt64(result.Limbs[4]+TRNLInt64(1 shl 25),26);
 inc(result.Limbs[5],c4);
 dec(result.Limbs[4],c4 shl 26);
 c6:=SARInt64(result.Limbs[6]+TRNLInt64(1 shl 25),26);
 inc(result.Limbs[7],c6);
 dec(result.Limbs[6],c6 shl 26);
 c8:=SARInt64(result.Limbs[8]+TRNLInt64(1 shl 25),26);
 inc(result.Limbs[9],c8);
 dec(result.Limbs[8],c8 shl 26);
end;

class function TRNLValue25519.Carry64(const aValue:TRNLValue2551964):TRNLValue25519;
var c0,c1,c2,c3,c4,c5,c6,c7,c8,c9:TRNLInt64;
    Value:TRNLValue2551964;
begin
 Value:=aValue;
 c9:=SARInt64(Value.Limbs[9]+TRNLInt64(1 shl 24),25);
 inc(Value.Limbs[0],c9*19);
 dec(Value.Limbs[9],c9 shl 25);
 c1:=SARInt64(Value.Limbs[1]+TRNLInt64(1 shl 24),25);
 inc(Value.Limbs[2],c1);
 dec(Value.Limbs[1],c1 shl 25);
 c3:=SARInt64(Value.Limbs[3]+TRNLInt64(1 shl 24),25);
 inc(Value.Limbs[4],c3);
 dec(Value.Limbs[3],c3 shl 25);
 c5:=SARInt64(Value.Limbs[5]+TRNLInt64(1 shl 24),25);
 inc(Value.Limbs[6],c5);
 dec(Value.Limbs[5],c5 shl 25);
 c7:=SARInt64(Value.Limbs[7]+TRNLInt64(1 shl 24),25);
 inc(Value.Limbs[8],c7);
 dec(Value.Limbs[7],c7 shl 25);
 c0:=SARInt64(Value.Limbs[0]+TRNLInt64(1 shl 25),26);
 inc(Value.Limbs[1],c0);
 dec(Value.Limbs[0],c0 shl 26);
 c2:=SARInt64(Value.Limbs[2]+TRNLInt64(1 shl 25),26);
 inc(Value.Limbs[3],c2);
 dec(Value.Limbs[2],c2 shl 26);
 c4:=SARInt64(Value.Limbs[4]+TRNLInt64(1 shl 25),26);
 inc(Value.Limbs[5],c4);
 dec(Value.Limbs[4],c4 shl 26);
 c6:=SARInt64(Value.Limbs[6]+TRNLInt64(1 shl 25),26);
 inc(Value.Limbs[7],c6);
 dec(Value.Limbs[6],c6 shl 26);
 c8:=SARInt64(Value.Limbs[8]+TRNLInt64(1 shl 25),26);
 inc(Value.Limbs[9],c8);
 dec(Value.Limbs[8],c8 shl 26);
 result.Limbs[0]:=Value.Limbs[0];
 result.Limbs[1]:=Value.Limbs[1];
 result.Limbs[2]:=Value.Limbs[2];
 result.Limbs[3]:=Value.Limbs[3];
 result.Limbs[4]:=Value.Limbs[4];
 result.Limbs[5]:=Value.Limbs[5];
 result.Limbs[6]:=Value.Limbs[6];
 result.Limbs[7]:=Value.Limbs[7];
 result.Limbs[8]:=Value.Limbs[8];
 result.Limbs[9]:=Value.Limbs[9];
end;

class function TRNLValue25519.CreateRandom(const aRandomGenerator:TRNLRandomGenerator):TRNLValue25519;
var Value:TRNLValue2551964;
begin
 Value.Limbs[0]:=aRandomGenerator.GetUInt32 and $7fffffff;
 Value.Limbs[1]:=aRandomGenerator.GetUInt32 and $7fffffff;
 Value.Limbs[2]:=aRandomGenerator.GetUInt32 and $7fffffff;
 Value.Limbs[3]:=aRandomGenerator.GetUInt32 and $7fffffff;
 Value.Limbs[4]:=aRandomGenerator.GetUInt32 and $7fffffff;
 Value.Limbs[5]:=aRandomGenerator.GetUInt32 and $7fffffff;
 Value.Limbs[6]:=aRandomGenerator.GetUInt32 and $7fffffff;
 Value.Limbs[7]:=aRandomGenerator.GetUInt32 and $7fffffff;
 Value.Limbs[8]:=aRandomGenerator.GetUInt32 and $7fffffff;
 Value.Limbs[9]:=aRandomGenerator.GetUInt32 and $7fffffff;
 result:=Carry64(Value);
end;

class function TRNLValue25519.LoadFromMemory(const aLocation):TRNLValue25519;
var Value:TRNLValue2551964;
begin
 Value.Limbs[0]:=TRNLInt64(TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt8Array(TRNLPointer(@aLocation))^[0]));
 Value.Limbs[1]:=TRNLInt64(TRNLMemoryAccess.LoadLittleEndianUInt24(PRNLUInt8Array(TRNLPointer(@aLocation))^[4])) shl 6;
 Value.Limbs[2]:=TRNLInt64(TRNLMemoryAccess.LoadLittleEndianUInt24(PRNLUInt8Array(TRNLPointer(@aLocation))^[7])) shl 5;
 Value.Limbs[3]:=TRNLInt64(TRNLMemoryAccess.LoadLittleEndianUInt24(PRNLUInt8Array(TRNLPointer(@aLocation))^[10])) shl 3;
 Value.Limbs[4]:=TRNLInt64(TRNLMemoryAccess.LoadLittleEndianUInt24(PRNLUInt8Array(TRNLPointer(@aLocation))^[13])) shl 2;
 Value.Limbs[5]:=TRNLInt64(TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt8Array(TRNLPointer(@aLocation))^[16]));
 Value.Limbs[6]:=TRNLInt64(TRNLMemoryAccess.LoadLittleEndianUInt24(PRNLUInt8Array(TRNLPointer(@aLocation))^[20])) shl 7;
 Value.Limbs[7]:=TRNLInt64(TRNLMemoryAccess.LoadLittleEndianUInt24(PRNLUInt8Array(TRNLPointer(@aLocation))^[23])) shl 5;
 Value.Limbs[8]:=TRNLInt64(TRNLMemoryAccess.LoadLittleEndianUInt24(PRNLUInt8Array(TRNLPointer(@aLocation))^[26])) shl 4;
 Value.Limbs[9]:=TRNLInt64(TRNLMemoryAccess.LoadLittleEndianUInt24(PRNLUInt8Array(TRNLPointer(@aLocation))^[29]) and $7fffff) shl 2;
 result:=Carry64(Value);
end;

procedure TRNLValue25519.SaveToMemory(out aLocation);
var t:TRNLValue25519;
    q,i,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9:TRNLInt32;
begin
 t:=self;
 q:=SARLongint((19*t.Limbs[9])+(1 shl 24),25);
 for i:=0 to 4 do begin
  q:=SARLongint(SARLongint(q+t.Limbs[(i shl 1) or 0],26)+t.Limbs[(i shl 1) or 1],25);
 end;
 inc(t.Limbs[0],19*q);
 c0:=SARLongint(t.Limbs[0],26);
 inc(t.Limbs[1],c0);
 dec(t.Limbs[0],c0 shl 26);
 c1:=SARLongint(t.Limbs[1],25);
 inc(t.Limbs[2],c1);
 dec(t.Limbs[1],c1 shl 25);
 c2:=SARLongint(t.Limbs[2],26);
 inc(t.Limbs[3],c2);
 dec(t.Limbs[2],c2 shl 26);
 c3:=SARLongint(t.Limbs[3],25);
 inc(t.Limbs[4],c3);
 dec(t.Limbs[3],c3 shl 25);
 c4:=SARLongint(t.Limbs[4],26);
 inc(t.Limbs[5],c4);
 dec(t.Limbs[4],c4 shl 26);
 c5:=SARLongint(t.Limbs[5],25);
 inc(t.Limbs[6],c5);
 dec(t.Limbs[5],c5 shl 25);
 c6:=SARLongint(t.Limbs[6],26);
 inc(t.Limbs[7],c6);
 dec(t.Limbs[6],c6 shl 26);
 c7:=SARLongint(t.Limbs[7],25);
 inc(t.Limbs[8],c7);
 dec(t.Limbs[7],c7 shl 25);
 c8:=SARLongint(t.Limbs[8],26);
 inc(t.Limbs[9],c8);
 dec(t.Limbs[8],c8 shl 26);
 c9:=SARLongint(t.Limbs[9],25);
 dec(t.Limbs[9],c9 shl 25);
 TRNLMemoryAccess.StoreLittleEndianUInt32(PRNLUInt8Array(TRNLPointer(@aLocation))^[0],(TRNLUInt32(t.Limbs[0]) shr 0) or (TRNLUInt32(t.Limbs[1]) shl 26));
 TRNLMemoryAccess.StoreLittleEndianUInt32(PRNLUInt8Array(TRNLPointer(@aLocation))^[4],(TRNLUInt32(t.Limbs[1]) shr 6) or (TRNLUInt32(t.Limbs[2]) shl 19));
 TRNLMemoryAccess.StoreLittleEndianUInt32(PRNLUInt8Array(TRNLPointer(@aLocation))^[8],(TRNLUInt32(t.Limbs[2]) shr 13) or (TRNLUInt32(t.Limbs[3]) shl 13));
 TRNLMemoryAccess.StoreLittleEndianUInt32(PRNLUInt8Array(TRNLPointer(@aLocation))^[12],(TRNLUInt32(t.Limbs[3]) shr 19) or (TRNLUInt32(t.Limbs[4]) shl 6));
 TRNLMemoryAccess.StoreLittleEndianUInt32(PRNLUInt8Array(TRNLPointer(@aLocation))^[16],(TRNLUInt32(t.Limbs[5]) shr 0) or (TRNLUInt32(t.Limbs[6]) shl 25));
 TRNLMemoryAccess.StoreLittleEndianUInt32(PRNLUInt8Array(TRNLPointer(@aLocation))^[20],(TRNLUInt32(t.Limbs[6]) shr 7) or (TRNLUInt32(t.Limbs[7]) shl 19));
 TRNLMemoryAccess.StoreLittleEndianUInt32(PRNLUInt8Array(TRNLPointer(@aLocation))^[24],(TRNLUInt32(t.Limbs[7]) shr 13) or (TRNLUInt32(t.Limbs[8]) shl 12));
 TRNLMemoryAccess.StoreLittleEndianUInt32(PRNLUInt8Array(TRNLPointer(@aLocation))^[28],(TRNLUInt32(t.Limbs[8]) shr 20) or (TRNLUInt32(t.Limbs[9]) shl 6));
end;

class operator TRNLValue25519.Multiply(const a:TRNLValue25519;const b:TRNLInt32):TRNLValue25519;
var Value:TRNLValue2551964;
begin
 Value.Limbs[0]:=a.Limbs[0]*TRNLInt64(b);
 Value.Limbs[1]:=a.Limbs[1]*TRNLInt64(b);
 Value.Limbs[2]:=a.Limbs[2]*TRNLInt64(b);
 Value.Limbs[3]:=a.Limbs[3]*TRNLInt64(b);
 Value.Limbs[4]:=a.Limbs[4]*TRNLInt64(b);
 Value.Limbs[5]:=a.Limbs[5]*TRNLInt64(b);
 Value.Limbs[6]:=a.Limbs[6]*TRNLInt64(b);
 Value.Limbs[7]:=a.Limbs[7]*TRNLInt64(b);
 Value.Limbs[8]:=a.Limbs[8]*TRNLInt64(b);
 Value.Limbs[9]:=a.Limbs[9]*TRNLInt64(b);
 result:=Carry64(Value);
end;

function TRNLValue25519.Mul121666:TRNLValue25519;
var Value:TRNLValue2551964;
begin
 Value.Limbs[0]:=Limbs[0]*TRNLInt64(121666);
 Value.Limbs[1]:=Limbs[1]*TRNLInt64(121666);
 Value.Limbs[2]:=Limbs[2]*TRNLInt64(121666);
 Value.Limbs[3]:=Limbs[3]*TRNLInt64(121666);
 Value.Limbs[4]:=Limbs[4]*TRNLInt64(121666);
 Value.Limbs[5]:=Limbs[5]*TRNLInt64(121666);
 Value.Limbs[6]:=Limbs[6]*TRNLInt64(121666);
 Value.Limbs[7]:=Limbs[7]*TRNLInt64(121666);
 Value.Limbs[8]:=Limbs[8]*TRNLInt64(121666);
 Value.Limbs[9]:=Limbs[9]*TRNLInt64(121666);
 result:=Carry64(Value);
end;

function TRNLValue25519.Mul973324:TRNLValue25519;
var Value:TRNLValue2551964;
begin
 Value.Limbs[0]:=Limbs[0]*TRNLInt64(973324);
 Value.Limbs[1]:=Limbs[1]*TRNLInt64(973324);
 Value.Limbs[2]:=Limbs[2]*TRNLInt64(973324);
 Value.Limbs[3]:=Limbs[3]*TRNLInt64(973324);
 Value.Limbs[4]:=Limbs[4]*TRNLInt64(973324);
 Value.Limbs[5]:=Limbs[5]*TRNLInt64(973324);
 Value.Limbs[6]:=Limbs[6]*TRNLInt64(973324);
 Value.Limbs[7]:=Limbs[7]*TRNLInt64(973324);
 Value.Limbs[8]:=Limbs[8]*TRNLInt64(973324);
 Value.Limbs[9]:=Limbs[9]*TRNLInt64(973324);
 result:=Carry64(Value);
end;

function TRNLValue25519.Invert:TRNLValue25519;
var t0,t1,t2,t3:TRNLValue25519;
    i:TRNLInt32;
begin
 t0:=self.Square;
 t1:=self*t0.Square.Square;
 t0:=t0*t1;
 t2:=t0.Square;
 t1:=t1*t2;
 t2:=t1.Square;
 for i:=2 to 5 do begin
  t2:=t2.Square;
 end;
 t1:=t2*t1;
 t2:=t1.Square;
 for i:=2 to 10 do begin
  t2:=t2.Square;
 end;
 t2:=t2*t1;
 t3:=t2.Square;
 for i:=2 to 20 do begin
  t3:=t3.Square;
 end;
 t2:=(t3*t2).Square;
 for i:=2 to 10 do begin
  t2:=t2.Square;
 end;
 t1:=t2*t1;
 t2:=t1.Square;
 for i:=2 to 50 do begin
  t2:=t2.Square;
 end;
 t2:=t2*t1;
 t3:=t2.Square;
 for i:=2 to 100 do begin
  t3:=t3.Square;
 end;
 t2:=(t3*t2).Square;
 for i:=2 to 50 do begin
  t2:=t2.Square;
 end;
 t1:=(t2*t1).Square;
 for i:=2 to 5 do begin
  t1:=t1.Square;
 end;
 result:=t1*t0;
end;

function TRNLValue25519.Pow22523:TRNLValue25519;
var t0,t1,t2:TRNLValue25519;
    i:TRNLInt32;
begin
 t0:=self.Square;
 t1:=self*t0.Square.Square;
 t0:=(t0*t1).Square;
 t0:=t1*t0;
 t1:=t0.Square;
 for i:=2 to 5 do begin
  t1:=t1.Square;
 end;
 t0:=t1*t0;
 t1:=t0.Square;
 for i:=2 to 10 do begin
  t1:=t1.Square;
 end;
 t1:=t1*t0;
 t2:=t1.Square;
 for i:=2 to 20 do begin
  t2:=t2.Square;
 end;
 t1:=t2*t1;
 t1:=t1.Square;
 for i:=2 to 10 do begin
  t1:=t1.Square;
 end;
 t0:=t1*t0;
 t1:=t0.Square;
 for i:=2 to 50 do begin
  t1:=t1.Square;
 end;
 t1:=t1*t0;
 t2:=t1.Square;
 for i:=2 to 100 do begin
  t2:=t2.Square;
 end;
 t1:=t2*t1;
 t1:=t1.Square;
 for i:=2 to 50 do begin
  t1:=t1.Square;
 end;
 t0:=(t1*t0).Square;
 for i:=2 to 2 do begin
  t0:=t0.Square;
 end;
 result:=t0*self;
end;

function TRNLValue25519.IsNegative:boolean;
var s:array[0..31] of TRNLUInt8;
begin
 SaveToMemory(s);
 result:=(s[0] and 1)<>0;
end;

function TRNLValue25519.IsNonZero:boolean;
var s:array[0..3] of TRNLUInt64;
begin
 SaveToMemory(s);
 result:=(s[0] or s[1] or s[2] or s[3])<>0;
end;

function TRNLValue25519.IsZero:boolean;
var s:array[0..3] of TRNLUInt64;
begin
 SaveToMemory(s);
 result:=(s[0] or s[1] or s[2] or s[3])=0;
end;

class procedure TRNLValue25519.SelfTest;
var a,b,c,d,x:TRNLValue25519;
    RandomGenerator:TRNLRandomGenerator;
begin
 RandomGenerator:=TRNLRandomGenerator.Create;
 try
  begin
   write('[Value25519] Testing conditional swap ... ');
   a:=13;
   b:=42;
   ConditionalSwap(a,b,0);
   c:=13;
   d:=42;
   ConditionalSwap(c,d,1);
   if (a=d) and (b=c) then begin
    writeln('OK!');
   end else begin
    writeln('FAILED!');
   end;
  end;
  begin
   write('[Value25519] Testing addition and subtraction ... ');
   a:=TRNLValue25519.CreateRandom(RandomGenerator);
   b:=TRNLValue25519.CreateRandom(RandomGenerator);
   c:=TRNLValue25519.CreateRandom(RandomGenerator);
   x:=((((a+b)-c)-a)+c).Carry;
   if x=b then begin
    writeln('OK!');
   end else begin
    writeln('FAILED!');
   end;
  end;
  begin
   write('[Value25519] Testing multiplication ... ');
   a:=TRNLValue25519.CreateRandom(RandomGenerator);
   b:=(a+a).Carry;
   c:=a*2;
   if b=c then begin
    writeln('OK!');
   end else begin
    writeln('FAILED!');
   end;
  end;
  begin
   write('[Value25519] Testing inverse ... ');
   a:=TRNLValue25519.CreateRandom(RandomGenerator);
   b:=1;
   c:=a.Invert*a;
   if b=c then begin
    writeln('OK!');
   end else begin
    writeln('FAILED!');
   end;
  end;
 finally
  RandomGenerator.Free;
 end;
end;

constructor TRNLPoint25519.CreateFromXY(const aX,aY:TRNLValue25519);
begin
 fX:=aX;
 fY:=aY;
 fZ:=1;
 fT:=fX*fY;
end;

class function TRNLPoint25519.LoadFromMemory(out aPoint:TRNLPoint25519;const aLocation):boolean;
const d:TRNLValue25519=(Limbs:(-10913610,13857413,-15372611,6949391,114729,-8787816,-6275908,-3247719,-18696448,-12055116));
      sqrtm1:TRNLValue25519=(Limbs:(-32595792,-7943725,9377950,3500415,12389472,-272473,-25146209,-2005654,326686,11406482));
var u,v,v3,vxx:TRNLValue25519;
begin
 aPoint.fY:=TRNLValue25519.LoadFromMemory(aLocation);
 aPoint.fZ:=1;
 u:=aPoint.fY.Square;
 v:=(u*d)+aPoint.fZ;
 u:=u-aPoint.fZ;
 v3:=v.Square*v;
 aPoint.fX:=(((v3.Square*v)*u).Pow22523*v3)*u;
 vxx:=aPoint.fX.Square*v;
 if (vxx-u).IsNonZero then begin
  if (vxx+u).IsNonZero then begin
   result:=false;
   exit;
  end;
  aPoint.fX:=aPoint.fX*sqrtm1;
 end;
 if aPoint.fX.IsNegative=(((PRNLUInt8Array(TRNLPointer(@aLocation))^[31] shr 7) and 1)<>0) then begin
  aPoint.fX:=-aPoint.fX;
 end;
 aPoint.fT:=aPoint.fX*aPoint.fY;
 result:=true;
end;

procedure TRNLPoint25519.SaveToMemory(out aLocation);
var r,x,y:TRNLValue25519;
begin
 r:=fZ.Invert;
 x:=fX*r;
 y:=fY*r;
 y.SaveToMemory(aLocation);
 PRNLUInt8Array(TRNLPointer(@aLocation))^[31]:=PRNLUInt8Array(TRNLPointer(@aLocation))^[31] xor (TRNLUInt8(ord(x.IsNegative) and 1) shl 7);
end;

class operator TRNLPoint25519.Add(const p,q:TRNLPoint25519):TRNLPoint25519;
const d2:TRNLValue25519=(Limbs:($2b2f159,$1a6e509,$22add7a,$0d4141d,$0038052,$0f3d130,$3407977,$19ce331,$1c56dff,$0901b67));
var a,b,c,d,e,f,g,h:TRNLValue25519;
begin
 a:=(p.fY-p.fX)*(q.fY-q.fX);
 b:=(p.fX+p.fY)*(q.fX+q.fY);
 c:=(p.fT*q.fT)*d2;
 d:=(p.fZ+p.fZ)*q.fZ;
 e:=b-a;
 f:=d-c;
 g:=d+c;
 h:=b+a;
 result.fX:=e*f;
 result.fY:=g*h;
 result.fZ:=f*g;
 result.fT:=e*h;
end;

class procedure TRNLCurve25519.Clean(out aX:TRNLKey);
begin
 FillChar(aX,SizeOf(TRNLKey),#0);
end;

class function TRNLCurve25519.IsWeakPoint(const aK:TRNLKey):boolean;
const Data:array[0..4,0..31] of TRNLUInt8=
       (($00,$00,$00,$00,$00,$00,$00,$00,
         $00,$00,$00,$00,$00,$00,$00,$00,
         $00,$00,$00,$00,$00,$00,$00,$00,
         $00,$00,$00,$00,$00,$00,$00,$00),
        ($01,$00,$00,$00,$00,$00,$00,$00,
         $00,$00,$00,$00,$00,$00,$00,$00,
         $00,$00,$00,$00,$00,$00,$00,$00,
         $00,$00,$00,$00,$00,$00,$00,$00),
        ($e0,$eb,$7a,$7c,$3b,$41,$b8,$ae,
         $16,$56,$e3,$fa,$f1,$9f,$c4,$6a,
         $da,$09,$8d,$eb,$9c,$32,$b1,$fd,
         $86,$62,$05,$16,$5f,$49,$b8,$00),
        ($5f,$9c,$95,$bc,$a3,$50,$8c,$24,
         $b1,$d0,$b1,$55,$9c,$83,$ef,$5b,
         $04,$44,$5c,$c4,$58,$1c,$8e,$86,
         $d8,$22,$4e,$dd,$d0,$9f,$11,$57),
        ($ec,$ff,$ff,$ff,$ff,$ff,$ff,$ff,
         $ff,$ff,$ff,$ff,$ff,$ff,$ff,$ff,
         $ff,$ff,$ff,$ff,$ff,$ff,$ff,$ff,
         $ff,$ff,$ff,$ff,$ff,$ff,$ff,$7f));
var Index,SubIndex,Check,ResultValue:TRNLInt32;
begin
 ResultValue:=0;
 for Index:=low(Data) to high(Data) do begin
  Check:=(Data[Index,31] xor aK.ui8[31]) and $7f;
  for SubIndex:=high(Data[Index])-1 downto low(Data[Index]) do begin
   Check:=Check or (Data[Index,SubIndex] xor aK.ui8[SubIndex]);
  end;
  ResultValue:=ResultValue or (($100-Check) shr 8);
 end;
 result:=ResultValue<>0;
end;

class function TRNLCurve25519.IsInRange(const aX:TRNLKey):boolean;
var Index,Last:TRNLUInt32;
    Carry:TRNLUInt64;
begin
 Carry:=19;
 for Index:=0 to 7 do begin
{$ifdef BIG_ENDIAN}
  inc(Carry,(aX.ui8[(Index shl 2) or 0] shl 0) or
            (aX.ui8[(Index shl 2) or 1] shl 8) or
            (aX.ui8[(Index shl 2) or 2] shl 16) or
            (aX.ui8[(Index shl 2) or 3] shl 24));
{$else}
  inc(Carry,aX.ui32[Index]);
{$endif}
  Last:=Carry and $ffffffff;
  Carry:=Carry shr 32;
 end;
 result:=(Last and $80000000)=0;
end;

class procedure TRNLCurve25519.Ladder(const aX1:TRNLValue25519;out aX2,aZ2,aX3,aZ3:TRNLValue25519;const aScalar:TRNLKey);
var Swap,Position,b:TRNLInt32;
    t0,t1:TRNLValue25519;
begin
 aX2:=1;
 aZ2:=0;
 aX3:=aX1;
 aZ3:=1;
 Swap:=0;
 for Position:=254 downto 0 do begin
  b:=(aScalar.ui8[Position shr 3] shr (Position and 7)) and 1;
  Swap:=Swap xor b;
  TRNLValue25519.ConditionalSwap(aX2,aX3,Swap);
  TRNLValue25519.ConditionalSwap(aZ2,aZ3,Swap);
  Swap:=b;
  t1:=aX2-aZ2;
  aX2:=aX2+aZ2;
  aZ2:=(aX3+aZ3)*t1;
  aZ3:=(aX3-aZ3)*aX2;
  aX3:=(aZ3+aZ2).Square;
  aZ3:=aX1*(aZ3-aZ2).Square;
  t0:=t1.Square;
  t1:=aX2.Square;
  aX2:=t1*t0;
  t1:=t1-t0;
  aZ2:=t1*(t0+t1.Mul121666);
 end;
 TRNLValue25519.ConditionalSwap(aX2,aX3,Swap);
 TRNLValue25519.ConditionalSwap(aZ2,aZ3,Swap);
end;

class function TRNLCurve25519.Eval(out aResult:TRNLKey;const aSecret:TRNLKey;const aBasePoint:PRNLKey=nil):boolean;
const Value9:TRNLKey=(ui8:(9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0));
var BasePoint:PRNLKey;
    x2,z2,x3,z3:TRNLValue25519;
begin
 if assigned(aBasePoint) then begin
  BasePoint:=aBasePoint;
 end else begin
  BasePoint:=@Value9;
 end;
 Ladder(TRNLValue25519.LoadFromMemory(BasePoint^),
        x2,z2,
        x3,z3,
        PRNLKey(TRNLPointer(@aSecret))^.ClampForCurve25519);
 (x2*z2.Invert).SaveToMemory(aResult);
 result:=IsInRange(BasePoint^);
end;

class procedure TRNLCurve25519.SelfTest;
const alice_private:TRNLKey=(ui8:($77,$07,$6d,$0a,$73,$18,$a5,$7d,$3c,$16,$c1,$72,$51,$b2,$66,$45,$df,$4c,$2f,$87,$eb,$c0,$99,$2a,$b1,$77,$fb,$a5,$1d,$b9,$2c,$2a));
      alice_public:TRNLKey=(ui8:($85,$20,$f0,$09,$89,$30,$a7,$54,$74,$8b,$7d,$dc,$b4,$3e,$f7,$5a,$0d,$bf,$3a,$0d,$26,$38,$1a,$f4,$eb,$a4,$a9,$8e,$aa,$9b,$4e,$6a));
      bob_private:TRNLKey=(ui8:($5d,$ab,$08,$7e,$62,$4a,$8a,$4b,$79,$e1,$7f,$8b,$83,$80,$0e,$e6,$6f,$3b,$b1,$29,$26,$18,$b6,$fd,$1c,$2f,$8b,$27,$ff,$88,$e0,$eb));
      bob_public:TRNLKey=(ui8:($de,$9e,$db,$7d,$7b,$7d,$c1,$b4,$d3,$5b,$61,$c2,$ec,$e4,$35,$37,$3f,$83,$43,$c8,$5b,$78,$67,$4d,$ad,$fc,$7e,$14,$6f,$88,$2b,$4f));
      shared_secret:TRNLKey=(ui8:($4a,$5d,$9d,$5b,$a4,$ce,$2d,$e1,$72,$8e,$3b,$f4,$80,$35,$0f,$25,$e0,$7e,$21,$c9,$47,$d1,$9e,$33,$76,$f0,$9b,$3c,$1e,$16,$17,$42));
var alice_private_,bob_private_,r:TRNLKey;
begin

 write('[Curve25519] Generating private and public key pair for Alice ... ');
 alice_private_:=alice_private.ClampForCurve25519;
 Eval(r,alice_private_,nil);
 if r=alice_public then begin
  writeln('OK!');
 end else begin
  writeln('FAILED!');
 end;

 write('[Curve25519] Generating private and public key pair for Bob ... ');
 bob_private_:=bob_private.ClampForCurve25519;
 Eval(r,bob_private_,nil);
 if r=bob_public then begin
  writeln('OK!');
 end else begin
  writeln('FAILED!');
 end;

 write('[Curve25519] Generating shared secret for Alice ... ');
 Eval(r,alice_private_,@bob_public);
 if r=shared_secret then begin
  writeln('OK!');
 end else begin
  writeln('FAILED!');
 end;

 write('[Curve25519] Generating shared secret for Bob ... ');
 Eval(r,bob_private_,@alice_public);
 if r=shared_secret then begin
  writeln('OK!');
 end else begin
  writeln('FAILED!');
 end;

end;

class function TRNLX25519.GeneratePublicPrivateKeyPair(const aRandomGenerator:TRNLRandomGenerator;out aPublicKey,aPrivateKey:TRNLKey):boolean;
begin
 repeat
  aPrivateKey:=TRNLKey.CreateRandom(aRandomGenerator).ClampForCurve25519;
  TRNLCurve25519.Eval(aPublicKey,aPrivateKey,nil);
 until not TRNLCurve25519.IsWeakPoint(aPublicKey);
 result:=true;
end;

class function TRNLX25519.GenerateSharedSecretKey(out aSharedSecretKey:TRNLKey;const aPublicKey,aPrivateKey:TRNLKey):boolean;
var k:TRNLKey;
begin
 k:=aPublicKey;
 result:=not ((TRNLCurve25519.IsWeakPoint(k) or not TRNLCurve25519.Eval(k,aPrivateKey,@k)) or TRNLCurve25519.IsWeakPoint(k));
 if result then begin
  aSharedSecretKey:=k;
 end else begin
  FillChar(aSharedSecretKey,SizeOf(TRNLKey),#0);
 end;
end;

class procedure TRNLX25519.SelfTest;
var alice_k,alice_f,alice_s,bob_k,bob_f,bob_s:TRNLKey;
    RandomGenerator:TRNLRandomGenerator;
begin

 RandomGenerator:=TRNLRandomGenerator.Create;
 try

  write('[X25519] Generating random public/private key pair for Alice ... ');
  if GeneratePublicPrivateKeyPair(RandomGenerator,alice_k,alice_f) then begin
   writeln('OK!');
  end else begin
   writeln('FAILED!');
   exit;
  end;

  write('[X25519] Generating random public/private key pair for Bob ... ');
  if GeneratePublicPrivateKeyPair(RandomGenerator,bob_k,bob_f) then begin
   writeln('OK!');
  end else begin
   writeln('FAILED!');
   exit;
  end;

  write('[X25519] Generating shared secret key for Alice ... ');
  if GenerateSharedSecretKey(alice_s,bob_k,alice_f) then begin
   writeln('OK!');
  end else begin
   writeln('FAILED!');
   exit;
  end;

  write('[X25519] Generating shared secret key for Bob ... ');
  if GenerateSharedSecretKey(bob_s,alice_k,bob_f) then begin
   writeln('OK!');
  end else begin
   writeln('FAILED!');
   exit;
  end;

  if alice_s=bob_s then begin
   writeln('[X25519] Both shared secrets are equal => OK!');
  end else begin
   writeln('[X25519] Both shared secrets are not equal => FAILED!');
  end;

 finally
  RandomGenerator.Free;
 end;

end;

procedure TRNLPoly1305Context.ClearC;
begin
 fC[0]:=0;
 fC[1]:=0;
 fC[2]:=0;
 fC[3]:=0;
 fCIndex:=0;
end;

procedure TRNLPoly1305Context.ProcessByte(const aValue:TRNLUInt8);
var Index:TRNLUInt32;
begin
 Index:=fCIndex shr 2;
 fC[Index]:=fC[Index] or (TRNLUInt64(aValue) shl ((fCIndex and 3) shl 3));
 inc(fCIndex);
end;

procedure TRNLPoly1305Context.Block;
var s0,s1,s2,s3,s4,x0,x1,x2,x3,u0,u1,u2,u3,u4:TRNLUInt64;
    r0,r1,r2,r3,rr0,rr1,rr2,rr3,x4,u5:TRNLUInt32;
begin
 s0:=fH[0]+TRNLUInt64(fC[0]);
 s1:=fH[1]+TRNLUInt64(fC[1]);
 s2:=fH[2]+TRNLUInt64(fC[2]);
 s3:=fH[3]+TRNLUInt64(fC[3]);
 s4:=fH[4]+TRNLUInt64(fC[4]);
 r0:=fR[0];
 r1:=fR[1];
 r2:=fR[2];
 r3:=fR[3];
 rr0:=(r0 shr 2)*5;
 rr1:=(r1 shr 2)+r1;
 rr2:=(r2 shr 2)+r2;
 rr3:=(r3 shr 2)+r3;
 x0:=(s0*r0)+(s1*rr3)+(s2*rr2)+(s3*rr1)+(s4*rr0);
 x1:=(s0*r1)+(s1*r0)+(s2*rr3)+(s3*rr2)+(s4*rr1);
 x2:=(s0*r2)+(s1*r1)+(s2*r0)+(s3*rr3)+(s4*rr2);
 x3:=(s0*r3)+(s1*r2)+(s2*r1)+(s3*r0)+(s4*rr3);
 x4:=s4*(r0 and 3);
 u5:=x4+(x3 shr 32);
 u0:=((u5 shr 2)*5)+(x0 and $ffffffff);
 u1:=(u0 shr 32)+(x1 and $ffffffff)+(x0 shr 32);
 u2:=(u1 shr 32)+(x2 and $ffffffff)+(x1 shr 32);
 u3:=(u2 shr 32)+(x3 and $ffffffff)+(x2 shr 32);
 u4:=(u3 shr 32)+(u5 and 3);
 fH[0]:=u0 and $ffffffff;
 fH[1]:=u1 and $ffffffff;
 fH[2]:=u2 and $ffffffff;
 fH[3]:=u3 and $ffffffff;
 fH[4]:=u4;
end;

procedure TRNLPoly1305Context.Initialize(const aKey);
begin
 FillChar(self,SizeOf(TRNLPoly1305Context),#0);
 fH[0]:=0;
 fH[1]:=0;
 fH[2]:=0;
 fH[3]:=0;
 fH[4]:=0;
 ClearC;
 fC[4]:=1;
 fR[0]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aKey))^[0]) and $0fffffff;
 fR[1]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aKey))^[1]) and $0ffffffc;
 fR[2]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aKey))^[2]) and $0ffffffc;
 fR[3]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aKey))^[3]) and $0ffffffc;
 fPad[0]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aKey))^[4]);
 fPad[1]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aKey))^[5]);
 fPad[2]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aKey))^[6]);
 fPad[3]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aKey))^[7]);
end;

procedure TRNLPoly1305Context.Update(const aMessage;const aMessageSize:TRNLSizeUInt);
var MessagePosition,MessageSize:TRNLSizeUInt;
begin
 MessagePosition:=0;
 MessageSize:=AMessageSize;
 while ((fCIndex and 15)<>0) and (MessageSize>0) do begin
  ProcessByte(PRNLUInt8Array(TRNLPointer(@aMessage))^[MessagePosition]);
  inc(MessagePosition);
  dec(MessageSize);
 end;
 if fCIndex=16 then begin
  Block;
  ClearC;
 end;
 if MessageSize>=16 then begin
  repeat
   fC[0]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt8Array(TRNLPointer(@aMessage))^[MessagePosition+0]);
   fC[1]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt8Array(TRNLPointer(@aMessage))^[MessagePosition+4]);
   fC[2]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt8Array(TRNLPointer(@aMessage))^[MessagePosition+8]);
   fC[3]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt8Array(TRNLPointer(@aMessage))^[MessagePosition+12]);
   Block;
   inc(MessagePosition,16);
   dec(MessageSize,16);
  until MessageSize<16;
  ClearC;
 end;
 while MessageSize>0 do begin
  ProcessByte(PRNLUInt8Array(TRNLPointer(@aMessage))^[MessagePosition]);
  inc(MessagePosition);
  dec(MessageSize);
 end;
end;

procedure TRNLPoly1305Context.Finalize(out aMAC);
var u:TRNLUInt64;
begin
 if fCIndex<>0 then begin
  fC[4]:=0;
  ProcessByte(1);
  Block;
 end;
 u:=(((((((((((5+TRNLUInt64(fH[0])) shr 32)+
                 TRNLUInt64(fH[1])) shr 32)+
                 TRNLUInt64(fH[2])) shr 32)+
                 TRNLUInt64(fH[3])) shr 32)+
                 TRNLUInt64(fH[4])) shr 2)*TRNLUInt64(5))+
    (TRNLUInt64(fH[0])+fPad[0]);
 TRNLMemoryAccess.StoreLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aMAC))^[0],u and $ffffffff);
 u:=(u shr 32)+
    (TRNLUInt64(fH[1])+fPad[1]);
 TRNLMemoryAccess.StoreLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aMAC))^[1],u and $ffffffff);
 u:=(u shr 32)+
    (TRNLUInt64(fH[2])+fPad[2]);
 TRNLMemoryAccess.StoreLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aMAC))^[2],u and $ffffffff);
 u:=(u shr 32)+
    (TRNLUInt64(fH[3])+fPad[3]);
 TRNLMemoryAccess.StoreLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aMAC))^[3],u and $ffffffff);
end;

class function TRNLPoly1305.OneTimeAuthentication(out aOutput;const aInput;const aInputLength:TRNLSizeUInt;const aSecretKey):boolean;
var Context:TRNLPoly1305Context;
begin
 Context.Initialize(aSecretKey);
 Context.Update(aInput,aInputLength);
 Context.Finalize(aOutput);
 result:=true;
end;

class function TRNLPoly1305.OneTimeAuthenticationVerify(const aComparsion;const aInput;const aInputLength:TRNLSizeUInt;const aSecretKey):boolean;
var Correct:array[0..15] of TRNLUInt8;
begin
 OneTimeAuthentication(Correct,aInput,aInputLength,aSecretKey);
 result:=(PRNLUInt64Array(TRNLPointer(@Correct))^[0]=PRNLUInt64Array(TRNLPointer(@aComparsion))^[0]) and
         (PRNLUInt64Array(TRNLPointer(@Correct))^[1]=PRNLUInt64Array(TRNLPointer(@aComparsion))^[1]);
end;

class procedure TRNLPoly1305.SelfTest;
const Key:array[0..31] of TRNLUInt8=($ee,$a6,$a7,$25,$1c,$1e,$72,$91,$6d,$11,$c2,$cb,$21,$4d,$3c,$25,$25,$39,$12,$1d,$8e,$23,$4e,$65,$2d,$65,$1f,$a4,$c8,$cf,$f8,$80);
      Data:array[0..130] of TRNLUInt8=($8e,$99,$3b,$9f,$48,$68,$12,$73,$c2,$96,$50,$ba,$32,$fc,
                                       $76,$ce,$48,$33,$2e,$a7,$16,$4d,$96,$a4,$47,$6f,$b8,$c5,
                                       $31,$a1,$18,$6a,$c0,$df,$c1,$7c,$98,$dc,$e8,$7b,$4d,$a7,
                                       $f0,$11,$ec,$48,$c9,$72,$71,$d2,$c2,$0f,$9b,$92,$8f,$e2,
                                       $27,$0d,$6f,$b8,$63,$d5,$17,$38,$b4,$8e,$ee,$e3,$14,$a7,
                                       $cc,$8a,$b9,$32,$16,$45,$48,$e5,$26,$ae,$90,$22,$43,$68,
                                       $51,$7a,$cf,$ea,$bd,$6b,$b3,$73,$2b,$c0,$e9,$da,$99,$83,
                                       $2b,$61,$ca,$01,$b6,$de,$56,$24,$4a,$9e,$88,$d5,$f9,$b3,
                                       $79,$73,$f6,$22,$a4,$3d,$14,$a6,$59,$9b,$1f,$65,$4c,$b4,
                                       $5a,$74,$e3,$55,$a5);
      Hash:array[0..15] of TRNLUInt8=($f3,$ff,$c7,$70,$3f,$94,$00,$e5,$2a,$7d,$fb,$4b,$3d,$33,$05,$d9);
begin
 write('[Poly1305] ');
 if OneTimeAuthenticationVerify(Hash,Data,SizeOf(Data),Key) then begin
  writeln('OK!');
 end else begin
  writeln('FAILED!');
 end;
end;

class function TRNLSHA512Context.RotateRight64(const aValue:TRNLUInt64;const aBits:TRNLUInt32):TRNLUInt64;
begin
{$ifdef fpc}
 result:=RORQWord(aValue,aBits);
{$else}
 result:=(aValue shl (64-aBits)) or (aValue shr aBits);
{$endif}
end;

procedure TRNLSHA512Context.ResetInput;
begin
 FillChar(fInput,SizeOf(fInput),#0);
 fInputIndex:=0;
end;

procedure TRNLSHA512Context.Initialize;
begin
 fState:=InitialState;
 ResetInput;
 fInputSize[0]:=0;
 fInputSize[1]:=0;
end;

procedure TRNLSHA512Context.Compress;
var w:array[0..79] of TRNLUInt64;
    a,b,c,d,e,f,g,h,t1,t2:TRNLUInt64;
    i:TRNLInt32;
begin
 PRNLSHA512Input(TRNLPointer(@w))^:=fInput;
 for i:=16 to 79 do begin
  a:=w[i-2];
  b:=w[i-15];
  w[i]:=(RotateRight64(a,19) xor RotateRight64(a,61) xor (a shr 6))+
        w[i-7]+
        (RotateRight64(b,1) xor RotateRight64(b,8) xor (b shr 7))+
        w[i-16];
 end;
 a:=fState[0];
 b:=fState[1];
 c:=fState[2];
 d:=fState[3];
 e:=fState[4];
 f:=fState[5];
 g:=fState[6];
 h:=fState[7];
 for i:=0 to 79 do begin
  t1:=(RotateRight64(e,14) xor RotateRight64(e,18) xor RotateRight64(e,41))+
      ((e and f) xor ((not e) and g))+
      h+
      RoundK[i]+
      w[i];
  t2:=(RotateRight64(a,28) xor RotateRight64(a,34) xor RotateRight64(a,39))+
      ((a and b) xor (a and c) xor (b and c));
  h:=g;
  g:=f;
  f:=e;
  e:=d+t1;
  d:=c;
  c:=b;
  b:=a;
  a:=t1+t2;
 end;
 inc(fState[0],a);
 inc(fState[1],b);
 inc(fState[2],c);
 inc(fState[3],d);
 inc(fState[4],e);
 inc(fState[5],f);
 inc(fState[6],g);
 inc(fState[7],h);
end;

procedure TRNLSHA512Context.ProcessByte(const aValue:TRNLUInt8);
var Index:TRNLUInt32;
begin
 Index:=fInputIndex shr 3;
 fInput[Index]:=fInput[Index] or (TRNLUInt64(aValue) shl ((7-(fInputIndex and 7)) shl 3));
end;

procedure TRNLSHA512Context.Increment(var aX;const aY:TRNLUInt64);
begin
 inc(PRNLUInt64Array(TRNLPointer(@aX))^[1],aY);
 if PRNLUInt64Array(TRNLPointer(@aX))^[1]<aY then begin
  inc(PRNLUInt64Array(TRNLPointer(@aX))^[0]);
 end;
end;

procedure TRNLSHA512Context.EndBlock;
begin
 if fInputIndex=128 then begin
  Increment(fInputSize,1024);
  Compress;
  ResetInput;
 end;
end;

procedure TRNLSHA512Context.Update(const aMessage;const aMessageSize:TRNLSizeUInt);
var MessagePosition,MessageSize:TRNLSizeUInt;
begin
 MessagePosition:=0;
 MessageSize:=AMessageSize;
 while ((fInputIndex and 7)<>0) and (MessageSize>0) do begin
  ProcessByte(PRNLUInt8Array(TRNLPointer(@aMessage))^[MessagePosition]);
  inc(fInputIndex);
  inc(MessagePosition);
  dec(MessageSize);
 end;
 EndBlock;
 while MessageSize>=8 do begin
  fInput[fInputIndex shr 3]:=TRNLMemoryAccess.LoadBigEndianUInt64(PRNLUInt8Array(TRNLPointer(@aMessage))^[MessagePosition]);
  inc(fInputIndex,8);
  inc(MessagePosition,8);
  dec(MessageSize,8);
  EndBlock;
 end;
 while MessageSize>0 do begin
  ProcessByte(PRNLUInt8Array(TRNLPointer(@aMessage))^[MessagePosition]);
  inc(fInputIndex);
  inc(MessagePosition);
  dec(MessageSize);
 end;
end;

procedure TRNLSHA512Context.Finalize(out aHash);
var Index:TRNLInt32;
begin
 Increment(fInputSize,fInputIndex shl 3);
 ProcessByte($80);
 if fInputIndex>111 then begin
  Compress;
  ResetInput;
 end;
 fInput[14]:=fInputSize[0];
 fInput[15]:=fInputSize[1];
 Compress;
 for Index:=0 to 7 do begin
  TRNLMemoryAccess.StoreBigEndianUInt64(PRNLUInt64Array(TRNLPointer(@aHash))^[Index],fState[Index]);
 end;
end;

class procedure TRNLSHA512.Process(out aHash;const aMessage;const aMessageSize:TRNLSizeUInt);
var Context:TRNLSHA512Context;
begin
 Context.Initialize;
 Context.Update(aMessage,aMessageSize);
 Context.Finalize(aHash);
end;

class procedure TRNLSHA512.SelfTest;
const Hash0:TRNLSHA512Hash=
       (
        $cf,$83,$e1,$35,$7e,$ef,$b8,$bd,
        $f1,$54,$28,$50,$d6,$6d,$80,$07,
        $d6,$20,$e4,$05,$0b,$57,$15,$dc,
        $83,$f4,$a9,$21,$d3,$6c,$e9,$ce,
        $47,$d0,$d1,$3c,$5d,$85,$f2,$b0,
        $ff,$83,$18,$d2,$87,$7e,$ec,$2f,
        $63,$b9,$31,$bd,$47,$41,$7a,$81,
        $a5,$38,$32,$7a,$f9,$27,$da,$3e
       );
       DataABC:array[0..2] of TRNLUInt8=
        (
         ord('a'),
         ord('b'),
         ord('c')
        );
       HashABC:TRNLSHA512Hash=
       (
        $dd,$af,$35,$a1,$93,$61,$7a,$ba,
        $cc,$41,$73,$49,$ae,$20,$41,$31,
        $12,$e6,$fa,$4e,$89,$a9,$7e,$a2,
        $0a,$9e,$ee,$e6,$4b,$55,$d3,$9a,
        $21,$92,$99,$2a,$27,$4f,$c1,$a8,
        $36,$ba,$3c,$23,$a3,$fe,$eb,$bd,
        $45,$4d,$44,$23,$64,$3c,$e8,$0e,
        $2a,$9a,$c9,$4f,$a5,$4c,$a4,$9f
       );
       Data0123456789abcdef:array[0..15] of TRNLUInt8=
        (
         ord('0'),
         ord('1'),
         ord('2'),
         ord('3'),
         ord('4'),
         ord('5'),
         ord('6'),
         ord('7'),
         ord('8'),
         ord('9'),
         ord('a'),
         ord('b'),
         ord('c'),
         ord('d'),
         ord('e'),
         ord('f')
        );
       Hash0123456789abcdef:TRNLSHA512Hash=
       (
        $1c,$04,$3f,$be,$4b,$ca,$7c,$79,
        $20,$da,$e5,$36,$c6,$80,$fd,$44,
        $c1,$5d,$71,$ec,$12,$cd,$82,$a2,
        $a9,$49,$1b,$00,$43,$b5,$7f,$4d,
        $0b,$89,$05,$98,$5e,$85,$ad,$13,
        $83,$1e,$e6,$d3,$9e,$55,$a5,$4e,
        $8f,$80,$8c,$c8,$2c,$41,$a0,$58,
        $29,$31,$bb,$c0,$c0,$22,$1d,$60
       );
{$if not defined(NEXTGEN)}
       DataLong:array[0..111] of TRNLRawByteChar='abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn'+
                                                 'hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu';
       HashLong:TRNLSHA512Hash=
       (
        $8e,$95,$9b,$75,$da,$e3,$13,$da,
        $8c,$f4,$f7,$28,$14,$fc,$14,$3f,
        $8f,$77,$79,$c6,$eb,$9f,$7f,$a1,
        $72,$99,$ae,$ad,$b6,$88,$90,$18,
        $50,$1d,$28,$9e,$49,$00,$f7,$e4,
        $33,$1b,$99,$de,$c4,$b5,$43,$3a,
        $c7,$d3,$29,$ee,$b6,$dd,$26,$54,
        $5e,$96,$e5,$5b,$87,$4b,$e9,$09
       );
{$ifend}
var Hash:TRNLSHA512Hash;
begin

 write('[SHA512] Hashing "" ... ');
 Process(Hash,TRNLPointer(nil)^,0);
 if TRNLMemory.SecureIsEqual(Hash,Hash0,SizeOf(TRNLSHA512Hash)) then begin
  writeln('OK!');
 end else begin
  writeln('FAILED!');
 end;

 write('[SHA512] Hashing "abc" ... ');
 Process(Hash,DataABC,SizeOf(DataABC));
 if TRNLMemory.SecureIsEqual(Hash,HashABC,SizeOf(TRNLSHA512Hash)) then begin
  writeln('OK!');
 end else begin
  writeln('FAILED!');
 end;

 write('[SHA512] Hashing "0123456789abcdef" ... ');
 Process(Hash,Data0123456789abcdef,SizeOf(Data0123456789abcdef));
 if TRNLMemory.SecureIsEqual(Hash,Hash0123456789abcdef,SizeOf(TRNLSHA512Hash)) then begin
  writeln('OK!');
 end else begin
  writeln('FAILED!');
 end;

{$if not defined(NEXTGEN)}
 write('[SHA512] Hashing "','abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu','" ... ');
 Process(Hash,DataLong,SizeOf(DataLong));
 if TRNLMemory.SecureIsEqual(Hash,HashLong,SizeOf(TRNLSHA512Hash)) then begin
  writeln('OK!');
 end else begin
  writeln('FAILED!');
 end;
{$ifend}

end;

class procedure TRNLED25519.ModL(out aR;const aX);
const L:array[0..31] of TRNLInt64=
       (
        $ed,$d3,$f5,$5c,$1a,$63,$12,$58,
        $d6,$9c,$f7,$a2,$de,$f9,$de,$14,
        $00,$00,$00,$00,$00,$00,$00,$00,
        $00,$00,$00,$00,$00,$00,$00,$10
       );
var i,j:TRNLInt32;
    Carry:TRNLInt64;
begin
 for i:=63 downto 32 do begin
  Carry:=0;
  for j:=i-32 to i-13 do begin
   inc(PRNLInt64Array(TRNLPointer(@aX))^[j],Carry-(16*PRNLInt64Array(TRNLPointer(@aX))^[i]*L[j-(i-32)]));
   Carry:=SARInt64(PRNLInt64Array(TRNLPointer(@aX))^[j]+128,8);
   dec(PRNLInt64Array(TRNLPointer(@aX))^[j],Carry shl 8);
  end;
  inc(PRNLInt64Array(TRNLPointer(@aX))^[i-12],Carry);
  PRNLInt64Array(TRNLPointer(@aX))^[i]:=0;
 end;
 Carry:=0;
 for i:=0 to 31 do begin
  inc(PRNLInt64Array(TRNLPointer(@aX))^[i],Carry-(SARInt64(PRNLInt64Array(TRNLPointer(@aX))^[31],4)*L[i]));
  Carry:=SARInt64(PRNLInt64Array(TRNLPointer(@aX))^[i],8);
  PRNLInt64Array(TRNLPointer(@aX))^[i]:=PRNLInt64Array(TRNLPointer(@aX))^[i] and $ff;
 end;
 for i:=0 to 31 do begin
  dec(PRNLInt64Array(TRNLPointer(@aX))^[i],Carry*L[i]);
 end;
 for i:=0 to 31 do begin
  inc(PRNLInt64Array(TRNLPointer(@aX))^[i+1],SARInt64(PRNLInt64Array(TRNLPointer(@aX))^[i],8));
  PRNLUInt8Array(TRNLPointer(@aR))^[i]:=PRNLInt64Array(TRNLPointer(@aX))^[i] and $ff;
 end;
end;

class procedure TRNLED25519.Reduce(var aR);
var x:array[0..64] of TRNLInt64;
    i:TRNLInt32;
begin
 for i:=0 to 63 do begin
  x[i]:=PRNLUInt8Array(TRNLPointer(@aR))^[i];
  PRNLUInt8Array(TRNLPointer(@aR))^[i]:=0;
 end;
 ModL(aR,x);
end;

class procedure TRNLED25519.HashRAM(out aK;const aR,aA,aM;const aMSize:TRNLSizeUInt);
var HashContext:TRNLED25519HashContext;
begin
 HashContext.Initialize;
 HashContext.Update(aR,32);
 HashContext.Update(aA,32);
 HashContext.Update(aM,aMSize);
 HashContext.Finalize(aK);
 Reduce(aK);
end;

class function TRNLED25519.ScalarMultiplication(out aResult:TRNLPoint25519;const aInput:TRNLPoint25519;const aScalar:TRNLKey):boolean;
const K:TRNLValue25519=(Limbs:(54885894,25242303,55597453,9067496,51808079,33312638,25456129,14121551,54921728,3972023));
var x1,y1,z1,x2,z2,x3,z3,t1,t2,t3,t4:TRNLValue25519;
begin

 // convert input to montgomery format
 z1:=aInput.fZ-aInput.fY;
 z1:=(z1*aInput.fX).Invert;
 t1:=aInput.fZ+aInput.fY;
 x1:=aInput.fX*t1;
 x1:=x1*z1;
 y1:=aInput.fZ*t1;
 y1:=y1*z1;
 y1:=K*y1;
 z1:=1; // implied in the ladder, needed to convert back.

 // montgomery scalarmult
 TRNLCurve25519.Ladder(x1,x2,z2,x3,z3,aScalar);

 // Recover the y coordinate (Katsuyuki Okeya & Kouichi Sakurai, 2001)
 // Note the shameless reuse of x1: (x1, y1, z1) will correspond to what was originally (x2, z2).
 t1:=x1*z2;
 t2:=x2+t1;
 t3:=x2-t1;
 t3:=t3.Square;
 t3:=t3*x3;
 t1:=z2.Mul973324;
 t2:=t2+t1;
 t4:=x1*x2;
 t4:=t4+z2;
 t2:=t2*t4;
 t1:=t1*z2;
 t2:=t2-t1;
 t2:=t2*z3;
 t1:=y1+y1;
 t1:=t1*z2;
 t1:=t1*z3;
 x1:=t1*x2;
 y1:=t2-t3;
 z1:=t1*z2;

 // convert back to twisted edwards
 t1:=x1-z1;
 t2:=x1+z1;
 x1:=K*x1;
 aResult.fX:=x1*t2;
 aResult.fY:=y1*t1;
 aResult.fZ:=y1*t2;
 aResult.fT:=x1*t1;

 result:=true;

end;

class function TRNLED25519.ScalarMultiplicationBase(out aResult:TRNLPoint25519;const aScalar:TRNLKey):boolean;
const x:TRNLValue25519=(Limbs:($325d51a,$18b5823,$0f6592a,$104a92d,$1a4b31d,$1d6dc5c,$27118fe,$07fd814,$13cd6e5,$085a4db));
      y:TRNLValue25519=(Limbs:($2666658,$1999999,$0cccccc,$1333333,$1999999,$0666666,$3333333,$0cccccc,$2666666,$1999999));
begin
 result:=ScalarMultiplication(aResult,TRNLPoint25519.CreateFromXY(x,y),aScalar);
end;

class procedure TRNLED25519.DerivePublicKey(out aPublicKey;const aPrivateKey);
var a:array[0..63] of TRNLUInt8;
    b:TRNLPoint25519;
begin
 TRNLED25519Hash.Process(a,aPrivateKey,32);
 PRNLKey(TRNLPointer(@a))^:=PRNLKey(TRNLPointer(@a))^.ClampForCurve25519;
 TRNLED25519.ScalarMultiplicationBase(b,PRNLKey(TRNLPointer(@a))^);
 b.SaveToMemory(aPublicKey);
end;

class procedure TRNLED25519.GeneratePublicPrivateKeyPair(const aRandomGenerator:TRNLRandomGenerator;out aPublicKey,aPrivateKey);
begin
 PRNLKey(TRNLPointer(@aPrivateKey))^:=TRNLKey.CreateRandom(aRandomGenerator).ClampForCurve25519;
 DerivePublicKey(aPublicKey,aPrivateKey);
end;

class procedure TRNLED25519.Sign(out aSignature;const aPrivateKey,aMessage;const aMessageSize:TRNLSizeUInt;const aPublicKey:TRNLPointer=nil);
var a,r,h_ram:array[0..63] of TRNLUInt8;
    pkbuf:array[0..31] of TRNLUInt8;
    pk,Prefix:TRNLPointer;
    Hash:TRNLED25519HashContext;
    b:TRNLPoint25519;
    s:array[0..63] of TRNLInt64;
    i,j:TRNLInt32;
begin

 Prefix:=@a[32];

 TRNLED25519Hash.Process(a,aPrivateKey,32);

 PRNLKey(TRNLPointer(@a))^:=PRNLKey(TRNLPointer(@a))^.ClampForCurve25519;

 pk:=aPublicKey;
 if not assigned(pk) then begin
  DerivePublicKey(pkbuf,aPrivateKey);
  pk:=@pkbuf;
 end;

 // Constructs the "random" nonce from the secret key and message.
 // An actual random number would work just fine, and would save us
 // the trouble of hashing the message twice.  If we did that
 // however, the user could fuck it up and reuse the nonce.
 Hash.Initialize;
 Hash.Update(Prefix^,32);
 Hash.Update(aMessage,aMessageSize);
 Hash.Finalize(r);
 Reduce(r);

 // first half of the signature = "random" nonce times basepoint
 ScalarMultiplicationBase(b,PRNLKey(TRNLPointer(@r))^);
 b.SaveToMemory(aSignature);

 HashRAM(h_ram,aSignature,pk^,aMessage,aMessageSize);

 for i:=0 to 31 do begin
  s[i]:=r[i];
 end;
 for i:=32 to 63 do begin
  s[i]:=0;
 end;
 for i:=0 to 31 do begin
  for j:=0 to 31 do begin
   inc(s[i+j],h_ram[i]*TRNLUInt64(a[j]));
  end;
 end;

 // second half of the signature = s
 ModL(PRNLUInt8Array(TRNLPointer(@aSignature))^[32],s);

end;

class procedure TRNLED25519.Sign(out aSignature;const aPrivateKey,aPublicKey,aMessage;const aMessageSize:TRNLSizeUInt);
begin
 Sign(aSignature,aPrivateKey,aMessage,aMessageSize,@aPublicKey);
end;

class function TRNLED25519.Verify(const aSignature,aPublicKey,aMessage;const aMessageSize:TRNLSizeUInt):boolean;
var A,p,sB:TRNLPoint25519;
    h_ram:array[0..63] of TRNLUInt8;
    R_check:array[0..31] of TRNLUInt8;
begin
 result:=TRNLPoint25519.LoadFromMemory(A,aPublicKey);
 if result then begin
  HashRAM(h_ram,aSignature,aPublicKey,aMessage,aMessageSize);
  ScalarMultiplication(p,A,PRNLKey(TRNLPointer(@h_ram))^);
  ScalarMultiplicationBase(sB,PRNLKey(TRNLPointer(@PRNLUInt8Array(TRNLPointer(@aSignature))^[32]))^);
  (p+sB).SaveToMemory(R_check);
  result:=TRNLMemory.SecureIsEqual(aSignature,R_check,32);
 end;
end;

class procedure TRNLED25519.SelfTest;
const PrivateKey0:array[0..31] of TRNLUInt8=
       (
        $9d,$61,$b1,$9d,$ef,$fd,$5a,$60,
        $ba,$84,$4a,$f4,$92,$ec,$2c,$c4,
        $44,$49,$c5,$69,$7b,$32,$69,$19,
        $70,$3b,$ac,$03,$1c,$ae,$7f,$60
       );
      PublicKey0:array[0..31] of TRNLUInt8=
       (
        $d7,$5a,$98,$01,$82,$b1,$0a,$b7,
        $d5,$4b,$fe,$d3,$c9,$64,$07,$3a,
        $0e,$e1,$72,$f3,$da,$a6,$23,$25,
        $af,$02,$1a,$68,$f7,$07,$51,$1a
       );
      Message0:array[0..1] of TRNLUInt8=
       (
        $00,
        $00
       );
      MessageSize0=0;
      Signature0:array[0..63] of TRNLUInt8=
       (
        $e5,$56,$43,$00,$c3,$60,$ac,$72,
        $90,$86,$e2,$cc,$80,$6e,$82,$8a,
        $84,$87,$7f,$1e,$b8,$e5,$d9,$74,
        $d8,$73,$e0,$65,$22,$49,$01,$55,
        $5f,$b8,$82,$15,$90,$a3,$3b,$ac,
        $c6,$1e,$39,$70,$1c,$f9,$b4,$6b,
        $d2,$5b,$f5,$f0,$59,$5b,$be,$24,
        $65,$51,$41,$43,$8e,$7a,$10,$0b
       );
      PrivateKey1:array[0..31] of TRNLUInt8=
       (
        $4c,$cd,$08,$9b,$28,$ff,$96,$da,
        $9d,$b6,$c3,$46,$ec,$11,$4e,$0f,
        $5b,$8a,$31,$9f,$35,$ab,$a6,$24,
        $da,$8c,$f6,$ed,$4f,$b8,$a6,$fb
       );
      PublicKey1:array[0..31] of TRNLUInt8=
       (
        $3d,$40,$17,$c3,$e8,$43,$89,$5a,
        $92,$b7,$0a,$a7,$4d,$1b,$7e,$bc,
        $9c,$98,$2c,$cf,$2e,$c4,$96,$8c,
        $c0,$cd,$55,$f1,$2a,$f4,$66,$0c
       );
      Message1:array[0..1] of TRNLUInt8=
       (
        $72,
        $00
       );
      MessageSize1=1;
      Signature1:array[0..63] of TRNLUInt8=
       (
        $92,$a0,$09,$a9,$f0,$d4,$ca,$b8,
        $72,$0e,$82,$0b,$5f,$64,$25,$40,
        $a2,$b2,$7b,$54,$16,$50,$3f,$8f,
        $b3,$76,$22,$23,$eb,$db,$69,$da,
        $08,$5a,$c1,$e4,$3e,$15,$99,$6e,
        $45,$8f,$36,$13,$d0,$f1,$1d,$8c,
        $38,$7b,$2e,$ae,$b4,$30,$2a,$ee,
        $b0,$0d,$29,$16,$12,$bb,$0c,$00
       );
var Signature:array[0..63] of TRNLUInt8;
begin

 write('[ED25519] Signing message 0 ... ');
 FillChar(Signature,64,#0);
 Sign(Signature,PrivateKey0,PublicKey0,Message0,MessageSize0);
 if TRNLMemory.SecureIsEqual(Signature,Signature0,64) then begin
  writeln('OK!');
 end else begin
  writeln('FAILED!');
 end;

 write('[ED25519] Verifing message 0 ... ');
 if Verify(Signature,PublicKey0,Message0,MessageSize0) then begin
  writeln('OK!');
 end else begin
  writeln('FAILED!');
 end;

 write('[ED25519] Deriving public key 0 ... ');
 FillChar(Signature,32,#0);
 DerivePublicKey(Signature,PrivateKey0);
 if TRNLMemory.SecureIsEqual(Signature,PublicKey0,32) then begin
  writeln('OK!');
 end else begin
  writeln('FAILED!');
 end;

 write('[ED25519] Signing message 1 ... ');
 FillChar(Signature,64,#0);
 Sign(Signature,PrivateKey1,PublicKey1,Message1,MessageSize1);
 if TRNLMemory.SecureIsEqual(Signature,Signature1,64) then begin
  writeln('OK!');
 end else begin
  writeln('FAILED!');
 end;

 write('[ED25519] Verifing message 1 ... ');
 if Verify(Signature,PublicKey1,Message1,MessageSize1) then begin
  writeln('OK!');
 end else begin
  writeln('FAILED!');
 end;

 write('[ED25519] Deriving public key 1 ... ');
 FillChar(Signature,32,#0);
 DerivePublicKey(Signature,PrivateKey1);
 if TRNLMemory.SecureIsEqual(Signature,PublicKey1,32) then begin
  writeln('OK!');
 end else begin
  writeln('FAILED!');
 end;

end;

function TRNLChaCha20Context.GetCounter:TRNLUInt64;
begin
 result:=(TRNLUInt64(fInput[12]) shl 0) or
         (TRNLUInt64(fInput[13]) shl 32);
end;

procedure TRNLChaCha20Context.SetCounter(const aCounter:TRNLUInt64);
begin
 fInput[12]:=aCounter and TRNLUInt32($ffffffff);
 fInput[13]:=aCounter shr 32;
 fPoolIndex:=64;
end;

procedure TRNLChaCha20Context.Initialize(const aKey,aNonce;const aCounter:TRNLUInt64=0);
begin
 fInput[0]:=$61707865;
 fInput[1]:=$3320646e;
 fInput[2]:=$79622d32;
 fInput[3]:=$6b206574;
 fInput[4]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aKey))^[0]);
 fInput[5]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aKey))^[1]);
 fInput[6]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aKey))^[2]);
 fInput[7]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aKey))^[3]);
 fInput[8]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aKey))^[4]);
 fInput[9]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aKey))^[5]);
 fInput[10]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aKey))^[6]);
 fInput[11]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aKey))^[7]);
 fInput[12]:=aCounter and TRNLUInt32($ffffffff);
 fInput[13]:=aCounter shr 32;
 fInput[14]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aNonce))^[0]);
 fInput[15]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aNonce))^[1]);
 FillChar(fPool,SizeOf(TRNLChaCha20State),#0);
 fPoolIndex:=64;
end;

procedure TRNLChaCha20Context.EndianNeutralInitialize(const aKey;const aNonce:TRNLUInt64=0;const aCounter:TRNLUInt64=0);
var LocalNonce:TRNLUInt64;
begin
 TRNLMemoryAccess.StoreBigEndianUInt64(LocalNonce,aNonce);
 Initialize(aKey,LocalNonce,Counter);
end;

class procedure TRNLChaCha20Context.Update(out aOutput:TRNLChaCha20State;const aInput:TRNLChaCha20State);
var Index,x,x00,x01,x02,x03,x04,x05,x06,x07,x08,x09,x10,x11,x12,x13,x14,x15:TRNLUInt32;
begin
 x00:=aInput[0];
 x01:=aInput[1];
 x02:=aInput[2];
 x03:=aInput[3];
 x04:=aInput[4];
 x05:=aInput[5];
 x06:=aInput[6];
 x07:=aInput[7];
 x08:=aInput[8];
 x09:=aInput[9];
 x10:=aInput[10];
 x11:=aInput[11];
 x12:=aInput[12];
 x13:=aInput[13];
 x14:=aInput[14];
 x15:=aInput[15];
 for Index:=1 to 20 shr 1 do begin
  // Two unrolled rounds per loop iteration
  inc(x00,x04);
  x:=x12 xor x00;
  x12:={$ifdef fpc}ROLDWord(x,16){$else}(x shl 16) or (x shr 16){$endif};
  inc(x08,x12);
  x:=x04 xor x08;
  x04:={$ifdef fpc}ROLDWord(x,12){$else}(x shl 12) or (x shr 20){$endif};
  inc(x00,x04);
  x:=x12 xor x00;
  x12:={$ifdef fpc}ROLDWord(x,8){$else}(x shl 8) or (x shr 24){$endif};
  inc(x08,x12);
  x:=x04 xor x08;
  x04:={$ifdef fpc}ROLDWord(x,7){$else}(x shl 7) or (x shr 25){$endif};
  inc(x01,x05);
  x:=x13 xor x01;
  x13:={$ifdef fpc}ROLDWord(x,16){$else}(x shl 16) or (x shr 16){$endif};
  inc(x09,x13);
  x:=x05 xor x09;
  x05:={$ifdef fpc}ROLDWord(x,12){$else}(x shl 12) or (x shr 20){$endif};
  inc(x01,x05);
  x:=x13 xor x01;
  x13:={$ifdef fpc}ROLDWord(x,8){$else}(x shl 8) or (x shr 24){$endif};
  inc(x09,x13);
  x:=x05 xor x09;
  x05:={$ifdef fpc}ROLDWord(x,7){$else}(x shl 7) or (x shr 25){$endif};
  inc(x02,x06);
  x:=x14 xor x02;
  x14:={$ifdef fpc}ROLDWord(x,16){$else}(x shl 16) or (x shr 16){$endif};
  inc(x10,x14);
  x:=x06 xor x10;
  x06:={$ifdef fpc}ROLDWord(x,12){$else}(x shl 12) or (x shr 20){$endif};
  inc(x02,x06);
  x:=x14 xor x02;
  x14:={$ifdef fpc}ROLDWord(x,8){$else}(x shl 8) or (x shr 24){$endif};
  inc(x10,x14);
  x:=x06 xor x10;
  x06:={$ifdef fpc}ROLDWord(x,7){$else}(x shl 7) or (x shr 25){$endif};
  inc(x03,x07);
  x:=x15 xor x03;
  x15:={$ifdef fpc}ROLDWord(x,16){$else}(x shl 16) or (x shr 16){$endif};
  inc(x11,x15);
  x:=x07 xor x11;
  x07:={$ifdef fpc}ROLDWord(x,12){$else}(x shl 12) or (x shr 20){$endif};
  inc(x03,x07);
  x:=x15 xor x03;
  x15:={$ifdef fpc}ROLDWord(x,8){$else}(x shl 8) or (x shr 24){$endif};
  inc(x11,x15);
  x:=x07 xor x11;
  x07:={$ifdef fpc}ROLDWord(x,7){$else}(x shl 7) or (x shr 25){$endif};
  inc(x00,x05);
  x:=x15 xor x00;
  x15:={$ifdef fpc}ROLDWord(x,16){$else}(x shl 16) or (x shr 16){$endif};
  inc(x10,x15);
  x:=x05 xor x10;
  x05:={$ifdef fpc}ROLDWord(x,12){$else}(x shl 12) or (x shr 20){$endif};
  inc(x00,x05);
  x:=x15 xor x00;
  x15:={$ifdef fpc}ROLDWord(x,8){$else}(x shl 8) or (x shr 24){$endif};
  inc(x10,x15);
  x:=x05 xor x10;
  x05:={$ifdef fpc}ROLDWord(x,7){$else}(x shl 7) or (x shr 25){$endif};
  inc(x01,x06);
  x:=x12 xor x01;
  x12:={$ifdef fpc}ROLDWord(x,16){$else}(x shl 16) or (x shr 16){$endif};
  inc(x11,x12);
  x:=x06 xor x11;
  x06:={$ifdef fpc}ROLDWord(x,12){$else}(x shl 12) or (x shr 20){$endif};
  inc(x01,x06);
  x:=x12 xor x01;
  x12:={$ifdef fpc}ROLDWord(x,8){$else}(x shl 8) or (x shr 24){$endif};
  inc(x11,x12);
  x:=x06 xor x11;
  x06:={$ifdef fpc}ROLDWord(x,7){$else}(x shl 7) or (x shr 25){$endif};
  inc(x02,x07);
  x:=x13 xor x02;
  x13:={$ifdef fpc}ROLDWord(x,16){$else}(x shl 16) or (x shr 16){$endif};
  inc(x08,x13);
  x:=x07 xor x08;
  x07:={$ifdef fpc}ROLDWord(x,12){$else}(x shl 12) or (x shr 20){$endif};
  inc(x02,x07);
  x:=x13 xor x02;
  x13:={$ifdef fpc}ROLDWord(x,8){$else}(x shl 8) or (x shr 24){$endif};
  inc(x08,x13);
  x:=x07 xor x08;
  x07:={$ifdef fpc}ROLDWord(x,7){$else}(x shl 7) or (x shr 25){$endif};
  inc(x03,x04);
  x:=x14 xor x03;
  x14:={$ifdef fpc}ROLDWord(x,16){$else}(x shl 16) or (x shr 16){$endif};
  inc(x09,x14);
  x:=x04 xor x09;
  x04:={$ifdef fpc}ROLDWord(x,12){$else}(x shl 12) or (x shr 20){$endif};
  inc(x03,x04);
  x:=x14 xor x03;
  x14:={$ifdef fpc}ROLDWord(x,8){$else}(x shl 8) or (x shr 24){$endif};
  inc(x09,x14);
  x:=x04 xor x09;
  x04:={$ifdef fpc}ROLDWord(x,7){$else}(x shl 7) or (x shr 25){$endif};
 end;
 aOutput[0]:=x00;
 aOutput[1]:=x01;
 aOutput[2]:=x02;
 aOutput[3]:=x03;
 aOutput[4]:=x04;
 aOutput[5]:=x05;
 aOutput[6]:=x06;
 aOutput[7]:=x07;
 aOutput[8]:=x08;
 aOutput[9]:=x09;
 aOutput[10]:=x10;
 aOutput[11]:=x11;
 aOutput[12]:=x12;
 aOutput[13]:=x13;
 aOutput[14]:=x14;
 aOutput[15]:=x15;
end;

class procedure TRNLChaCha20Context.HChaCha20Process(out aOutput;const aKey,aInput);
var State:TRNLChaCha20State;
begin
 State[0]:=$61707865;
 State[1]:=$3320646e;
 State[2]:=$79622d32;
 State[3]:=$6b206574;
 State[4]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aKey))^[0]);
 State[5]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aKey))^[1]);
 State[6]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aKey))^[2]);
 State[7]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aKey))^[3]);
 State[8]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aKey))^[4]);
 State[9]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aKey))^[5]);
 State[10]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aKey))^[6]);
 State[11]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aKey))^[7]);
 State[12]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aInput))^[0]);
 State[13]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aInput))^[1]);
 State[14]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aInput))^[2]);
 State[15]:=TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aInput))^[3]);
 TRNLChaCha20Context.Update(State,State);
 TRNLMemoryAccess.StoreLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aOutput))^[0],State[0]);
 TRNLMemoryAccess.StoreLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aOutput))^[1],State[1]);
 TRNLMemoryAccess.StoreLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aOutput))^[2],State[2]);
 TRNLMemoryAccess.StoreLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aOutput))^[3],State[3]);
 TRNLMemoryAccess.StoreLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aOutput))^[4],State[12]);
 TRNLMemoryAccess.StoreLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aOutput))^[5],State[13]);
 TRNLMemoryAccess.StoreLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aOutput))^[6],State[14]);
 TRNLMemoryAccess.StoreLittleEndianUInt32(PRNLUInt32Array(TRNLPointer(@aOutput))^[7],State[15]);
end;

procedure TRNLChaCha20Context.XChaCha20Initialize(const aKey,aNonce;const aCounter:TRNLUInt64=0);
var DerivedKey:TRNLKey;
begin
 HChaCha20Process(DerivedKey,aKey,aNonce);
 Initialize(DerivedKey,PRNLUInt64(@PRNLUInt8Array(TRNLPointer(@aNonce))^[16])^,0);
end;

procedure TRNLChaCha20Context.RefillPool;
begin
 Update(fPool,fInput);
 inc(fPool[0],fInput[0]);
 inc(fPool[1],fInput[1]);
 inc(fPool[2],fInput[2]);
 inc(fPool[3],fInput[3]);
 inc(fPool[4],fInput[4]);
 inc(fPool[5],fInput[5]);
 inc(fPool[6],fInput[6]);
 inc(fPool[7],fInput[7]);
 inc(fPool[8],fInput[8]);
 inc(fPool[9],fInput[9]);
 inc(fPool[10],fInput[10]);
 inc(fPool[11],fInput[11]);
 inc(fPool[12],fInput[12]);
 inc(fPool[13],fInput[13]);
 inc(fPool[14],fInput[14]);
 inc(fPool[15],fInput[15]);
 fPoolIndex:=0;
 inc(fInput[12]);
 if fInput[12]=0 then begin
  inc(fInput[13]);
 end;
end;

procedure TRNLChaCha20Context.Process(out aCipherText;const aPlainText;const aTextSize:TRNLSizeUInt;const aUsePlainText:boolean=true);
var TextPosition,TextSize:TRNLSizeUInt;
    Plain:TRNLUInt8;
    Index:TRNLUInt32;
begin
 TextPosition:=0;
 TextSize:=aTextSize;
 Plain:=0;
 while ((fPoolIndex and 63)<>0) and (TextSize>0) do begin
  if aUsePlainText then begin
   Plain:=PRNLUInt8Array(TRNLPointer(@aPlainText))^[TextPosition];
  end;
  PRNLUInt8Array(TRNLPointer(@aCipherText))^[TextPosition]:=Plain xor (fPool[fPoolIndex shr 2] shr ((fPoolIndex and 3) shl 3)) and $ff;
  inc(fPoolIndex);
  inc(TextPosition);
  dec(TextSize);
 end;
 if TextSize>=64 then begin
  repeat
   RefillPool;
   if aUsePlainText then begin
    for Index:=0 to 15 do begin
     TRNLMemoryAccess.StoreLittleEndianUInt32(PRNLUInt8Array(TRNLPointer(@aCipherText))^[TextPosition+(Index shl 2)],
                                              TRNLMemoryAccess.LoadLittleEndianUInt32(PRNLUInt8Array(TRNLPointer(@aPlainText))^[TextPosition+(Index shl 2)]) xor fPool[Index]);
    end;
   end else begin
    for Index:=0 to 15 do begin
     TRNLMemoryAccess.StoreLittleEndianUInt32(PRNLUInt8Array(TRNLPointer(@aCipherText))^[TextPosition+(Index shl 2)],
                                              fPool[Index]);
    end;
   end;
   inc(TextPosition,64);
   dec(TextSize,64);
  until TextSize<64;
  fPoolIndex:=64;
 end;
 while TextSize>0 do begin
  if fPoolIndex=64 then begin
   RefillPool;
  end;
  if aUsePlainText then begin
   Plain:=PRNLUInt8Array(TRNLPointer(@aPlainText))^[TextPosition];
  end;
  PRNLUInt8Array(TRNLPointer(@aCipherText))^[TextPosition]:=Plain xor (fPool[fPoolIndex shr 2] shr ((fPoolIndex and 3) shl 3)) and $ff;
  inc(fPoolIndex);
  inc(TextPosition);
  dec(TextSize);
 end;
end;

procedure TRNLChaCha20Context.Stream(out aCipherText;const aTextSize:TRNLSizeUInt);
begin
 Process(aCipherText,TRNLPointer(nil)^,aTextSize,false);
end;

class procedure TRNLChaCha20.SelfTest;
begin
end;

class function TRNLKeyExchange.Process(out aSharedKey:TRNLKey;const aYourSecretKey,aTheirPublicKey:TRNLKey):boolean;
const Zero:array[0..15] of TRNLUInt8=(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
var SharedSecret:TRNLKey;
begin
 result:=TRNLCurve25519.Eval(SharedSecret,aYourSecretKey,@aTheirPublicKey);
 TRNLChaCha20Context.HChaCha20Process(aSharedKey,SharedSecret,Zero);
end;

class procedure TRNLAuthenticatedEncryption.Authenticate(out aMAC;const aAuthKey,aT1;const aT1Size:TRNLSizeUInt;const aT2;const aT2Size:TRNLSizeUInt);
var Context:TRNLPoly1305Context;
begin
 Context.Initialize(aAuthKey);
 Context.Update(aT1,aT1Size);
 Context.Update(aT2,aT2Size);
 Context.Finalize(aMAC);
end;

class function TRNLAuthenticatedEncryption.Encrypt(out aCipherText;const aKey,aNonce;out aMAC;const aAssociatedData;const aAssociatedDataSize:TRNLSizeUInt;const aPlainText;const aPlainTextSize:TRNLSizeUInt):boolean;
var AuthKey:TRNLKey;
    Context:TRNLChaCha20Context;
begin
 Context.XChaCha20Initialize(aKey,aNonce,0);
 Context.Stream(AuthKey,SizeOf(TRNLKey));
 Context.Process(aCipherText,aPlainText,aPlainTextSize);
 Authenticate(aMAC,AuthKey,aAssociatedData,aAssociatedDataSize,aCipherText,aPlainTextSize);
 result:=true;
end;

class function TRNLAuthenticatedEncryption.Encrypt(out aCipherText;const aKey,aNonce;out aMAC;const aPlainText;const aPlainTextSize:TRNLSizeUInt):boolean;
begin
 result:=Encrypt(aCipherText,aKey,aNonce,aMAC,TRNLPointer(nil)^,0,aPlainText,aPlainTextSize);
end;

class function TRNLAuthenticatedEncryption.Decrypt(out aPlainText;const aKey,aNonce,aMAC,aAssociatedData;const aAssociatedDataSize:TRNLSizeUInt;const aCipherText;const aCipherTextSize:TRNLSizeUInt):boolean;
var AuthKey:TRNLKey;
    RealMAC:array[0..15] of TRNLUInt8;
    Context:TRNLChaCha20Context;
begin
 Context.XChaCha20Initialize(aKey,aNonce,0);
 Context.Stream(AuthKey,SizeOf(TRNLKey));
 Authenticate(RealMAC,AuthKey,aAssociatedData,aAssociatedDataSize,aCipherText,aCipherTextSize);
 result:=TRNLMemory.SecureIsEqual(aMAC,RealMAC,16);
 if result then begin
  Context.Process(aPlainText,aCipherText,aCipherTextSize,true);
 end;
end;

class function TRNLAuthenticatedEncryption.Decrypt(out aPlainText;const aKey,aNonce,aMAC,aCipherText;const aCipherTextSize:TRNLSizeUInt):boolean;
begin
 result:=Decrypt(aPlainText,aKey,aNonce,aMac,TRNLPointer(nil)^,0,aCipherText,aCipherTextSize);
end;

constructor TRNLCircularDoublyLinkedListNode<T>.TValueEnumerator.Create(const aCircularDoublyLinkedList:TRNLCircularDoublyLinkedListNode<T>);
begin
 fCircularDoublyLinkedList:=aCircularDoublyLinkedList;
 fNode:=aCircularDoublyLinkedList;
end;

function TRNLCircularDoublyLinkedListNode<T>.TValueEnumerator.GetCurrent:T;
begin
 result:=fNode.fValue;
end;

function TRNLCircularDoublyLinkedListNode<T>.TValueEnumerator.MoveNext:boolean;
begin
 result:=fCircularDoublyLinkedList.fNext<>fCircularDoublyLinkedList;
 if result then begin
  fNode:=fNode.fNext;
  result:=assigned(fNode) and (fNode<>fCircularDoublyLinkedList);
 end;
end;

constructor TRNLCircularDoublyLinkedListNode<T>.Create;
begin
 inherited Create;
 fNext:=self;
 fPrevious:=self;
 Initialize(fValue);
end;

destructor TRNLCircularDoublyLinkedListNode<T>.Destroy;
begin
 Finalize(fValue);
 if fNext<>self then begin
  Remove;
 end;
 inherited Destroy;
end;

procedure TRNLCircularDoublyLinkedListNode<T>.Clear;
begin
 fNext:=self;
 fPrevious:=self;
 Finalize(fValue);
 Initialize(fValue);
end;

function TRNLCircularDoublyLinkedListNode<T>.Head:TRNLCircularDoublyLinkedListNode<T>;
begin
 result:=fNext;
end;

function TRNLCircularDoublyLinkedListNode<T>.Tail:TRNLCircularDoublyLinkedListNode<T>;
begin
 result:=self;
end;

function TRNLCircularDoublyLinkedListNode<T>.Empty:boolean;
begin
 result:=fNext=self;
end;

function TRNLCircularDoublyLinkedListNode<T>.Front:TRNLCircularDoublyLinkedListNode<T>;
begin
 result:=fNext;
end;

function TRNLCircularDoublyLinkedListNode<T>.Back:TRNLCircularDoublyLinkedListNode<T>;
begin
 result:=fPrevious;
end;

function TRNLCircularDoublyLinkedListNode<T>.Insert(const aData:TRNLCircularDoublyLinkedListNode<T>):TRNLCircularDoublyLinkedListNode<T>;
var Position:TRNLCircularDoublyLinkedListNode<T>;
begin
 Position:=self;
 result:=aData;
 result.fPrevious:=Position.fPrevious;
 result.fNext:=Position;
 result.fPrevious.fNext:=result;
 Position.fPrevious:=result;
end;

function TRNLCircularDoublyLinkedListNode<T>.Add(const aData:TRNLCircularDoublyLinkedListNode<T>):TRNLCircularDoublyLinkedListNode<T>;
var Position:TRNLCircularDoublyLinkedListNode<T>;
begin
 Position:=Previous;
 result:=aData;
 result.fPrevious:=Position.fPrevious;
 result.fNext:=Position;
 result.fPrevious.fNext:=result;
 Position.fPrevious:=result;
end;

function TRNLCircularDoublyLinkedListNode<T>.Remove:TRNLCircularDoublyLinkedListNode<T>;
begin
 fPrevious.fNext:=fNext;
 fNext.fPrevious:=fPrevious;
 fPrevious:=self;
 fNext:=self;
 result:=self;
end;

function TRNLCircularDoublyLinkedListNode<T>.Move(const aDataFirst,aDataLast:TRNLCircularDoublyLinkedListNode<T>):TRNLCircularDoublyLinkedListNode<T>;
var First,Last:TRNLCircularDoublyLinkedListNode<T>;
begin
 First:=aDataFirst;
 Last:=aDataLast;
 First.fPrevious.fNext:=Last.fNext;
 Last.fNext.fPrevious:=First.fPrevious;
 First.fPrevious:=fPrevious;
 Last.fNext:=self;
 First.fPrevious.fNext:=First;
 fPrevious:=Last;
 result:=First;
end;

function TRNLCircularDoublyLinkedListNode<T>.PopFromFront(out aData):boolean;
begin
 result:=fNext<>self;
 if result then begin
  TRNLCircularDoublyLinkedListNode<T>(aData):=fNext;
  fNext.Remove;
 end;
end;

function TRNLCircularDoublyLinkedListNode<T>.PopFromBack(out aData):boolean;
begin
 result:=fNext<>self;
 if result then begin
  TRNLCircularDoublyLinkedListNode<T>(aData):=fPrevious;
  fPrevious.Remove;
 end;
end;

function TRNLCircularDoublyLinkedListNode<T>.ListSize:TRNLInt32;
var Position:TRNLCircularDoublyLinkedListNode<T>;
begin
 result:=0;
 if assigned(self) then begin
  Position:=Next;
  while Position<>self do begin
   inc(result);
   Position:=Position.fNext;
  end;
 end;
end;

function TRNLCircularDoublyLinkedListNode<T>.GetEnumerator:TRNLCircularDoublyLinkedListNode<T>.TValueEnumerator;
begin
 result:=TValueEnumerator.Create(self);
end;

constructor TRNLQueue<T>.Create;
begin
 inherited Create;
 fItems:=nil;
 fHead:=0;
 fTail:=0;
 fCount:=0;
 fSize:=0;
end;

destructor TRNLQueue<T>.Destroy;
begin
 inherited Destroy;
end;

function TRNLQueue<T>.GetCount:TRNLSizeInt;
begin
 result:=fCount;
end;

procedure TRNLQueue<T>.Clear;
begin
 while fCount>0 do begin
  dec(fCount);
  Finalize(fItems[fHead]);
  inc(fHead);
  if fHead>=fSize then begin
   fHead:=0;
  end;
 end;
 fItems:=nil;
 fHead:=0;
 fTail:=0;
 fCount:=0;
 fSize:=0;
end;

function TRNLQueue<T>.IsEmpty:boolean;
begin
 result:=fCount=0;
end;

procedure TRNLQueue<T>.GrowResize(const aSize:TRNLSizeInt);
var Index,OtherIndex:TRNLSizeInt;
    NewItems:TRNLQueueItems;
begin
 SetLength(NewItems,aSize);
 OtherIndex:=fHead;
 for Index:=0 to fCount-1 do begin
  NewItems[Index]:=fItems[OtherIndex];
  inc(OtherIndex);
  if OtherIndex>=fSize then begin
   OtherIndex:=0;
  end;
 end;
 fItems:=NewItems;
 fHead:=0;
 fTail:=fCount;
 fSize:=aSize;
end;

procedure TRNLQueue<T>.EnqueueAtFront(const aItem:T);
var Index:TRNLSizeInt;
begin
 if fSize<=fCount then begin
  GrowResize(fCount+1);
 end;
 dec(fHead);
 if fHead<0 then begin
  inc(fHead,fSize);
 end;
 Index:=fHead;
 fItems[Index]:=aItem;
 inc(fCount);
end;

procedure TRNLQueue<T>.Enqueue(const aItem:T);
var Index:TRNLSizeInt;
begin
 if fSize<=fCount then begin
  GrowResize(fCount+1);
 end;
 Index:=fTail;
 inc(fTail);
 if fTail>=fSize then begin
  fTail:=0;
 end;
 fItems[Index]:=aItem;
 inc(fCount);
end;

function TRNLQueue<T>.Dequeue(out aItem:T):boolean;
begin
 result:=fCount>0;
 if result then begin
  dec(fCount);
  aItem:=fItems[fHead];
  Finalize(fItems[fHead]);
  FillChar(fItems[fHead],SizeOf(T),#0);
  if fCount=0 then begin
   fHead:=0;
   fTail:=0;
  end else begin
   inc(fHead);
   if fHead>=fSize then begin
    fHead:=0;
   end;
  end;
 end;
end;

function TRNLQueue<T>.Dequeue:boolean;
begin
 result:=fCount>0;
 if result then begin
  dec(fCount);
  Finalize(fItems[fHead]);
  FillChar(fItems[fHead],SizeOf(T),#0);
  if fCount=0 then begin
   fHead:=0;
   fTail:=0;
  end else begin
   inc(fHead);
   if fHead>=fSize then begin
    fHead:=0;
   end;
  end;
 end;
end;

function TRNLQueue<T>.Peek(out aItem:T):boolean;
begin
 result:=fCount>0;
 if result then begin
  aItem:=fItems[fHead];
 end;
end;

constructor TRNLStack<T>.Create;
begin
 inherited Create;
 fItems:=nil;
 fCount:=0;
end;

destructor TRNLStack<T>.Destroy;
begin
 inherited Destroy;
end;

function TRNLStack<T>.GetCount:TRNLSizeInt;
begin
 result:=fCount;
end;

procedure TRNLStack<T>.Clear;
begin
 while fCount>0 do begin
  dec(fCount);
  Finalize(fItems[fCount]);
 end;
end;

function TRNLStack<T>.IsEmpty:boolean;
begin
 result:=fCount=0;
end;

procedure TRNLStack<T>.Push(const aItem:T);
var Index:TRNLSizeInt;
begin
 Index:=fCount;
 inc(fCount);
 if length(fItems)<fCount then begin
  SetLength(fItems,fCount+fCount);
 end;
 fItems[Index]:=aItem;
end;

function TRNLStack<T>.Pop(out aItem:T):boolean;
begin
 result:=fCount>0;
 if result then begin
  dec(fCount);
  aItem:=fItems[fCount];
  Finalize(fItems[fCount]);
 end;
end;

function TRNLStack<T>.Peek(out aItem:T):boolean;
begin
 result:=fCount>0;
 if result then begin
  aItem:=fItems[fCount-1];
 end;
end;

constructor TRNLObjectList<T>.TValueEnumerator.Create(const aObjectList:TRNLObjectList<T>);
begin
 fObjectList:=aObjectList;
 fIndex:=-1;
end;

function TRNLObjectList<T>.TValueEnumerator.MoveNext:boolean;
begin
 inc(fIndex);
 result:=fIndex<fObjectList.fCount;
end;

function TRNLObjectList<T>.TValueEnumerator.GetCurrent:T;
begin
 result:=fObjectList.fItems[fIndex];
end;

constructor TRNLObjectList<T>.Create(const aOwnObjects:boolean);
begin
 inherited Create;
 fItems:=nil;
 fCount:=0;
 fAllocated:=0;
 fOwnObjects:=aOwnObjects;
end;

destructor TRNLObjectList<T>.Destroy;
begin
 Clear;
 inherited Destroy;
end;

procedure TRNLObjectList<T>.Clear;
var Index:TRNLSizeInt;
begin
 if fOwnObjects then begin
  for Index:=0 to fCount-1 do begin
   FreeAndNil(fItems[Index]);
  end;
 end;
 SetLength(fItems,0);
 fCount:=0;
 fAllocated:=0;
end;

function TRNLObjectList<T>.GetItem(const pIndex:TRNLSizeInt):T;
begin
 if (pIndex<0) or (pIndex>=fCount) then begin
  raise ERangeError.Create('Out of index range');
 end;
 result:=fItems[pIndex];
end;

procedure TRNLObjectList<T>.SetItem(const pIndex:TRNLSizeInt;const pItem:T);
begin
 if (pIndex<0) or (pIndex>=fCount) then begin
  raise ERangeError.Create('Out of index range');
 end;
 fItems[pIndex]:=pItem;
end;

procedure TRNLObjectList<T>.Assign(const pFrom:TRNLObjectList<T>);
begin
 fItems:=pFrom.fItems;
 fCount:=pFrom.Count;
 fAllocated:=pFrom.fAllocated;
end;

function TRNLObjectList<T>.IndexOf(const pItem:T):TRNLSizeInt;
var Index:TRNLSizeInt;
begin
 for Index:=0 to fCount-1 do begin
  if fItems[Index]=pItem then begin
   result:=Index;
   exit;
  end;
 end;
 result:=-1;
end;

function TRNLObjectList<T>.Add(const pItem:T):TRNLSizeInt;
begin
 result:=fCount;
 inc(fCount);
 if fAllocated<fCount then begin
  fAllocated:=fCount+fCount;
  SetLength(fItems,fAllocated);
 end;
 fItems[result]:=pItem;
end;

procedure TRNLObjectList<T>.Insert(const pIndex:TRNLSizeInt;const pItem:T);
begin
 if pIndex>=0 then begin
  if pIndex<fCount then begin
   inc(fCount);
   if fCount<fAllocated then begin
    fAllocated:=fCount shl 1;
    SetLength(fItems,fAllocated);
   end;
   Move(fItems[pIndex],fItems[pIndex+1],(fCount-(pIndex+1))*SizeOf(T));
   FillChar(fItems[pIndex],SizeOf(T),#0);
  end else begin
   fCount:=pIndex+1;
   if fCount<fAllocated then begin
    fAllocated:=fCount shl 1;
    SetLength(fItems,fAllocated);
   end;
  end;
  fItems[pIndex]:=pItem;
 end;
end;

procedure TRNLObjectList<T>.Delete(const pIndex:TRNLSizeInt);
begin
 if (pIndex<0) or (pIndex>=fCount) then begin
  raise ERangeError.Create('Out of index range');
 end;
 if fOwnObjects then begin
  FreeAndNil(fItems[pIndex]);
 end;
 pointer(fItems[pIndex]):=nil;
 Move(fItems[pIndex+1],fItems[pIndex],(fCount-pIndex)*SizeOf(T));
 dec(fCount);
 FillChar(fItems[fCount],SizeOf(T),#0);
 if fCount<(fAllocated shr 1) then begin
  fAllocated:=fAllocated shr 1;
  SetLength(fItems,fAllocated);
 end;
end;

procedure TRNLObjectList<T>.Remove(const pItem:T);
var Index:TRNLSizeInt;
begin
 Index:=IndexOf(pItem);
 if Index>=0 then begin
  Delete(Index);
 end;
end;

procedure TRNLObjectList<T>.Exchange(const pIndex,pWithIndex:TRNLSizeInt);
var Temporary:T;
begin
 if ((pIndex<0) or (pIndex>=fCount)) or ((pWithIndex<0) or (pWithIndex>=fCount)) then begin
  raise ERangeError.Create('Out of index range');
 end;
 Temporary:=fItems[pIndex];
 fItems[pIndex]:=fItems[pWithIndex];
 fItems[pWithIndex]:=Temporary;
end;

function TRNLObjectList<T>.GetEnumerator:TRNLObjectList<T>.TValueEnumerator;
begin
 result:=TValueEnumerator.Create(self);
end;

constructor TRNLBits.Create(const aSize:TRNLSizeInt);
begin
 inherited Create;
 fData:=nil;
 fSize:=aSize;
 SetLength(fData,(fSize+31) shr 5);
 if length(fData)>0 then begin
  FillChar(fData[0],length(fData)*SizeOf(TRNLUInt32),#0);
 end;
end;

destructor TRNLBits.Destroy;
begin
 fData:=nil;
 inherited Destroy;
end;

procedure TRNLBits.Clear;
begin
 if length(fData)>0 then begin
  FillChar(fData[0],length(fData)*SizeOf(TRNLUInt32),#0);
 end;
end;

function TRNLBits.GetNextSetBitIndex(const aIndex:TRNLSizeInt=-1):TRNLSizeInt;
var Index,ElementIndex:TRNLSizeInt;
    Element:TRNLUInt32;
begin
 Index:=aIndex+1;
 while Index<fSize do begin
  ElementIndex:=Index shr 5;
  Element:=fData[ElementIndex] and not ((TRNLUInt32(1) shl (Index and 31))-1);
  if Element<>0 then begin
   result:=(ElementIndex shl 5) or TRNLSizeInt({$ifdef fpc}BSFDWord{$else}RawBitScanForwardUInt32{$endif}(Element));
   exit;
  end else begin
   inc(Index,32);
  end;
 end;
 result:=-1;
end;

function TRNLBits.GetBit(const aIndex:TRNLSizeInt):boolean;
begin
 result:=(fData[aIndex shr 5] and (TRNLUInt32(1) shl (aIndex and 31)))<>0;
end;

procedure TRNLBits.SetBit(const aIndex:TRNLSizeInt;const aBit:boolean);
var Index:TRNLSizeUInt;
    Mask:TRNLUInt32;
begin
 Index:=aIndex shr 5;
 Mask:=TRNLUInt32(1) shl (aIndex and 31);
 if aBit then begin
  fData[Index]:=fData[Index] or Mask;
 end else begin
  fData[Index]:=fData[Index] and not Mask;
 end;
end;

constructor TRNLIDManager.Create;
begin
 inherited Create;
 fIDCounter:=0;
 fFreeStack:=TRNLIDManagerFreeStack.Create;
end;

destructor TRNLIDManager.Destroy;
begin
 fFreeStack.Free;
 inherited Destroy;
end;

function TRNLIDManager.AllocateID:TRNLID;
begin
 if not fFreeStack.Pop(result) then begin
  result:=fIDCounter;
  inc(fIDCounter);
 end;
end;

procedure TRNLIDManager.FreeID(const aID:TRNLID);
begin
 fFreeStack.Push(aID);
end;

constructor TRNLIDMap<T>.Create;
begin
 inherited Create;
 fItems:=nil;
 fCount:=0;
end;

destructor TRNLIDMap<T>.Destroy;
begin
 fItems:=nil;
 inherited Destroy;
end;

function TRNLIDMap<T>.GetItem(const aID:TRNLID):T;
begin
 if aID<fCount then begin
  result:=fItems[aID];
 end else begin
  pointer(result):=nil;
 end;
end;

procedure TRNLIDMap<T>.SetItem(const aID:TRNLID;const aItem:T);
var OldCount:TRNLSizeUInt;
begin
 OldCount:=fCount;
 if OldCount<=aID then begin
  fCount:=TRNLSizeUInt(aID+1)*2;
  SetLength(fItems,fCount);
  FillChar(fItems[OldCount],(fCount-OldCount)*TRNLSizeUInt(SizeOf(T)),#0);
 end;
 fItems[aID]:=aItem;
end;

{$ifdef Windows}
function __WSAFDIsSet(s:TRNLSocket;var FDSet:TRNLSocketSet):bool; stdcall; external 'ws2_32.dll' name '__WSAFDIsSet';

procedure FD_CLR(const Socket:TRNLSocket;var FDSet:TRNLSocketSet);
var i:TRNLUInt32;
begin
 i:=0;
 while i<FDSet.fd_count do begin
  if FDSet.fd_array[i]=Socket then begin
   while i<FDSet.fd_count-1 do begin
    FDSet.fd_array[i]:=FDSet.fd_array[i+1];
    inc(i);
   end;
   dec(FDSet.fd_count);
   break;
  end;
  inc(i);
 end;
end;

function FD_ISSET(const Socket:TRNLSocket;var FDSet:TRNLSocketSet):Boolean;
begin
 result:=__WSAFDIsSet(Socket,FDSet);
end;

procedure FD_SET(const Socket:TRNLSocket;var FDSet:TRNLSocketSet);
begin
 if FDSet.fd_count<RNL_FD_SETSIZE then begin
  FDSet.fd_array[FDSet.fd_count]:=Socket;
  inc(FDSet.fd_count);
 end;
end;

procedure FD_ZERO(var FDSet:TRNLSocketSet);
begin
 FDSet.fd_count:=0;
end;
{$endif}

class function TRNLSocketSetHelper.Empty:TRNLSocketSet;
begin
{$if defined(Posix)}
 __FD_ZERO(result);
{$elseif defined(Unix)}
 fpFD_ZERO(result);
{$else}
 FD_ZERO(result);
{$ifend}
end;

procedure TRNLSocketSetHelper.Add(const aSocket:TRNLSocket);
begin
{$if defined(Posix)}
 __FD_SET(aSocket,self);
{$elseif defined(Unix)}
 fpFD_SET(aSocket,self);
{$else}
 FD_SET(aSocket,self);
{$ifend}
end;

procedure TRNLSocketSetHelper.Remove(const aSocket:TRNLSocket);
begin
{$if defined(Posix)}
 __FD_CLR(aSocket,self);
{$elseif defined(Unix)}
 fpFD_CLR(aSocket,self);
{$else}
 FD_CLR(aSocket,self);
{$ifend}
end;

function TRNLSocketSetHelper.Check(const aSocket:TRNLSocket):boolean;
begin
{$if defined(Posix)}
 result:=__FD_ISSET(aSocket,self);
{$elseif defined(Unix)}
 result:=fpFD_ISSET(aSocket,self)=1;
{$else}
 result:=FD_ISSET(aSocket,self);
{$ifend}
end;

constructor TRNLHostAddress.CreateFromIPV4(Address:TRNLUInt32);
begin
 self:=RNL_IPV4MAPPED_PREFIX_INIT;
 TRNLUInt32(TRNLPointer(@Addr[12])^):=Address;
end;

function TRNLHostAddress.Equals(const aWith:TRNLHostAddress):boolean;
begin
 result:=(PRNLUInt64Array(TRNLPointer(@self))^[0]=PRNLUInt64Array(TRNLPointer(@aWith))^[0]) and
         (PRNLUInt64Array(TRNLPointer(@self))^[1]=PRNLUInt64Array(TRNLPointer(@aWith))^[1]);
end;

function TRNLAddress.GetAddressFamily:TRNLAddressFamily;
begin
 if (Host.Addr[0]=RNL_IPV4MAPPED_PREFIX.Addr[0]) and
    (Host.Addr[1]=RNL_IPV4MAPPED_PREFIX.Addr[1]) and
    (Host.Addr[2]=RNL_IPV4MAPPED_PREFIX.Addr[2]) and
    (Host.Addr[3]=RNL_IPV4MAPPED_PREFIX.Addr[3]) and
    (Host.Addr[4]=RNL_IPV4MAPPED_PREFIX.Addr[4]) and
    (Host.Addr[5]=RNL_IPV4MAPPED_PREFIX.Addr[5]) and
    (Host.Addr[6]=RNL_IPV4MAPPED_PREFIX.Addr[6]) and
    (Host.Addr[7]=RNL_IPV4MAPPED_PREFIX.Addr[7]) and
    (Host.Addr[8]=RNL_IPV4MAPPED_PREFIX.Addr[8]) and
    (Host.Addr[9]=RNL_IPV4MAPPED_PREFIX.Addr[9]) and
    (Host.Addr[10]=RNL_IPV4MAPPED_PREFIX.Addr[10]) and
    (Host.Addr[11]=RNL_IPV4MAPPED_PREFIX.Addr[11]) then begin
  result:=RNL_IPV4;
 end else begin
  result:=RNL_IPV6;
 end;
end;

var RNLInitializationReferenceCounter:TRNLInt32=0;

    RNLNetworkInitializationReferenceCounter:TRNLInt32=0;

{$if defined(Unix) or defined(Posix)}
const SOCKET_ERROR=-1;

{$if defined(Linux) or defined(Android)}
      SOCK_CLOEXEC=$02000000;
{$ifend}

{$ifdef fpc}
      AI_ADDRCONFIG=$0400;
{$endif}

{$if defined(Linux) or defined(Android)}
      IP_MTU_DISCOVER=10;
      IP_MTU=14;

      IP_NODEFRAG=22;

      IP_PMTUDISC_DONT=0;
      IP_PMTUDISC_WANT=1;
      IP_PMTUDISC_DO=2;
      IP_PMTUDISC_PROBE=3;
      IP_PMTUDISC_INTERFACE=4;
      IP_PMTUDISC_OMIT=5;
{$elseif defined(AIX)}
      IP_DONTFRAG=25;
{$elseif defined(Solaris)}
      IP_DONTFRAG=27;
{$elseif defined(Darwin)}
      IP_DONTFRAG=67; // TODO: Check
{$elseif defined(NetBSD)}
      IP_DONTFRAG=$4000;
{$elseif defined(BSD) or defined(FreeBSD)}
      IP_DONTFRAG=67;
{$ifend}

{$ifndef fpc}
{$if defined(Linux) or defined(Android)}
     FIONREAD=$541;
     FIONBIO=$5421;
     FIOASYNC=$5452;
{$else}
     FIONBIO=$8004667e;
     FIOASYNC=$8004667d;
{$ifend}
{$endif}

type PSockaddrStorage=^TSockaddrStorage;
     TSockaddrStorage=record
      ss_family:TRNLUInt16;
      _ss_pad1:array[0..5] of TRNLUInt8;
      _ss_align:TRNLInt64;
      _ss_pad2:array[0..119] of TRNLUInt8;
     end;

{$if defined(Posix)}
     TAddrInfo=AddrInfo;
{$ifend}

class procedure TRNLInstance.GlobalInitialize;
begin
end;

class procedure TRNLInstance.GlobalFinalize;
begin
end;

function TRNLInstance.GetTime:TRNLTime;
{$if defined(fpc)}
var tv:TTimeVal;
begin
 fpgettimeofday(@tv,nil);
 result:=((TRNLUInt64(tv.tv_sec)*1000)+(TRNLUInt64(tv.tv_usec) div 1000))-fTimeBase;
end;
{$else}
var tv:TimeVal;
begin
 gettimeofday(tv,nil);
 result:=((TRNLUInt64(tv.tv_sec)*1000)+(TRNLUInt64(tv.tv_usec) div 1000))-fTimeBase;
end;
{$ifend}

procedure TRNLInstance.SetTime(const aTimeBase:TRNLTime);
begin
 fTimeBase:=(GetTime+fTimeBase)-aTimeBase;
end;

function TRNLAddressFamilyHelper.GetAddressFamily:TRNLUInt16;
begin
 case self of
  RNL_IPV4:begin
   result:=AF_INET;
  end;
  RNL_IPV6:begin
   result:=AF_INET6;
  end;
  else begin
   result:=0;
  end;
 end;
end;

function TRNLAddressFamilyHelper.GetSockAddrSize:TRNLInt32;
begin
 case self of
  RNL_IPV4:begin
   result:=SizeOf(sockaddr_in);
  end;
  RNL_IPV6:begin
   result:=SizeOf(sockaddr_in6);
  end;
  else begin
   result:=0;
  end;
 end;
end;

function TRNLAddress.SetAddress(const aSIN:TRNLPointer):TRNLAddressFamily;
begin
 FillChar(self,SizeOf(TRNLAddress),#0);
 case Psockaddr_in(aSIN)^.sin_family of
  AF_INET:begin
   Host:=TRNLHostAddress.CreateFromIPV4(Psockaddr_in(aSIN)^.sin_addr.S_addr);
   ScopeID:=0;
   Port:=TRNLEndianness.NetToHost16(Psockaddr_in(aSIN)^.sin_port);
   result:=RNL_IPV4;
  end;
  AF_INET6:begin
   Host:=PRNLHostAddress(TRNLPointer(@Psockaddr_in6(aSIN)^.sin6_addr))^;
   ScopeID:=Psockaddr_in6(aSIN)^.sin6_scope_id;
   Port:=TRNLEndianness.NetToHost16(Psockaddr_in6(aSIN)^.sin6_port);
   result:=RNL_IPV6;
  end;
  else begin
   result:=RNL_NO_ADDRESS_FAMILY;
  end;
 end;
end;

function TRNLAddress.SetSIN(const aSIN:TRNLPointer;const aFamily:TRNLAddressFamily):boolean;
begin
 FillChar(aSIN^,aFamily.GetSockAddrSize,#0);
 if (aFamily=RNL_IPV4) and
    ((GetAddressFamily=RNL_IPV4) or
     ((Host.Addr[0]=RNL_HOST_ANY.Addr[0]) and
      (Host.Addr[1]=RNL_HOST_ANY.Addr[1]) and
      (Host.Addr[2]=RNL_HOST_ANY.Addr[2]) and
      (Host.Addr[3]=RNL_HOST_ANY.Addr[3]) and
      (Host.Addr[4]=RNL_HOST_ANY.Addr[4]) and
      (Host.Addr[5]=RNL_HOST_ANY.Addr[5]) and
      (Host.Addr[6]=RNL_HOST_ANY.Addr[6]) and
      (Host.Addr[7]=RNL_HOST_ANY.Addr[7]) and
      (Host.Addr[8]=RNL_HOST_ANY.Addr[8]) and
      (Host.Addr[9]=RNL_HOST_ANY.Addr[9]) and
      (Host.Addr[10]=RNL_HOST_ANY.Addr[10]) and
      (Host.Addr[11]=RNL_HOST_ANY.Addr[11]) and
      (Host.Addr[12]=RNL_HOST_ANY.Addr[12]) and
      (Host.Addr[13]=RNL_HOST_ANY.Addr[13]) and
      (Host.Addr[14]=RNL_HOST_ANY.Addr[14]) and
      (Host.Addr[15]=RNL_HOST_ANY.Addr[15]))) then begin
  Psockaddr_in(aSIN)^.sin_family:=AF_INET;
  Psockaddr_in(aSIN)^.sin_addr.S_addr:=TRNLUInt32(TRNLPointer(@Host.Addr[12])^);
  Psockaddr_in(aSIN)^.sin_port:=TRNLEndianness.HostToNet16(Port);
  result:=true;
 end else if aFamily=RNL_IPV6 then begin
  Psockaddr_in6(aSIN)^.sin6_family:=AF_INET6;
  PRNLHostAddress(TRNLPointer(@Psockaddr_in6(aSIN)^.sin6_addr))^:=Host;
  Psockaddr_in6(aSIN)^.sin6_scope_id:=ScopeID;
  Psockaddr_in6(aSIN)^.sin6_port:=TRNLEndianness.HostToNet16(Port);
  result:=true;
 end else begin
  result:=false;
 end;
end;

{$else}
const AF_UNSPEC=0;
      AF_INET=2;
      AF_INET6=23;
      AF_MAX=24;

      AI_ADDRCONFIG=$0400;

      NI_NUMERICHOST=$2;

      IPPROTO_IP=0;
      IPPROTO_TCP=6;
      IPPROTO_UDP=17;
      IPPROTO_IPV6=41;

      IPV6_V6ONLY=26;

      WSADESCRIPTION_LEN=256;
      WSASYS_STATUS_LEN=128;

      SOCKET_ERROR=-1;

      SOMAXCONN=$7fffffff;

      SOCK_STREAM=1;
      SOCK_DGRAM=2;
      SOCK_RAW=3;
      SOCK_RDM=4;
      SOCK_SEQPACKET=5;

      IOC_IN=$80000000;

      FIONBIO=IOC_IN or (SizeOf(TRNLInt32) shl 16) or (Ord('f') shl 8) or 126;

      SOL_SOCKET=$ffff;

      SO_DEBUG=$0001;
      SO_ACCEPTCONN=$0002;
      SO_REUSEADDR=$0004;
      SO_KEEPALIVE=$0008;
      SO_DONTROUTE=$0010;
      SO_BROADCAST=$0020;
      SO_USELOOPBACK=$0040;
      SO_LINGER=$0080;
      SO_OOBINLINE=$0100;
      SO_DONTLINGER=not SO_LINGER;
      SO_EXCLUSIVEADDRUSE=not SO_REUSEADDR;
      SO_SNDBUF=$1001;
      SO_RCVBUF=$1002;      
      SO_SNDLOWAT=$1003;      
      SO_RCVLOWAT=$1004;      
      SO_SNDTIMEO=$1005;
      SO_RCVTIMEO=$1006;      
      SO_ERROR=$1007;
      SO_TYPE=$1008;
      SO_CONNDATA=$7000;
      SO_CONNOPT=$7001;
      SO_DISCDATA=$7002;
      SO_DISCOPT=$7003;
      SO_CONNDATALEN=$7004;
      SO_CONNOPTLEN=$7005;
      SO_DISCDATALEN=$7006;
      SO_DISCOPTLEN=$7007;
      SO_OPENTYPE=$7008;
      SO_SYNCHRONOUS_ALERT=$10;
      SO_SYNCHRONOUS_NONALERT=$20;
      SO_MAXDG=$7009;
      SO_MAXPATHDG=$700A;
      SO_UPDATE_ACCEPT_CONTEXT=$700B;
      SO_CONNECT_TIME=$700C;
      TCP_NODELAY=$0001;
      TCP_BSDURGENT=$7000;
      SO_GROUP_ID=$2001;
      SO_GROUP_PRIORITY=$2002;
      SO_MAX_MSG_SIZE=$2003;
      SO_Protocol_InfoA=$2004;
      SO_Protocol_InfoW=$2005;
      SO_Protocol_Info=SO_Protocol_InfoA;
      PVD_CONFIG=$3001;
      SO_CONDITIONAL_ACCEPT=$3002;

      IP_DONTFRAGMENT=14;

      IP_DONTFRAG=$1023;

      WSABASEERR=10000;

      WSAEINTR=WSABASEERR+4;
      WSAEBADF=WSABASEERR+9;
      WSAEACCES=WSABASEERR+13;
      WSAEFAULT=WSABASEERR+14;
      WSAEINVAL=WSABASEERR+22;
      WSAEMFILE=WSABASEERR+24;
      WSAEWOULDBLOCK=WSABASEERR+35;
      WSAEINPROGRESS=WSABASEERR+36;
      WSAEALREADY=WSABASEERR+37;
      WSAENOTSOCK=WSABASEERR+38;
      WSAEDESTADDRREQ=WSABASEERR+39;
      WSAEMSGSIZE=WSABASEERR+40;
      WSAEPROTOTYPE=WSABASEERR+41;
      WSAENOPROTOOPT=WSABASEERR+42;
      WSAEPROTONOSUPPORT=WSABASEERR+43;
      WSAESOCKTNOSUPPORT=WSABASEERR+44;
      WSAEOPNOTSUPP=WSABASEERR+45;
      WSAEPFNOSUPPORT=WSABASEERR+46;
      WSAEAFNOSUPPORT=WSABASEERR+47;
      WSAEADDRINUSE=WSABASEERR+48;
      WSAEADDRNOTAVAIL=WSABASEERR+49;
      WSAENETDOWN=WSABASEERR+50;
      WSAENETUNREACH=WSABASEERR+51;
      WSAENETRESET=WSABASEERR+52;
      WSAECONNABORTED=WSABASEERR+53;
      WSAECONNRESET=WSABASEERR+54;
      WSAENOBUFS=WSABASEERR+55;
      WSAEISCONN=WSABASEERR+56;
      WSAENOTCONN=WSABASEERR+57;
      WSAESHUTDOWN=WSABASEERR+58;
      WSAETOOMANYREFS=WSABASEERR+59;
      WSAETIMEDOUT=WSABASEERR+60;
      WSAECONNREFUSED=WSABASEERR+61;
      WSAELOOP=WSABASEERR+62;
      WSAENAMETOOLONG=WSABASEERR+63;
      WSAEHOSTDOWN=WSABASEERR+64;
      WSAEHOSTUNREACH=WSABASEERR+65;
      WSAENOTEMPTY=WSABASEERR+66;
      WSAEPROCLIM=WSABASEERR+67;
      WSAEUSERS=WSABASEERR+68;
      WSAEDQUOT=WSABASEERR+69;
      WSAESTALE=WSABASEERR+70;
      WSAEREMOTE=WSABASEERR+71;
      WSASYSNOTREADY=WSABASEERR+91;
      WSAVERNOTSUPPORTED=WSABASEERR+92;
      WSANOTINITIALISED=WSABASEERR+93;
      WSAEDISCON=WSABASEERR+101;
      WSAENOMORE=WSABASEERR+102;
      WSAECANCELLED=WSABASEERR+103;
      WSAEINVALIDPROCTABLE=WSABASEERR+104;
      WSAEINVALIDPROVIDER=WSABASEERR+105;
      WSAEPROVIDERFAILEDINIT=WSABASEERR+106;
      WSASYSCALLFAILURE=WSABASEERR+107;
      WSASERVICE_NOT_FOUND=WSABASEERR+108;
      WSATYPE_NOT_FOUND=WSABASEERR+109;
      WSA_E_NO_MORE=WSABASEERR+110;
      WSA_E_CANCELLED=WSABASEERR+111;
      WSAEREFUSED=WSABASEERR+112;

      MSG_PARTIAL=$8000;

type TInAddr=record
      case TRNLInt32 of
       0:(
        S_bytes:array[0..3] of TRNLUInt8;
       );
       1:(
        S_addr:TRNLUInt32;
       );
     end;

     PSockAddrIn=^TSockAddrIn;
     TSockAddrIn=packed record
      case TRNLInt32 of
       0:(
        sin_family:TRNLUInt16;
        sin_port:TRNLUInt16;
        sin_addr:TInAddr;
        sin_zero:array[0..7] of TRNLUInt8;
       );
       1:(
        sa_family:TRNLUInt16;
        sa_data:array[0..13] of TRNLUInt8;
       );
     end;

     PInAddr6=^TInAddr6;
     TInAddr6=record
      case TRNLUInt8 of
       0:(
        s6_addr:array[0..15] of TRNLInt8;
       );
       1:(
        u6_addr8:array[0..15] of TRNLUInt8;
       );
       2:(
        u6_addr16:array[0..7] of TRNLUInt16;
       );
       3:(
        u6_addr32:array[0..3] of TRNLUInt32;
       );
       4:(
        u6_addr64:array[0..1] of TRNLUInt64;
       );
     end;

     PSockAddrIn6=^TSockAddrIn6;
     TSockAddrIn6=record
      sin6_family:TRNLUInt16;
      sin6_port:TRNLUInt16;
      sin6_flowinfo:TRNLUInt32;
      sin6_addr:TInAddr6;
      sin6_scope_id:TRNLUInt32;
     end;

     PSockAddr=^TSockAddr;
     TSockAddr=TSockAddrIn;

     PPAddrInfo=^PAddrInfo;
     PAddrInfo=^TAddrInfo;
     TAddrInfo=record
      ai_flags:TRNLInt32;
      ai_family:TRNLInt32;
      ai_socktype:TRNLInt32;
      ai_protocol:TRNLInt32;
      ai_addrlen:TRNLSizeInt;
      ai_canonname:PAnsiChar;
      ai_addr:PSockAddr;
      ai_next:PAddrInfo;
     end;

     PSockaddrStorage=^TSockaddrStorage;
     TSockaddrStorage=record
      ss_family:TRNLUInt16;
      _ss_pad1:array[0..5] of TRNLUInt8;
      _ss_align:TRNLInt64;
      _ss_pad2:array[0..119] of TRNLUInt8;
     end;

     PWSAData=^TWSAData;
     TWSAData=packed record
      wVersion:TRNLUInt16;
      wHighVersion:TRNLUInt16;
      szDescription:array[0..WSADESCRIPTION_LEN] of AnsiChar;
      szSystemStatus:array[0..WSASYS_STATUS_LEN] of AnsiChar;
      iMaxSockets:TRNLUInt16;
      iMaxUdpDg:TRNLUInt16;
      lpVendorInfo:PAnsiChar;
     end;

     PWSABUF=^TWSABUF;
     LPWSABUF=PWSABUF;
     TWSABUF=packed record
      len:TRNLUInt32;
      buf:PRNLUInt8Array;
     end;

     PWSAOverlapped=^WSAOverlapped;
     LPWSAOVERLAPPED=PWSAOverlapped;
     WSAOVERLAPPED=TOverlapped;
     TWSAOverlapped=WSAOverlapped;

     TGetAddrInfo=function(NodeName:PAnsiChar;ServName:PAnsiChar;Hints:PAddrInfo;Addrinfo:PPAddrInfo):TRNLInt32; stdcall;
     TFreeAddrInfo=procedure(ai:PAddrInfo); stdcall;
     TGetNameInfo=function(Addr:PSockAddr;namelen:TRNLUInt32;Host:PAnsiChar;hostlen:TRNLUInt32;serv:PAnsiChar;servlen:TRNLUInt32;Flags:TRNLInt32):TRNLInt32; stdcall;

     LPWSAOVERLAPPED_COMPLETION_ROUTINE=procedure(const dwError,cbTransferred:TRNLUInt32;
                                                  const lpOverlapped:LPWSAOVERLAPPED;
                                                  const dwFlags:TRNLUInt32); stdcall;


     PTimeVal=^TTimeVal;
     TTimeVal=packed record
      tv_sec:TRNLInt32;
      tv_usec:TRNLInt32;
     end;

     TGetTickCount64=function:TRNLUInt64; stdcall;

     TQueryUnbiasedInterruptTime=function(var lpUnbiasedInterruptTime:TRNLUInt64):bool; stdcall;

const GetAddrInfo:TGetAddrInfo=nil;
      FreeAddrInfo:TFreeAddrInfo=nil;
      GetNameInfo:TGetNameInfo=nil;
      GetTickCount64:TGetTickCount64=nil;
      QueryUnbiasedInterruptTime:TQueryUnbiasedInterruptTime=nil;

      WinSock2LibHandle:THandle=0;
      Kernel32LibHandle:THandle=0;

      QueryPerformanceFrequencyBase:TRNLUInt64=0;
      QueryPerformanceFrequencyShift:TRNLInt32=0;

function WSAStartup(wVersionRequired:TRNLUInt16;var WSData:TWSAData):TRNLInt32; stdcall; external 'ws2_32.dll' name 'WSAStartup';
function WSACleanup:TRNLInt32; stdcall; external 'ws2_32.dll' name 'WSACleanup';
function _bind(const s:TRNLSocket;const addr:PSockAddr;const namelen:TRNLInt32):TRNLInt32; stdcall; external 'ws2_32.dll' name 'bind';
function getsockname(const s:TRNLSocket;var name:TSockAddr;var namelen:TRNLInt32):TRNLInt32; stdcall; external 'ws2_32.dll' name 'getsockname';
function _listen(s:TrNLSocket;backlog:TRNLInt32):TRNLInt32; stdcall; external 'ws2_32.dll' name 'listen';
function _socket(const af,struct,protocol:TRNLInt32):TRNLSocket; stdcall; external 'ws2_32.dll' name 'socket';
function ioctlsocket(const s:TRNLSocket;const cmd:TRNLUInt32;var arg:TRNLUInt32):TRNLInt32; stdcall; external 'ws2_32.dll' name 'ioctlsocket';
function setsockopt(s:TRNLSocket;level,optname:TRNLInt32;optval:PAnsiChar;optlen:TRNLInt32):TRNLInt32; stdcall; external 'ws2_32.dll' name 'setsockopt';
function _shutdown(s:TRNLSocket;how:TRNLInt32):TRNLInt32; stdcall; external 'ws2_32.dll' name 'shutdown';
function _connect(const s:TRNLSocket;const name:PSockAddr;namelen:TRNLInt32):TRNLInt32; stdcall; external 'ws2_32.dll' name 'connect';
function WSAGetLastError:TRNLInt32; stdcall; external 'ws2_32.dll' name 'WSAGetLastError';
function _accept(const s:TRNLSocket;var addr:TSockAddr;var addrlen:TRNLInt32):TRNLSocket; stdcall; external 'ws2_32.dll' name 'accept';
function closesocket(const s:TRNLSocket):TRNLInt32; stdcall; external 'ws2_32.dll' name 'closesocket';
function WSASendTo(s:TRNLSocket;
                   lpBuffers:LPWSABUF;
                   dwBufferCount:TRNLUInt32;
                   var lpNumberOfBytesSent:TRNLUInt32;
                   dwFlags:DWORD;
                   lpTo:PSockAddr;
                   iToLen:TRNLInt32;
                   lpOverlapped:LPWSAOVERLAPPED;
                   lpCompletionRoutine:LPWSAOVERLAPPED_COMPLETION_ROUTINE):TRNLInt32; stdcall; external 'ws2_32.dll' name 'WSASendTo';
function WSARecvFrom(s:TRNLSocket;
                     lpBuffers:LPWSABUF;
                     dwBufferCount:TRNLUInt32;
                     var lpNumberOfBytesRecvd:TRNLUInt32;
                     var lpFlags:TRNLUInt32;
                     lpFrom:PSockAddr;
                     lpFromLen:PRNLInt32;
                     lpOverlapped:LPWSAOVERLAPPED;
                     lpCompletionRoutine:LPWSAOVERLAPPED_COMPLETION_ROUTINE):TRNLInt32; stdcall; external 'ws2_32.dll' name 'WSARecvFrom';
function _select(nfds:TRNLInt32;readfds,writefds,exceptfds:PRNLSocketSet;timeout:PTimeVal):TRNLInt32; stdcall; external 'ws2_32.dll' name 'select';

function QueryPerformanceCounter(out lpPerformanceCount:TRNLUInt64):bool; stdcall; external kernel32 name 'QueryPerformanceCounter';
function QueryPerformanceFrequency(out lpFrequency:TRNLUInt64):bool; stdcall; external kernel32 name 'QueryPerformanceFrequency';

class procedure TRNLInstance.GlobalInitialize;
begin
 Kernel32LibHandle:=LoadLibrary(PChar('kernel32.dll'));
 if Kernel32LibHandle=0 then begin
  WSACleanup;
  raise ERNLInstance.Create('Incompatible system version');
 end;
 GetTickCount64:=GetProcAddress(Kernel32LibHandle,PAnsiChar(AnsiString('GetTickCount64')));
 QueryUnbiasedInterruptTime:=GetProcAddress(Kernel32LibHandle,PAnsiChar(AnsiString('QueryUnbiasedInterruptTime')));
 if QueryPerformanceFrequency(QueryPerformanceFrequencyBase) then begin
  if QueryPerformanceFrequencyBase=1000 then begin
   QueryPerformanceFrequencyBase:=0;
  end else begin
   QueryPerformanceFrequencyShift:=0;
   while (QueryPerformanceFrequencyBase>1) and ((QueryPerformanceFrequencyBase and 1)=0) do begin
    QueryPerformanceFrequencyBase:=QueryPerformanceFrequencyBase shr 1;
    inc(QueryPerformanceFrequencyShift);
   end;
  end;
 end else begin
  QueryPerformanceFrequencyBase:=0;
 end;
 timeBeginPeriod(1);
end;

class procedure TRNLInstance.GlobalFinalize;
begin
 timeEndPeriod(1);
 FreeLibrary(Kernel32LibHandle);
end;

function TRNLInstance.GetTime:TRNLTime;
begin
 if assigned(QueryUnbiasedInterruptTime) and QueryUnbiasedInterruptTime(TRNLUInt64(result.fValue)) then begin
  result:=result div 10000;
 end else if (QueryPerformanceFrequencyBase<>0) and QueryPerformanceCounter(TRNLUInt64(result.fValue)) then begin
  result:=(((result.fValue shr QueryPerformanceFrequencyShift)*1000) div QueryPerformanceFrequencyBase)-fTimeBase;
 end else if assigned(GetTickCount64) then begin
  result:=GetTickCount64-fTimeBase;
 end else begin
  result:=timeGetTime-fTimeBase;
 end;
end;

procedure TRNLInstance.SetTime(const aTimeBase:TRNLTime);
begin
 fTimeBase:=(GetTime+fTimeBase)-aTimeBase;
end;

function TRNLAddressFamilyHelper.GetAddressFamily:TRNLUInt16;
begin
 case self of
  RNL_IPV4:begin
   result:=AF_INET;
  end;
  RNL_IPV6:begin
   result:=AF_INET6;
  end;
  else begin
   result:=0;
  end;
 end;
end;

function TRNLAddressFamilyHelper.GetSockAddrSize:TRNLInt32;
begin
 case self of
  RNL_IPV4:begin
   result:=SizeOf(TSockAddrIn);
  end;
  RNL_IPV6:begin
   result:=SizeOf(TSockAddrIn6);
  end;
  else begin
   result:=0;
  end;
 end;
end;

function TRNLAddress.SetAddress(const aSIN:TRNLPointer):TRNLAddressFamily;
begin
 FillChar(self,SizeOf(TRNLAddress),AnsiChar(#0));
 case PSockAddrIn(aSIN)^.sin_family of
  AF_INET:begin
   Host:=TRNLHostAddress.CreateFromIPV4(PSockAddrIn(aSIN)^.sin_addr.S_addr);
   ScopeID:=0;
   Port:=TRNLEndianness.NetToHost16(PSockAddrIn(aSIN)^.sin_port);
   result:=RNL_IPV4;
  end;
  AF_INET6:begin
   Host:=PRNLHostAddress(TRNLPointer(@PSockAddrIn6(aSIN)^.sin6_addr))^;
   ScopeID:=PSockAddrIn6(aSIN)^.sin6_scope_id;
   Port:=TRNLEndianness.NetToHost16(PSockAddrIn6(aSIN)^.sin6_port);
   result:=RNL_IPV6;
  end;
  else begin
   result:=RNL_NO_ADDRESS_FAMILY;
  end;
 end;
end;

function TRNLAddress.SetSIN(const aSIN:TRNLPointer;const aFamily:TRNLAddressFamily):boolean;
begin
 FillChar(aSIN^,aFamily.GetSockAddrSize,AnsiChar(#0));
 if (aFamily=RNL_IPV4) and
    ((GetAddressFamily=RNL_IPV4) or
     ((Host.Addr[0]=RNL_HOST_ANY.Addr[0]) and
      (Host.Addr[1]=RNL_HOST_ANY.Addr[1]) and
      (Host.Addr[2]=RNL_HOST_ANY.Addr[2]) and
      (Host.Addr[3]=RNL_HOST_ANY.Addr[3]) and
      (Host.Addr[4]=RNL_HOST_ANY.Addr[4]) and
      (Host.Addr[5]=RNL_HOST_ANY.Addr[5]) and
      (Host.Addr[6]=RNL_HOST_ANY.Addr[6]) and
      (Host.Addr[7]=RNL_HOST_ANY.Addr[7]) and
      (Host.Addr[8]=RNL_HOST_ANY.Addr[8]) and
      (Host.Addr[9]=RNL_HOST_ANY.Addr[9]) and
      (Host.Addr[10]=RNL_HOST_ANY.Addr[10]) and
      (Host.Addr[11]=RNL_HOST_ANY.Addr[11]) and
      (Host.Addr[12]=RNL_HOST_ANY.Addr[12]) and
      (Host.Addr[13]=RNL_HOST_ANY.Addr[13]) and
      (Host.Addr[14]=RNL_HOST_ANY.Addr[14]) and
      (Host.Addr[15]=RNL_HOST_ANY.Addr[15]))) then begin
  PSockAddrIn(aSIN)^.sin_family:=AF_INET;
  PSockAddrIn(aSIN)^.sin_addr.S_addr:=TRNLUInt32(TRNLPointer(@Host.Addr[12])^);
  PSockAddrIn(aSIN)^.sin_port:=TRNLEndianness.HostToNet16(Port);
  result:=true;
 end else if aFamily=RNL_IPV6 then begin
  PSockAddrIn6(aSIN)^.sin6_family:=AF_INET6;
  PRNLHostAddress(TRNLPointer(@PSockAddrIn6(aSIN)^.sin6_addr))^:=Host;
  PSockAddrIn6(aSIN)^.sin6_scope_id:=ScopeID;
  PSockAddrIn6(aSIN)^.sin6_port:=TRNLEndianness.HostToNet16(Port);
  result:=true;
 end else begin
  result:=false;
 end;
end;

{$ifend}

procedure TRNLConnectionRequestRateLimiter.Reset(const aTime:TRNLTime);
begin
 fBurst:=0;
 fLastTime:=aTime;
end;

function TRNLConnectionRequestRateLimiter.RateLimit(const aTime:TRNLTime;const aBurst:TRNLInt64;const aPeriod:TRNLUInt64):boolean;
var Interval,Expired:TRNLTime;
begin
 Interval:=aTime-fLastTime;
 Expired:=Interval div aPeriod;
 if Expired>fBurst then begin
  Reset(aTime);
 end else begin
  dec(fBurst,Expired.fValue);
  fLastTime:=aTime-(Interval mod aPeriod);
 end;
 if fBurst<aBurst then begin
  inc(fBurst);
  result:=false;
 end else begin
  result:=true;
 end;
end;

constructor TRNLBandwidthRateLimiter.Create(const aMaximumPerPeriod,aPeriodLength:TRNLUInt64;const aTime:TRNLTime);
begin
 Setup(aMaximumPerPeriod,aPeriodLength);
 Reset(aTime);
end;

procedure TRNLBandwidthRateLimiter.Setup(const aMaximumPerPeriod,aPeriodLength:TRNLUInt64);
begin
 fMaximumPerPeriod:=aMaximumPerPeriod;
 fPeriodLength:=aPeriodLength;
end;

procedure TRNLBandwidthRateLimiter.Reset(const aTime:TRNLTime);
begin
 fUsedInPeriod:=0;
 fPeriodStart:=aTime;
 fPeriodEnd:=aTime+fMaximumPerPeriod;
end;

function TRNLBandwidthRateLimiter.CanProceed(const aDesired:TRNLUInt32;const aTime:TRNLTime):boolean;
begin
 result:=(fMaximumPerPeriod=0) or
         ((fPeriodEnd<aTime) and (aDesired<=fMaximumPerPeriod)) or
         ((fUsedInPeriod+aDesired)<=fMaximumPerPeriod);
end;

procedure TRNLBandwidthRateLimiter.AddAmount(const aUsed:TRNLUInt32;const aTime:TRNLTime);
begin
 if fPeriodEnd<aTime then begin
  Reset(aTime);
 end;
 if fMaximumPerPeriod=0 then begin
  fUsedInPeriod:=0;
 end else begin
  inc(fUsedInPeriod,aUsed);
 end;
end;

procedure TRNLBandwidthRateTracker.Reset;
begin
 fPeriodUnits:=0;
 fUnitsPerSecond:=0;
 fLastTime:=0;
 fTime:=0;
end;

procedure TRNLBandwidthRateTracker.SetTime(const aTime:TRNLTime);
begin
 fTime:=aTime;
 if fLastTime.fValue=0 then begin
  fLastTime:=aTime;
 end;
end;

procedure TRNLBandwidthRateTracker.AddUnits(const aUnits:TRNLUInt32);
begin
 inc(fPeriodUnits,aUnits);
end;

procedure TRNLBandwidthRateTracker.Update;
var TimeDifference:TRNLInt64;
    AbsoluteTimeDifference,FractionUnits,Seconds,FractionTime:TRNLSizeUInt;
begin
 TimeDifference:=TRNLTime.RelativeDifference(fTime,fLastTime);
 if TimeDifference>=1000 then begin
  AbsoluteTimeDifference:=TRNLSizeUInt(TimeDifference);
{$if not (defined(CPU386) or defined(CPUX64))}
  if AbsoluteTimeDifference<400000 then begin
   // Fast path
   Seconds:=((AbsoluteTimeDifference shr 3)*67109) shr 23; // /8)*125)/(2 shl 23) because 1000 = 8*125
   FractionTime:=AbsoluteTimeDifference-(Seconds*1000);
  end else{$ifend}begin
   // Slower path on CPUs (mostly on older ARM CPUs) without extra hardware division support
   Seconds:=AbsoluteTimeDifference div 1000;
   FractionTime:=AbsoluteTimeDifference mod 1000;
  end;
  FractionUnits:=(TRNLUInt64(fPeriodUnits)*FractionTime) div AbsoluteTimeDifference;
  fUnitsPerSecond:=(fPeriodUnits-FractionUnits) div Seconds;
  fLastTime:=fTime-FractionTime;
  fPeriodUnits:=FractionUnits;
 end;
end;

procedure TRNLOutgoingPacketBuffer.Reset(const aAssociatedDataSize:TRNLSizeUInt=0;const aBufferLength:TRNLSizeUInt=SizeOf(TRNLPacketBuffer));
begin
 fSize:=0;
 fAssociatedDataSize:=aAssociatedDataSize;
 fBufferLength:=aBufferLength;
end;

function TRNLOutgoingPacketBuffer.HasSpaceFor(const aDataLength:TRNLSizeUInt):boolean;
begin
 result:=Max(0,fBufferLength-(fSize+fAssociatedDataSize))>=aDataLength;
end;

function TRNLOutgoingPacketBuffer.Write(const aData;const aDataLength:TRNLSizeUInt):TRNLSizeUInt;
begin
 result:=TRNLSizeUInt(SizeOf(TRNLPacketBuffer))-(fSize+fAssociatedDataSize);
 if aDataLength<result then begin
  result:=aDataLength;
 end;
 if result>0 then begin
{ if length(fData)<(fSize+result) then begin
   SetLength(fData,(fSize+result)*2);
  end;}
  Move(aData,fData[fSize],result);
  inc(fSize,result);
 end;
end;

procedure TRNLConnectionKnownCandidateHostAddressHashTable.Clear;
begin
 FillChar(self,SizeOf(TRNLConnectionKnownCandidateHostAddressHashTable),#0);
end;

function TRNLConnectionKnownCandidateHostAddressHashTable.Find(const aHostAddress:TRNLHostAddress;const aTime:TRNLTime;const aAddIfNotExist:boolean):PRNLConnectionKnownCandidateHostAddress;
type PToHash=^TToHash;
     TToHash=packed record
      HostAddress:TRNLHostAddress;
     end;
var ToHash:TToHash;
    Hash,Index:TRNLUInt32;
    Item:PRNLConnectionKnownCandidateHostAddress;
begin
 result:=nil;
 ToHash.HostAddress:=aHostAddress;
 Hash:=TRNLHashUtils.Hash32(ToHash,SizeOf(TToHash));
 Index:=Hash and HashMask;
 Item:=@fEntries[Index];
 if TRNLMemory.SecureIsEqual(Item^.HostAddress,aHostAddress,SizeOf(TRNLHostAddress)) then begin
  result:=Item;
 end else if aAddIfNotExist then begin
  Item^.HostAddress:=aHostAddress;
  Item^.RateLimiter.Reset(aTime);
  result:=Item;
 end;
end;

procedure TRNLConnectionCandidateHashTable.Clear;
begin
 FillChar(self,SizeOf(TRNLConnectionCandidateHashTable),#0);
end;

function TRNLConnectionCandidateHashTable.Find(const aRandomGenerator:TRNLRandomGenerator;const aAddress:TRNLAddress;const aRemoteSalt,aLocalSalt:TRNLUInt64;const aTime,aTimeout:TRNLTime;const aAddIfNotExist:boolean):PRNLConnectionCandidate;
type PToHash=^TToHash;
     TToHash=packed record
      Address:TRNLAddress;
      RemoteSalt:TRNLUInt64;
      LocalSalt:TRNLUInt64;
     end;
var ToHash:TToHash;
    Hash,Index:TRNLUInt32;
    Item:PRNLConnectionCandidate;
begin
 result:=nil;
 ToHash.Address:=aAddress;
 ToHash.RemoteSalt:=aRemoteSalt;
 ToHash.LocalSalt:=aLocalSalt;
 Hash:=TRNLHashUtils.Hash32(ToHash,SizeOf(TToHash));
 Index:=Hash and HashMask;
 Item:=@fEntries[Index];
 if (Item^.State<>RNL_CONNECTION_STATE_INVALID) and
    TRNLMemory.SecureIsEqual(Item^.Address,aAddress,SizeOf(TRNLAddress)) and
    (Item^.RemoteSalt=aRemoteSalt) and
    (Item^.CreateTime.fValue<=aTime.fValue) and
    ((Item^.CreateTime+aTimeout).fValue>=aTime.fValue) then begin
  result:=Item;
 end else if aAddIfNotExist then begin
  Item^.State:=RNL_CONNECTION_STATE_REQUESTING;
  Item^.RemoteSalt:=aRemoteSalt;
  Item^.LocalSalt:=aLocalSalt;
  Item^.CreateTime:=aTime;
  Item^.Address:=aAddress;
  Item^.Peer:=nil;
  result:=Item;
 end;
end;

constructor TRNLMessage.CreateFromMemory(const aData:TRNLPointer;const aDataLength:TRNLUInt32;const aFlags:TRNLMessageFlags);
begin
 inherited Create;
 if RNL_MESSAGE_FLAG_NO_ALLOCATE in aFlags then begin
  fData:=aData;
 end else if aDataLength<=0 then begin
  fData:=nil;
 end else begin
  GetMem(fData,aDataLength);
  if assigned(aData) then begin
   Move(aData^,fData^,aDataLength);
  end else begin
   FillChar(fData^,aDataLength,#0);
  end;
 end;
 fReferenceCount:=1;
 fFlags:=aFlags;
 fDataLength:=aDataLength;
 fFreeCallback:=nil;
 fUserData:=nil;
end;

constructor TRNLMessage.CreateFromString(const aData:TRNLRawByteString;const aFlags:TRNLMessageFlags);
begin
 CreateFromMemory(@aData[1],length(aData),aFlags);
end;

constructor TRNLMessage.CreateFromStream(const aStream:TStream;const aFlags:TRNLMessageFlags);
var StreamData:TRNLPointer;
begin
 if aStream is TMemoryStream then begin
  CreateFromMemory(TMemoryStream(aStream).Memory,aStream.Size,aFlags);
 end else begin
  GetMem(StreamData,aStream.Size+1);
  try
   aStream.Seek(0,soBeginning);
   aStream.ReadBuffer(StreamData^,aStream.Size);
   CreateFromMemory(StreamData,aStream.Size,aFlags);
  finally
   FreeMem(StreamData);
  end;
 end;
end;

destructor TRNLMessage.Destroy;
begin
 if assigned(fFreeCallback) then begin
  fFreeCallback(self);
 end;
 if assigned(fData) and not (RNL_MESSAGE_FLAG_NO_FREE in fFlags) then begin
  FreeMem(fData);
 end;
 fData:=nil;
 inherited Destroy;
end;

procedure TRNLMessage.IncRef;
begin
 inc(fReferenceCount);
end;

procedure TRNLMessage.DecRef;
begin
 if assigned(self) and (fReferenceCount>0) then begin
  dec(fReferenceCount);
  if fReferenceCount=0 then begin
   Free;
  end;
 end;
end;

procedure TRNLMessage.Resize(const aDataLength:TRNLUInt32);
var NewData:TRNLPointer;
begin
 if (aDataLength<=fDataLength) or (RNL_MESSAGE_FLAG_NO_ALLOCATE in fFlags) then begin
  fDataLength:=aDataLength;
 end else begin
  GetMem(NewData,aDataLength);
  FillChar(NewData^,aDataLength,#0);
  Move(fData^,NewData^,fDataLength);
  FreeMem(fData);
  fData:=NewData;
  fDataLength:=aDataLength;
 end;
end;

function TRNLMessage.GetDataAsString:TRNLRawByteString;
{$if defined(NEXTGEN)}
begin
 SetLength(result,fDataLength);
 Move(fData^,result[1],fDataLength);
end;
{$else}
begin
 result:=copy(PAnsiChar(fData),0,fDataLength);
end;
{$ifend}

var CRC32CTable:array[0..7,TRNLUInt8] of TRNLUInt32;

procedure InitializeCRC32C;
const ReversedBitOrderPoly=$82f63b78;
var Index,OtherIndex:TRNLInt32;
    Value:TRNLUInt32;
begin
 for Index:=0 to 255 do begin
  Value:=Index;
  for OtherIndex:=0 to 7 do begin
   Value:=(Value shr 1) xor (ReversedBitOrderPoly and (-(Value and 1)));
  end;
  CRC32CTable[0,Index]:=Value;
 end;
 for Index:=0 to 255 do begin
  Value:=CRC32CTable[0,Index];
  for OtherIndex:=1 to 7 do begin
   Value:=(Value shr 8) xor CRC32CTable[0,Value and $ff];
   CRC32CTable[OtherIndex,Index]:=Value;
  end;
 end;
end;

function ChecksumCRC32C(const aBuffers;const aCountBuffers:TRNLUInt32):TRNLUInt32;
var Buffer:PRNLBuffer;
    BufferIndex,Remaining:TRNLInt32;
    Data:PRNLUInt8;
{$ifdef CPU64}
    Value:TRNLUInt64;
{$endif}
begin
 result:=$ffffffff;
 for BufferIndex:=0 to aCountBuffers-1 do begin
  Buffer:=@PRNLBufferArray(TRNLPointer(@aBuffers))^[BufferIndex];
  Remaining:=Buffer^.DataLength;
  if Remaining>0 then begin
   Data:=@Buffer^.Data[0];
   while (Remaining>0) and (({%H-}TRNLPtrUInt(TRNLPointer(Data)) and ({$ifdef CPU64}SizeOf(TRNLUInt64){$else}SizeOf(TRNLUInt32){$endif}-1))<>0) do begin
    result:=(result shr 8) xor CRC32CTable[0,(result and $ff) xor Data^];
    inc(Data);
    dec(Remaining);
   end;
{$ifdef CPU64}
   while Remaining>=SizeOf(TRNLUInt64) do begin
    Value:=result xor PRNLUInt64(TRNLPointer(Data))^;
{$ifdef BIG_ENDIAN}
    result:=CRC32CTable[0,(Value shr 0) and $ff] xor
            CRC32CTable[1,(Value shr 8) and $ff] xor
            CRC32CTable[2,(Value shr 16) and $ff] xor
            CRC32CTable[3,(Value shr 24) and $ff] xor
            CRC32CTable[4,(Value shr 32) and $ff] xor
            CRC32CTable[5,(Value shr 40) and $ff] xor
            CRC32CTable[6,(Value shr 48) and $ff] xor
            CRC32CTable[7,(Value shr 56) and $ff];
{$else}
    result:=CRC32CTable[7,(Value shr 0) and $ff] xor
            CRC32CTable[6,(Value shr 8) and $ff] xor
            CRC32CTable[5,(Value shr 16) and $ff] xor
            CRC32CTable[4,(Value shr 24) and $ff] xor
            CRC32CTable[3,(Value shr 32) and $ff] xor
            CRC32CTable[2,(Value shr 40) and $ff] xor
            CRC32CTable[1,(Value shr 48) and $ff] xor
            CRC32CTable[0,(Value shr 56) and $ff];
{$endif}
    inc(Data,SizeOf(TRNLUInt64));
    dec(Remaining,SizeOf(TRNLUInt64));
   end;
{$else}
   while Remaining>=SizeOf(TRNLUInt32) do begin
    result:=result xor PRNLUInt32(TRNLPointer(Data))^;
{$ifdef BIG_ENDIAN}
    result:=CRC32CTable[0,(result shr 0) and $ff] xor
            CRC32CTable[1,(result shr 8) and $ff] xor
            CRC32CTable[2,(result shr 16) and $ff] xor
            CRC32CTable[3,(result shr 24) and $ff];
{$else}
    result:=CRC32CTable[3,(result shr 0) and $ff] xor
            CRC32CTable[2,(result shr 8) and $ff] xor
            CRC32CTable[1,(result shr 16) and $ff] xor
            CRC32CTable[0,(result shr 24) and $ff];
{$endif}
    inc(Data,SizeOf(TRNLUInt32));
    dec(Remaining,SizeOf(TRNLUInt32));
   end;
{$endif}
   while Remaining>0 do begin
    result:=(result shr 8) xor CRC32CTable[0,(result and $ff) xor Data^];
    inc(Data);
    dec(Remaining);
   end;
  end;
 end;
 result:=not result;
end;

function DirectChecksumCRC32C(const aLocation;const aSize:TRNLUInt32):TRNLUInt32;
var Buffer:TRNLBuffer;
begin
 Buffer.Data:=@aLocation;
 Buffer.DataLength:=aSize;
 result:=ChecksumCRC32C(Buffer,1);
end;

constructor TRNLInstance.Create;
begin
 inherited Create;
 if RNLInitializationReferenceCounter=0 then begin
  GlobalInitialize;
  inc(RNLInitializationReferenceCounter);
 end;
 fTimeBase:=0;
{$if defined(RNL_DEBUG)}
 fDebugLock:=TCriticalSection.Create;
{$ifend}
end;

destructor TRNLInstance.Destroy;
begin
 if RNLInitializationReferenceCounter>0 then begin
  dec(RNLInitializationReferenceCounter);
  if RNLInitializationReferenceCounter=0 then begin
   GlobalFinalize;
  end;
 end;
{$if defined(RNL_DEBUG)}
 FreeAndNil(fDebugLock);
{$ifend}
 inherited Destroy;
end;

constructor TRNLNetwork.Create(const aInstance:TRNLInstance);
begin
 inherited Create;
 fInstance:=aInstance;
end;

destructor TRNLNetwork.Destroy;
begin
 inherited Destroy;
end;

function TRNLNetwork.AddressSetHost(var aAddress:TRNLAddress;const aName:TRNLRawByteString):boolean;
begin
 result:=false;
end;

function TRNLNetwork.AddressGetHost(const aAddress:TRNLAddress;out aName;const aNameLength:TRNLInt32;const aFlags:TRNLInt32=0):boolean;
begin
 result:=false;
end;

function TRNLNetwork.AddressGetHostIP(const aAddress:TRNLAddress;out aName;const aNameLength:TRNLInt32):boolean;
begin
 result:=false;
end;

function TRNLNetwork.SocketCreate(const aType:TRNLSocketType;const aFamily:TRNLAddressFamily):TRNLSocket;
begin
 result:=RNL_SOCKET_NULL;
end;

procedure TRNLNetwork.SocketDestroy(const aSocket:TRNLSocket);
begin
end;

function TRNLNetwork.SocketShutdown(const aSocket:TRNLSocket;const aHow:TRNLSocketShutdown=RNL_SOCKET_SHUTDOWN_READ):boolean;
begin
 result:=false;
end;

function TRNLNetwork.SocketGetAddress(const aSocket:TRNLSocket;out aAddress:TRNLAddress;const aFamily:TRNLAddressFamily):boolean;
begin
 result:=false;
end;

function TRNLNetwork.SocketSetOption(const aSocket:TRNLSocket;const aOption:TRNLSocketOption;const aValue:TRNLInt32):boolean;
begin
 result:=false;
end;

function TRNLNetwork.SocketGetOption(const aSocket:TRNLSocket;const aOption:TRNLSocketOption;out aValue:TRNLInt32):boolean;
begin
 result:=false;
end;

function TRNLNetwork.SocketBind(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aFamily:TRNLAddressFamily):boolean;
begin
 result:=false;
end;

function TRNLNetwork.SocketListen(const aSocket:TRNLSocket;const aBackLog:TRNLInt32):boolean;
begin
 result:=false;
end;

function TRNLNetwork.SocketConnect(const aSocket:TRNLSocket;const aAddress:TRNLAddress;const aFamily:TRNLAddressFamily):boolean;
begin
 result:=false;
end;

function TRNLNetwork.SocketAccept(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aFamily:TRNLAddressFamily):TRNLSocket;
begin
 result:=RNL_SOCKET_NULL;
end;

function TRNLNetwork.SocketSelect(const aMaxSocket:TRNLSocket;var aReadSet,aWriteSet:TRNLSocketSet;const aTimeout:TRNLTime):TRNLInt32;
begin
 result:=-1;
end;

function TRNLNetwork.SocketWait(const aSockets:array of TRNLSocket;var aConditions:TRNLSocketWaitConditions;const aTimeout:TRNLTime):boolean;
begin
 aConditions:=[];
 result:=false;
end;

function TRNLNetwork.SendBuffers(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aBuffers;const aCountBuffers:TRNLUInt32;const aFamily:TRNLAddressFamily):TRNLSizeInt;
begin
 result:=-1;
end;

function TRNLNetwork.ReceiveBuffers(const aSocket:TRNLSocket;const aAddress:PRNLAddress;var aBuffers;const aCountBuffers:TRNLUInt32;const aFamily:TRNLAddressFamily):TRNLSizeInt;
begin
 result:=-1;
end;

function TRNLNetwork.Send(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aData;const aDataLength:TRNLSizeInt;const aFamily:TRNLAddressFamily):TRNLSizeInt;
begin
 result:=-1;
end;

function TRNLNetwork.Receive(const aSocket:TRNLSocket;const aAddress:PRNLAddress;var aData;const aDataLength:TRNLSizeInt;const aFamily:TRNLAddressFamily):TRNLSizeInt;
begin
 result:=-1;
end;

constructor TRNLRealNetwork.Create(const aInstance:TRNLInstance);
begin
 if RNLNetworkInitializationReferenceCounter=0 then begin
  GlobalInitialize;
  inc(RNLNetworkInitializationReferenceCounter);
 end;
 inherited Create(aInstance);
end;

destructor TRNLRealNetwork.Destroy;
begin
 inherited Destroy;
 if RNLNetworkInitializationReferenceCounter>0 then begin
  dec(RNLNetworkInitializationReferenceCounter);
  if RNLNetworkInitializationReferenceCounter=0 then begin
   GlobalFinalize;
  end;
 end;
end;

class procedure TRNLRealNetwork.GlobalInitialize;
{$if defined(Windows)}
var versionRequested:TRNLUInt16;
    vWSAData:TWSAData;
begin
 WinSock2LibHandle:=0;
 versionRequested:=MAKEWORD(2,2);
 if WSAStartup(versionRequested,vWSAData)<>0 then begin
  raise ERNLNetwork.Create('Incompatible WinSocks version');
 end;
 WinSock2LibHandle:=LoadLibrary(PChar('ws2_32.dll'));
 if (WinSock2LibHandle=0) or ((LOBYTE(vWSAData.wVersion)<>2) or (HIBYTE(vWSAData.wVersion)<>2)) then begin
  WSACleanup;
  raise ERNLNetwork.Create('Incompatible WinSocks version');
 end;
 GetAddrInfo:=GetProcAddress(WinSock2LibHandle,PAnsiChar(AnsiString('getaddrinfo')));
 FreeAddrInfo:=GetProcAddress(WinSock2LibHandle,PAnsiChar(AnsiString('freeaddrinfo')));
 GetNameInfo:=GetProcAddress(WinSock2LibHandle,PAnsiChar(AnsiString('getnameinfo')));
 if not (assigned(GetAddrInfo) and assigned(FreeAddrInfo) and assigned(GetNameInfo)) then begin
  FreeLibrary(WinSock2LibHandle);
  WinSock2LibHandle:=LoadLibrary(PChar('wship6.dll'));
  GetAddrInfo:=GetProcAddress(WinSock2LibHandle,PAnsiChar(AnsiString('getaddrinfo')));
  FreeAddrInfo:=GetProcAddress(WinSock2LibHandle,PAnsiChar(AnsiString('freeaddrinfo')));
  GetNameInfo:=GetProcAddress(WinSock2LibHandle,PAnsiChar(AnsiString('getnameinfo')));
  if not (assigned(GetAddrInfo) and assigned(FreeAddrInfo) and assigned(GetNameInfo)) then begin
   FreeLibrary(WinSock2LibHandle);
   WinSock2LibHandle:=0;
   WSACleanup;
   raise ERNLNetwork.Create('Incompatible WinSocks version');
  end;
 end;
end;
{$else}
begin
end;
{$ifend}

class procedure TRNLRealNetwork.GlobalFinalize;
{$if defined(Windows)}
begin
 WSACleanup;
 FreeLibrary(WinSock2LibHandle);
end;
{$else}
begin
end;
{$ifend}

function TRNLRealNetwork.AddressSetHost(var aAddress:TRNLAddress;const aName:TRNLRawByteString):boolean;
{$if defined(Windows)}
var TempPort:TRNLUInt16;
    Hints:TAddrInfo;
    r,res:PAddrInfo;
begin
 TempPort:=aAddress.Port;
 FillChar(Hints,SizeOf(TAddrInfo),AnsiChar(#0));
 hints.ai_flags:=AI_ADDRCONFIG;
 hints.ai_family:=AF_UNSPEC;
 if getaddrinfo(PAnsiChar(aName),nil,@hints,@r)<>0 then begin
  result:=false;
  exit;
 end;
 try
  res:=r;
  while assigned(res) do begin
   if aAddress.SetAddress(res^.ai_addr)<>RNL_NO_ADDRESS_FAMILY then begin
    break;
   end;
   res:=res^.ai_next;
  end;
  aAddress.Port:=TempPort;
 finally
  freeaddrinfo(r);
 end;
 if not assigned(res) then begin
  result:=false;
  exit;
 end;
 result:=true;
end;
{$else}
var TempPort:TRNLUInt16;
    Hints:TAddrInfo;
    r,res:PAddrInfo;
begin
 TempPort:=aAddress.Port;
 FillChar(Hints,SizeOf(TAddrInfo),#0);
 hints.ai_flags:=AI_ADDRCONFIG;
 hints.ai_family:=AF_UNSPEC;
 if getaddrinfo({$ifdef NEXTGEN}MarshaledAString{$else}PAnsiChar{$endif}(aName),nil,{$ifdef fpc}@hints,@r{$else}hints,r{$endif})<>0 then begin
  result:=false;
  exit;
 end;
 try
  res:=r;
  while assigned(res) do begin
   if aAddress.SetAddress(res^.ai_addr)<>RNL_NO_ADDRESS_FAMILY then begin
    break;
   end;
   res:=res^.ai_next;
  end;
  aAddress.Port:=TempPort;
 finally
  freeaddrinfo({$ifdef fpc}r{$else}r^{$endif});
 end;
 if not assigned(res) then begin
  result:=false;
  exit;
 end;
 result:=true;
end;
{$ifend}

function TRNLRealNetwork.AddressGetHost(const aAddress:TRNLAddress;out aName;const aNameLength:TRNLInt32;const aFlags:TRNLInt32=0):boolean;
var SIN:TSockaddrStorage;
begin
 aAddress.SetSIN(@SIN,RNL_IPV6);
{$if defined(Windows)}
 result:=GetNameInfo(TRNLPointer(@SIN),TRNLAddressFamily(RNL_IPV6).GetSockAddrSize,@aName,aNameLength,nil,0,aFlags)<>0;
{$elseif defined(fpc)}
 result:=getnameinfo(TRNLPointer(@SIN),TRNLAddressFamily(RNL_IPV6).GetSockAddrSize,@aName,aNameLength,nil,0,aFlags)<>0;
{$else}
 result:=getnameinfo(sockaddr(TRNLPointer(@SIN)^),TRNLAddressFamily(RNL_IPV6).GetSockAddrSize,@aName,aNameLength,nil,0,aFlags)<>0;
{$ifend}
end;

function TRNLRealNetwork.AddressGetHostIP(const aAddress:TRNLAddress;out aName;const aNameLength:TRNLInt32):boolean;
begin
 result:=AddressGetHost(aAddress,aName,aNameLength,NI_NUMERICHOST);
end;

function TRNLRealNetwork.SocketCreate(const aType:TRNLSocketType;const aFamily:TRNLAddressFamily):TRNLSocket;
{$if defined(Windows)}
begin
 if aType=RNL_SOCKET_TYPE_DATAGRAM then begin
  result:=_Socket(aFamily.GetAddressFamily,SOCK_DGRAM,0);
 end else begin
  result:=_Socket(aFamily.GetAddressFamily,SOCK_STREAM,0);
 end;
end;
{$else}
begin
{$ifdef fpc}
 if aType=RNL_SOCKET_TYPE_DATAGRAM then begin
  result:=fpsocket(aFamily.GetAddressFamily,SOCK_DGRAM{$if defined(Linux) or defined(Android)}or SOCK_CLOEXEC{$ifend},0);
 end else begin
  result:=fpsocket(aFamily.GetAddressFamily,SOCK_STREAM{$if defined(Linux) or defined(Android)}or SOCK_CLOEXEC{$ifend},0);
 end;
{$else}
 if aType=RNL_SOCKET_TYPE_DATAGRAM then begin
  result:=Posix.SysSocket.socket(aFamily.GetAddressFamily,SOCK_DGRAM{$if defined(Linux) or defined(Android)}or SOCK_CLOEXEC{$ifend},0);
 end else begin
  result:=Posix.SysSocket.socket(aFamily.GetAddressFamily,SOCK_STREAM{$if defined(Linux) or defined(Android)}or SOCK_CLOEXEC{$ifend},0);
 end;
{$endif}
end;
{$ifend}

procedure TRNLRealNetwork.SocketDestroy(const aSocket:TRNLSocket);
{$if defined(Windows)}
begin
 if aSocket<>RNL_INVALID_SOCKET then begin
  CloseSocket(aSocket);
 end;
end;
{$else}
begin
 if aSocket<>RNL_INVALID_SOCKET then begin
{$ifdef fpc}
  CloseSocket(aSocket);
{$else}
  Posix.Unistd.__close(aSocket);
{$endif}
 end;
end;
{$ifend}

function TRNLRealNetwork.SocketShutdown(const aSocket:TRNLSocket;const aHow:TRNLSocketShutdown=RNL_SOCKET_SHUTDOWN_READ):boolean;
begin
{$if defined(Windows)}
 result:=_shutdown(aSocket,TRNLINt32(aHow))<>SOCKET_ERROR;
{$elseif defined(fpc)}
 result:=fpshutdown(aSocket,TRNLInt32(aHow))<>SOCKET_ERROR;
{$else}
 result:=Posix.SysSocket.shutdown(aSocket,TRNLInt32(aHow))<>SOCKET_ERROR;
{$ifend}
end;

function TRNLRealNetwork.SocketGetAddress(const aSocket:TRNLSocket;out aAddress:TRNLAddress;const aFamily:TRNLAddressFamily):boolean;
var SIN:TSockaddrStorage;
    SINLength:{$if defined(Windows)}TRNLInt32{$else}socklen_t{$ifend};
    TemporaryAddress:TRNLAddress;
begin
 SINLength:=aFamily.GetSockAddrSize;
{$if defined(Windows)}
 if getsockname(aSocket,TSockAddr(TRNLPointer(@SIN)^),SINLength)=-1 then begin
  result:=false;
 end else begin
  if TemporaryAddress.SetAddress(@SIN)=RNL_NO_ADDRESS_FAMILY then begin
   result:=false;
  end else begin
   aAddress:=TemporaryAddress;
   result:=false;
  end;
 end;
{$else}
 if {$ifdef fpc}
     fpgetsockname(aSocket,TRNLPointer(@SIN),@SINLength)=-1
    {$else}
     getsockname(aSocket,sockaddr(TRNLPointer(@SIN)^),SINLength)=-1
    {$endif} then begin
  result:=false;
 end else begin
  if TemporaryAddress.SetAddress(@SIN)=RNL_NO_ADDRESS_FAMILY then begin
   result:=false;
  end else begin
   aAddress:=TemporaryAddress;
   result:=true;
  end;
 end;
{$ifend}
end;

function TRNLRealNetwork.SocketSetOption(const aSocket:TRNLSocket;const aOption:TRNLSocketOption;const aValue:TRNLInt32):boolean;
{$if defined(Windows)}
var r:TRNLInt32;
    nonBlocking:TRNLUInt32;
begin
 r:=SOCKET_ERROR;
 case aOption of
  RNL_SOCKET_OPTION_NONBLOCK:begin
   nonBlocking:=aValue;
   r:=ioctlsocket(aSocket,FIONBIO,nonBlocking);
  end;
  RNL_SOCKET_OPTION_BROADCAST:begin
   r:=setsockopt(aSocket,SOL_SOCKET,SO_BROADCAST,TRNLPointer(@aValue),SizeOf(TRNLInt32));
  end;
  RNL_SOCKET_OPTION_REUSEADDR:begin
   r:=setsockopt(aSocket,SOL_SOCKET,SO_REUSEADDR,TRNLPointer(@aValue),SizeOf(TRNLInt32));
  end;
  RNL_SOCKET_OPTION_RCVBUF:begin
   r:=setsockopt(aSocket,SOL_SOCKET,SO_RCVBUF,TRNLPointer(@aValue),SizeOf(TRNLInt32));
  end;
  RNL_SOCKET_OPTION_SNDBUF:begin
   r:=setsockopt(aSocket,SOL_SOCKET,SO_SNDBUF,TRNLPointer(@aValue),SizeOf(TRNLInt32));
  end;
  RNL_SOCKET_OPTION_RCVTIMEO:begin
   r:=setsockopt(aSocket,SOL_SOCKET,SO_RCVTIMEO,TRNLPointer(@aValue),SizeOf(TRNLInt32));
  end;
  RNL_SOCKET_OPTION_SNDTIMEO:begin
   r:=setsockopt(aSocket,SOL_SOCKET,SO_SNDTIMEO,TRNLPointer(@aValue),SizeOf(TRNLInt32));
  end;
  RNL_SOCKET_OPTION_NODELAY:begin
   r:=setsockopt(aSocket,IPPROTO_TCP,TCP_NODELAY,TRNLPointer(@aValue),SizeOf(TRNLInt32));
  end;
  RNL_SOCKET_OPTION_DONTFRAGMENT:begin
   r:=setsockopt(aSocket,IPPROTO_IP,IP_DONTFRAGMENT,TRNLPointer(@aValue),SizeOf(TRNLInt32));
  end;
  RNL_SOCKET_OPTION_IPV6_V6ONLY:begin
   r:=setsockopt(aSocket,IPPROTO_IPV6,IPV6_V6ONLY,TRNLPointer(@aValue),SizeOf(TRNLInt32));
  end;
 end;
 result:=r<>SOCKET_ERROR;
end;
{$elseif defined(fpc)}
var r,t:TRNLInt32;
    nonBlocking:TRNLUInt32;
    tv:TTimeVal;
begin
 r:=SOCKET_ERROR;
 case aOption of
  RNL_SOCKET_OPTION_NONBLOCK:begin
   nonBlocking:=aValue;
   r:=fpioctl(aSocket,FIONBIO,TRNLPointer(@nonBlocking));
  end;
  RNL_SOCKET_OPTION_BROADCAST:begin
   r:=fpsetsockopt(aSocket,SOL_SOCKET,SO_BROADCAST,TRNLPointer(@aValue),SizeOf(TRNLInt32));
  end;
  RNL_SOCKET_OPTION_REUSEADDR:begin
   r:=fpsetsockopt(aSocket,SOL_SOCKET,SO_REUSEADDR,TRNLPointer(@aValue),SizeOf(TRNLInt32));
  end;
  RNL_SOCKET_OPTION_RCVBUF:begin
   r:=fpsetsockopt(aSocket,SOL_SOCKET,SO_RCVBUF,TRNLPointer(@aValue),SizeOf(TRNLInt32));
  end;
  RNL_SOCKET_OPTION_SNDBUF:begin
   r:=fpsetsockopt(aSocket,SOL_SOCKET,SO_SNDBUF,TRNLPointer(@aValue),SizeOf(TRNLInt32));
  end;
  RNL_SOCKET_OPTION_RCVTIMEO:begin
   tv.tv_sec:=aValue div 1000;
   tv.tv_usec:=(aValue mod 1000)*1000;
   r:=fpsetsockopt(aSocket,SOL_SOCKET,SO_RCVTIMEO,TRNLPointer(@tv),SizeOf(TTimeVal));
  end;
  RNL_SOCKET_OPTION_SNDTIMEO:begin
   tv.tv_sec:=aValue div 1000;
   tv.tv_usec:=(aValue mod 1000)*1000;
   r:=fpsetsockopt(aSocket,SOL_SOCKET,SO_SNDTIMEO,TRNLPointer(@tv),SizeOf(TTimeVal));
  end;
  RNL_SOCKET_OPTION_NODELAY:begin
   r:=fpsetsockopt(aSocket,IPPROTO_TCP,TCP_NODELAY,TRNLPointer(@aValue),SizeOf(TRNLInt32));
  end;
  RNL_SOCKET_OPTION_DONTFRAGMENT:begin
{$if defined(Linux) or defined(Android)}
   if aValue<>0 then begin
    t:=IP_PMTUDISC_DO;
   end else begin
    t:=IP_PMTUDISC_DONT;
   end;
   r:=setsockopt(aSocket,IPPROTO_IP,IP_MTU_DISCOVER,TRNLPointer(@t),SizeOf(TRNLInt32));
{$else}
   t:=aValue;
   r:=setsockopt(aSocket,IPPROTO_IP,IP_DONTFRAG,TRNLPointer(@t),SizeOf(TRNLInt32));
{$ifend}
  end;
  RNL_SOCKET_OPTION_IPV6_V6ONLY:begin
   r:=fpsetsockopt(aSocket,IPPROTO_IPV6,IPV6_V6ONLY,TRNLPointer(@aValue),SizeOf(TRNLInt32));
  end;
 end;
 result:=r<>SOCKET_ERROR;
end;
{$else}
var r,t:TRNLInt32;
    nonBlocking:TRNLUInt32;
    tv:TimeVal;
begin
 r:=SOCKET_ERROR;
 case aOption of
  RNL_SOCKET_OPTION_NONBLOCK:begin
   nonBlocking:=aValue;
   r:=ioctl(aSocket,FIONBIO,TRNLPointer(@nonBlocking));
  end;
  RNL_SOCKET_OPTION_BROADCAST:begin
   r:=setsockopt(aSocket,SOL_SOCKET,SO_BROADCAST,aValue,SizeOf(TRNLInt32));
  end;
  RNL_SOCKET_OPTION_REUSEADDR:begin
   r:=setsockopt(aSocket,SOL_SOCKET,SO_REUSEADDR,aValue,SizeOf(TRNLInt32));
  end;
  RNL_SOCKET_OPTION_RCVBUF:begin
   r:=setsockopt(aSocket,SOL_SOCKET,SO_RCVBUF,aValue,SizeOf(TRNLInt32));
  end;
  RNL_SOCKET_OPTION_SNDBUF:begin
   r:=setsockopt(aSocket,SOL_SOCKET,SO_SNDBUF,aValue,SizeOf(TRNLInt32));
  end;
  RNL_SOCKET_OPTION_RCVTIMEO:begin
   tv.tv_sec:=aValue div 1000;
   tv.tv_usec:=(aValue mod 1000)*1000;
   r:=setsockopt(aSocket,SOL_SOCKET,SO_RCVTIMEO,tv,SizeOf(TimeVal));
  end;
  RNL_SOCKET_OPTION_SNDTIMEO:begin
   tv.tv_sec:=aValue div 1000;
   tv.tv_usec:=(aValue mod 1000)*1000;
   r:=setsockopt(aSocket,SOL_SOCKET,SO_SNDTIMEO,tv,SizeOf(TimeVal));
  end;
  RNL_SOCKET_OPTION_NODELAY:begin
   r:=setsockopt(aSocket,IPPROTO_TCP,TCP_NODELAY,aValue,SizeOf(TRNLInt32));
  end;
  RNL_SOCKET_OPTION_DONTFRAGMENT:begin
{$if defined(Linux) or defined(Android)}
   if aValue<>0 then begin
    t:=IP_PMTUDISC_DO;
   end else begin
    t:=IP_PMTUDISC_DONT;
   end;
   r:=setsockopt(aSocket,IPPROTO_IP,IP_MTU_DISCOVER,t,SizeOf(TRNLInt32));
{$else}
   t:=aValue;
   r:=setsockopt(aSocket,IPPROTO_IP,IP_DONTFRAG,t,SizeOf(TRNLInt32));
{$ifend}
  end;
  RNL_SOCKET_OPTION_IPV6_V6ONLY:begin
   r:=setsockopt(aSocket,IPPROTO_IPV6,IPV6_V6ONLY,aValue,SizeOf(TRNLInt32));
  end;
 end;
 result:=r<>SOCKET_ERROR;
end;
{$ifend}

function TRNLRealNetwork.SocketGetOption(const aSocket:TRNLSocket;const aOption:TRNLSocketOption;out aValue:TRNLInt32):boolean;
{$if defined(Windows)}
var r:TRNLInt32;
begin
 r:=SOCKET_ERROR;
 case aOption of
  RNL_SOCKET_OPTION_ERROR:begin
   r:=setsockopt(aSocket,SOL_SOCKET,SO_ERROR,TRNLPointer(@aValue),SizeOf(TRNLInt32));
  end;
 end;
 result:=r<>SOCKET_ERROR;
end;
{$else}
var r:TRNLInt32;
    SockLen:socklen_t;
begin
 r:=SOCKET_ERROR;
 case aOption of
  RNL_SOCKET_OPTION_ERROR:begin
   SockLen:=SizeOf(TRNLInt32);
{$ifdef fpc}
   r:=fpgetsockopt(aSocket,SOL_SOCKET,SO_ERROR,TRNLPointer(@aValue),@SockLen);
{$else}
   r:=getsockopt(aSocket,SOL_SOCKET,SO_ERROR,aValue,SockLen);
{$endif}
  end;
 end;
 result:=r<>SOCKET_ERROR;
end;
{$ifend}

function TRNLRealNetwork.SocketBind(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aFamily:TRNLAddressFamily):boolean;
var SIN:TSockaddrStorage;
    Address_:TRNLAddress;
begin
 if assigned(aAddress) then begin
  aAddress^.SetSIN(@SIN,aFamily);
 end else begin
  Address_.Host:=RNL_HOST_ANY_INIT;
  Address_.ScopeID:=0;
  Address_.Port:=0;
  Address_.SetSIN(@SIN,aFamily);
 end;
{$if defined(Windows)}
 result:=_bind(aSocket,TRNLPointer(@SIN),aFamily.GetSockAddrSize)<>SOCKET_ERROR;
{$elseif defined(fpc)}
 result:=fpbind(aSocket,TRNLPointer(@SIN),aFamily.GetSockAddrSize)<>SOCKET_ERROR;
{$else}
 result:=Posix.SysSocket.bind(aSocket,sockaddr(TRNLPointer(@SIN)^),aFamily.GetSockAddrSize)<>SOCKET_ERROR;
{$ifend}
end;

function TRNLRealNetwork.SocketListen(const aSocket:TRNLSocket;const aBackLog:TRNLInt32):boolean;
begin
{$if defined(Windows)}
 if aBackLog<0 then begin
  result:=_listen(aSocket,SOMAXCONN)<>SOCKET_ERROR;
 end else begin
  result:=_listen(aSocket,aBackLog)<>SOCKET_ERROR;
 end;
{$elseif defined(fpc)}
 if aBackLog<0 then begin
  result:=fplisten(aSocket,SOMAXCONN)<>SOCKET_ERROR;
 end else begin
  result:=fplisten(aSocket,aBackLog)<>SOCKET_ERROR;
 end;
{$else}
 if aBackLog<0 then begin
  result:=Posix.SysSocket.listen(aSocket,SOMAXCONN)<>SOCKET_ERROR;
 end else begin
  result:=Posix.SysSocket.listen(aSocket,aBackLog)<>SOCKET_ERROR;
 end;
{$ifend}
end;

function TRNLRealNetwork.SocketConnect(const aSocket:TRNLSocket;const aAddress:TRNLAddress;const aFamily:TRNLAddressFamily):boolean;
var r:TRNLInt32;
    SIN:TSockaddrStorage;
begin
 aAddress.SetSIN(@SIN,aFamily);
{$if defined(Windows)}
 r:=_Connect(aSocket,TRNLPointer(@SIN),aFamily.GetSockAddrSize);
 result:=not ((r=SOCKET_ERROR) and (WSAGetLastError<>WSAEWOULDBLOCK));
{$elseif defined(fpc)}
 r:=fpconnect(aSocket,TRNLPointer(@SIN),aFamily.GetSockAddrSize);
 if (r=SOCKET_ERROR) and (fpgeterrno=ESysEINPROGRESS) then begin
  result:=true;
 end else begin
  result:=r<>SOCKET_ERROR;
 end;
{$else}
 r:=Posix.SysSocket.connect(aSocket,sockaddr(TRNLPointer(@SIN)^),aFamily.GetSockAddrSize);
 if (r=SOCKET_ERROR) and (Posix.Errno.Errno=EINPROGRESS) then begin
  result:=true;
 end else begin
  result:=r<>SOCKET_ERROR;
 end;
{$ifend}
end;

function TRNLRealNetwork.SocketAccept(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aFamily:TRNLAddressFamily):TRNLSocket;
var SIN:TSockaddrStorage;
    SINLength:{$if defined(Windows)}TRNLInt32{$else}socklen_t{$ifend};
begin
 SINLength:=aFamily.GetSockAddrSize;
{$if defined(Windows)}
 if assigned(aAddress) then begin
  result:=_accept(aSocket,TSockAddr(TRNLPointer(@SIN)^),SINLength);
 end else begin
  result:=_accept(aSocket,TSockAddr(TRNLPointer(nil)^),TRNLInt32(TRNLPointer(nil)^));
 end;
{$elseif defined(fpc)}
 if assigned(aAddress) then begin
  result:=fpaccept(aSocket,TRNLPointer(@SIN),@SINLength);
 end else begin
  result:=fpaccept(aSocket,nil,nil);
 end;
{$else}
 if assigned(aAddress) then begin
  result:=Posix.SysSocket.accept(aSocket,sockaddr(TRNLPointer(@SIN)^),SINLength);
 end else begin
  result:=Posix.SysSocket.accept(aSocket,sockaddr(TRNLPointer(nil)^),socklen_t(TRNLPointer(nil)^));
 end;
{$ifend}
 if result=RNL_INVALID_SOCKET then begin
  result:=RNL_SOCKET_NULL;
  exit;
 end;
 if assigned(aAddress) then begin
  aAddress.SetAddress(@SIN);
 end;
end;

function TRNLRealNetwork.SocketSelect(const aMaxSocket:TRNLSocket;var aReadSet,aWriteSet:TRNLSocketSet;const aTimeout:TRNLTime):TRNLInt32;
var tv:{$if defined(Windows)}TTimeVal{$elseif defined(fpc)}TTimeVal{$else}TimeVal{$ifend};
begin
 tv.tv_sec:=aTimeout div 1000;
 tv.tv_usec:=(aTimeout mod 1000)*1000;
{$if defined(Windows)}
 result:=_select(aMaxSocket+1,@aReadSet,@aWriteSet,nil,@tv);
{$elseif defined(fpc)}
 result:=fpselect(aMaxSocket+1,@aReadSet,@aWriteSet,nil,@tv);
{$else}
 result:=Posix.SysSelect.select(aMaxSocket+1,@aReadSet,@aWriteSet,nil,@tv);
{$ifend}
end;

function TRNLRealNetwork.SocketWait(const aSockets:array of TRNLSocket;var aConditions:TRNLSocketWaitConditions;const aTimeout:TRNLTime):boolean;
var Index,SelectCount:TRNLInt32;
    ReadSet,WriteSet:TRNLSocketSet;
    tv:{$if defined(Windows)}TTimeVal{$elseif defined(fpc)}TTimeVal{$else}TimeVal{$ifend};
    MaxSocket:TRNLSocket;
begin

 tv.tv_sec:=aTimeout div 1000;
 tv.tv_usec:=(aTimeout mod 1000)*1000;

{$if defined(Windows)}
 FD_ZERO(ReadSet);
 FD_ZERO(WriteSet);
{$elseif defined(fpc)}
 fpFD_ZERO(ReadSet);
 fpFD_ZERO(WriteSet);
{$else}
 FD_ZERO(ReadSet);
 FD_ZERO(WriteSet);
{$ifend}

 for Index:=0 to length(aSockets)-1 do begin
  if aSockets[Index]<>RNL_SOCKET_NULL then begin
   if RNL_SOCKET_WAIT_CONDITION_RECEIVE in aConditions then begin
{$if defined(Windows)}
    FD_SET(aSockets[Index],ReadSet);
{$elseif defined(Posix)}
    __fd_set(aSockets[Index],ReadSet);
{$elseif defined(Unix)}
    fpFD_SET(aSockets[Index],ReadSet);
{$else}
    FD_SET(aSockets[Index],ReadSet);
{$ifend}
   end;
   if RNL_SOCKET_WAIT_CONDITION_SEND in aConditions then begin
{$if defined(Windows)}
    FD_SET(aSockets[Index],WriteSet);
{$elseif defined(Posix)}
    __fd_set(aSockets[Index],WriteSet);
{$elseif defined(Unix)}
    fpFD_SET(aSockets[Index],WriteSet);
{$else}
    FD_SET(aSockets[Index],WriteSet);
{$ifend}
   end;
  end;
 end;

 MaxSocket:=0;
 for Index:=0 to length(aSockets)-1 do begin
  if (aSockets[Index]<>RNL_SOCKET_NULL) and (MaxSocket>aSockets[Index]) then begin
   MaxSocket:=aSockets[Index];
  end;
 end;

{$if defined(Windows)}
 SelectCount:=_select(MaxSocket+1,@ReadSet,@WriteSet,nil,@tv);
 if SelectCount<0 then begin
  result:=false;
  exit;
 end;
{$else}
{$ifdef fpc}
 SelectCount:=fpselect(MaxSocket+1,@ReadSet,@WriteSet,nil,@tv);
{$else}
 SelectCount:=Posix.SysSelect.select(MaxSocket+1,@ReadSet,@WriteSet,nil,@tv);
{$endif}
 if SelectCount<0 then begin
  if (errno={$ifdef fpc}ESysEINTR{$else}EINTR{$endif}) and
     (RNL_SOCKET_WAIT_CONDITION_INTERRUPT in aConditions) then begin
   aConditions:=[RNL_SOCKET_WAIT_CONDITION_INTERRUPT];
   result:=true;
  end else begin
   result:=false;
  end;
  exit;
 end;
{$ifend}

 aConditions:=[];

 if SelectCount=0 then begin
  result:=true;
  exit;
 end;

 for Index:=0 to length(aSockets)-1 do begin
  if aSockets[Index]<>RNL_SOCKET_NULL then begin
   if {$if defined(Windows)}FD_ISSET(aSockets[Index],ReadSet)
      {$elseif defined(fpc)}
       fpFD_ISSET(aSockets[Index],ReadSet)=1
      {$else}
       __fd_isset(aSockets[Index],ReadSet)
      {$ifend} then begin
    Include(aConditions,RNL_SOCKET_WAIT_CONDITION_RECEIVE);
   end;
   if {$if defined(Windows)}FD_ISSET(aSockets[Index],WriteSet)
      {$elseif defined(fpc)}
       fpFD_ISSET(aSockets[Index],WriteSet)=1
      {$else}
       __fd_isset(aSockets[Index],WriteSet)
      {$ifend} then begin
    Include(aConditions,RNL_SOCKET_WAIT_CONDITION_SEND);
   end;
  end;
 end;

 result:=true;
end;

function TRNLRealNetwork.SendBuffers(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aBuffers;const aCountBuffers:TRNLUInt32;const aFamily:TRNLAddressFamily):TRNLSizeInt;
{$if defined(Windows)}
var SIN:TSockaddrStorage;
    SentLength:TRNLUInt32;
begin
 if assigned(aAddress) then begin
  aAddress^.SetSIN(@SIN,aFamily);
  if WSASendTo(aSocket,LPWSABUF(@aBuffers),aCountBuffers,SentLength,0,TRNLPointer(@SIN),aFamily.GetSockAddrSize,nil,nil)=SOCKET_ERROR then begin
   case WSAGetLastError of
    WSAEWOULDBLOCK,WSAEMSGSIZE:begin
     result:=0;
    end;
    else begin
     result:=-1;
    end;
   end;
   exit;
  end;
 end else begin
  if WSASendTo(aSocket,LPWSABUF(@aBuffers),aCountBuffers,SentLength,0,nil,0,nil,nil)=SOCKET_ERROR then begin
   case WSAGetLastError of
    WSAEWOULDBLOCK,WSAEMSGSIZE:begin
     result:=0;
    end;
    else begin
     result:=-1;
    end;
   end;
   exit;
  end;
 end;
 result:=SentLength;
end;
{$else}
var SIN:TSockaddrStorage;
    SentLength:TRNLInt32;
begin
 if assigned(aAddress) then begin
  aAddress^.SetSIN(@SIN,aFamily);
{$ifdef fpc}
  SentLength:=fpSendTo(aSocket,TRNLPointer(@aBuffers),aCountBuffers,MSG_NOSIGNAL,TRNLPointer(@SIN),aFamily.GetSockAddrSize);
  if SentLength=SOCKET_ERROR then begin
   case socketerror of
    EsockEWOULDBLOCK,EsockEMSGSIZE:begin
{$else}
  SentLength:=Posix.SysSocket.SendTo(aSocket,aBuffers,aCountBuffers,MSG_NOSIGNAL,sockaddr(TRNLPointer(@SIN)^),aFamily.GetSockAddrSize);
  if SentLength=SOCKET_ERROR then begin
   case GetLastError of
    EWOULDBLOCK,EMSGSIZE:begin
{$endif}
     result:=0;
    end;
    else begin
     result:=-1;
    end;
   end;
   exit;
  end;
 end else begin
{$ifdef fpc}
  SentLength:=fpSendTo(aSocket,TRNLPointer(@aBuffers),aCountBuffers,MSG_NOSIGNAL,nil,0);
  if SentLength=SOCKET_ERROR then begin
   case socketerror of
    EsockEWOULDBLOCK,EsockEMSGSIZE:begin
{$else}
  SentLength:=Posix.SysSocket.SendTo(aSocket,aBuffers,aCountBuffers,MSG_NOSIGNAL,sockaddr(TRNLPointer(nil)^),0);
  if SentLength=SOCKET_ERROR then begin
   case GetLastError of
    EWOULDBLOCK,EMSGSIZE:begin
{$endif}
     result:=0;
    end;
    else begin
     result:=-1;
    end;
   end;
   exit;
  end;
 end;
 result:=SentLength;
end;
{$ifend}

function TRNLRealNetwork.ReceiveBuffers(const aSocket:TRNLSocket;const aAddress:PRNLAddress;var aBuffers;const aCountBuffers:TRNLUInt32;const aFamily:TRNLAddressFamily):TRNLSizeInt;
{$if defined(Windows)}
var SIN:TSockaddrStorage;
    SINLength:TRNLInt32;
    Flags,RecvLength:TRNLUInt32;
begin
 SINLength:=aFamily.GetSockAddrSize;
 Flags:=0;
 if assigned(aAddress) then begin
  if WSARecvFrom(aSocket,LPWSABUF(@aBuffers),aCountBuffers,RecvLength,Flags,TRNLPointer(@SIN),@SINLength,nil,nil)=SOCKET_ERROR then begin
   case WSAGetLastError of
    WSAEWOULDBLOCK,WSAECONNRESET,WSAEMSGSIZE:begin
     result:=0;
    end;
    else begin
     result:=-1;
    end;
   end;
   exit;
  end;
 end else begin
  if WSARecvFrom(aSocket,LPWSABUF(@aBuffers),aCountBuffers,RecvLength,Flags,nil,nil,nil,nil)=SOCKET_ERROR then begin
   case WSAGetLastError of
    WSAEWOULDBLOCK,WSAECONNRESET,WSAEMSGSIZE:begin
     result:=0;
    end;
    else begin
     result:=-1;
    end;
   end;
   exit;
  end;
 end;
 if (Flags and MSG_PARTIAL)<>0 then begin
  result:=-1;
  exit;
 end;
 if assigned(aAddress) then begin
  aAddress^.SetAddress(@SIN);
 end;
 result:=RecvLength;
end;
{$else}
var SIN:TSockaddrStorage;
    SINLength,RecvLength:TRNLInt32;
begin
 SINLength:=aFamily.GetSockAddrSize;
 RecvLength:=0;
{$ifdef fpc}
 if assigned(aAddress) then begin
  RecvLength:=fpRecvFrom(aSocket,TRNLPointer(@aBuffers),aCountBuffers,MSG_NOSIGNAL,TRNLPointer(@SIN),@SINLength);
  if RecvLength=SOCKET_ERROR then begin
   case SocketError of
    EsockEWOULDBLOCK{,EsockECONNRESET},EsockEMSGSIZE:begin
     result:=0;
    end;
    else begin
     result:=-1;
    end;
   end;
   exit;
  end;
 end else begin
  RecvLength:=fpRecvFrom(aSocket,TRNLPointer(@aBuffers),aCountBuffers,MSG_NOSIGNAL,nil,nil);
  if RecvLength=SOCKET_ERROR then begin
   case SocketError of
    EsockEWOULDBLOCK{,EsockECONNRESET},EsockEMSGSIZE:begin
     result:=0;
    end;
    else begin
     result:=-1;
    end;
   end;
   exit;
  end;
 end;
{$else}
 if assigned(aAddress) then begin
  RecvLength:=Posix.SysSocket.RecvFrom(aSocket,aBuffers,aCountBuffers,MSG_NOSIGNAL,sockaddr(TRNLPointer(@SIN)^),TRNLUInt32(SINLength));
  if RecvLength=SOCKET_ERROR then begin
   case GetLastError of
    EWOULDBLOCK{,ECONNRESET},EMSGSIZE:begin
     result:=0;
    end;
    else begin
     result:=-1;
    end;
   end;
   exit;
  end;
 end else begin
  RecvLength:=Posix.SysSocket.RecvFrom(aSocket,aBuffers,aCountBuffers,MSG_NOSIGNAL,sockaddr(TRNLPointer(nil)^),TRNLUInt32(TRNLPointer(@SIN)^));
  if RecvLength=SOCKET_ERROR then begin
   case GetLastError of
    EWOULDBLOCK{,ECONNRESET},EMSGSIZE:begin
     result:=0;
    end;
    else begin
     result:=-1;
    end;
   end;
   exit;
  end;
 end;
{$endif}
{if (Flags and MSG_PARTIAL)<>0 then begin
  result:=-1;
  exit;
 end;}
 if assigned(aAddress) then begin
  aAddress^.SetAddress(@SIN);
 end;
 result:=RecvLength;
end;
{$ifend}

function TRNLRealNetwork.Send(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aData;const aDataLength:TRNLSizeInt;const aFamily:TRNLAddressFamily):TRNLSizeInt;
var Buffer:TRNLBuffer;
begin
 Buffer.Data:=@aData;
 Buffer.DataLength:=aDataLength;
 result:=SendBuffers(aSocket,aAddress,Buffer,1,aFamily);
end;

function TRNLRealNetwork.Receive(const aSocket:TRNLSocket;const aAddress:PRNLAddress;var aData;const aDataLength:TRNLSizeInt;const aFamily:TRNLAddressFamily):TRNLSizeInt;
var Buffer:TRNLBuffer;
begin
 Buffer.Data:=@aData;
 Buffer.DataLength:=aDataLength;
 result:=ReceiveBuffers(aSocket,aAddress,Buffer,1,aFamily);
end;

constructor TRNLVirtualNetwork.TRNLVirtualNetworkSocketInstance.Create(const aNetwork:TRNLVirtualNetwork;const aSocket:TRNLSocket);
begin

 inherited Create;

 fValue:=self;

 fNetwork:=aNetwork;

 fSocket:=aSocket;

 FillChar(fAddress,SizeOf(TRNLAddress),#0);

 System.Move(RNL_IPV4MAPPED_PREFIX,fAddress.Host,RNL_IPV4MAPPED_PREFIX_LEN);

 fAddress.Host.Addr[RNL_IPV4MAPPED_PREFIX_LEN+0]:=((aSocket+1) shr 24) and $ff;
 fAddress.Host.Addr[RNL_IPV4MAPPED_PREFIX_LEN+1]:=((aSocket+1) shr 16) and $ff;
 fAddress.Host.Addr[RNL_IPV4MAPPED_PREFIX_LEN+2]:=((aSocket+1) shr 8) and $ff;
 fAddress.Host.Addr[RNL_IPV4MAPPED_PREFIX_LEN+3]:=((aSocket+1) shr 0) and $ff;

 fAddress.ScopeID:=1;

 fAddress.Port:=(TRNLUInt16(aSocket)+1) and $ffff;

 fAddressHash:=0;

 fAddressListNode:=TRNLVirtualNetworkSocketInstanceListNode.Create;
 fAddressListNode.fValue:=self;

 fSocketInstanceListNode:=TRNLVirtualNetworkSocketInstanceListNode.Create;
 fSocketInstanceListNode.fValue:=self;

 fData:=TRNLVirtualNetworkSocketDataQueue.Create;

end;

destructor TRNLVirtualNetwork.TRNLVirtualNetworkSocketInstance.Destroy;
begin

 FreeAndNil(fAddressListNode);

 FreeAndNil(fSocketInstanceListNode);

 FreeAndNil(fData);

 inherited Destroy;

end;

procedure TRNLVirtualNetwork.TRNLVirtualNetworkSocketInstance.UpdateAddress;
var Hash:TRNLUInt32;
begin
 fAddressListNode.Remove;
 Hash:=TRNLVirtualNetwork.HashAddress(fAddress);
 fAddressHash:=Hash;
 fNetwork.fAddressSocketInstanceHashMap[Hash and RNL_VIRTUAL_NETWORK_SOCKET_HASH_MASK].Add(fAddressListNode);
end;

constructor TRNLVirtualNetwork.Create(const aInstance:TRNLInstance);
var Index:TRNLSizeInt;
begin

 inherited Create(aInstance);

 fLock:=TCriticalSection.Create;

 fNewDataEvent:=TEvent.Create(nil,false,false,'');

 fSocketCounter:=0;

 fFreeSockets:=TRNLVirtualNetworkSocketStack.Create;

 fSocketInstanceList:=TRNLVirtualNetworkSocketInstanceListNode.Create;

 for Index:=Low(TRNLVirtualNetworkSocketInstanceHashMap) to High(TRNLVirtualNetworkSocketInstanceHashMap) do begin
  fSocketInstanceHashMap[Index]:=TRNLVirtualNetworkSocketInstanceListNode.Create;
  fAddressSocketInstanceHashMap[Index]:=TRNLVirtualNetworkSocketInstanceListNode.Create;
 end;

end;

destructor TRNLVirtualNetwork.Destroy;
var Index:TRNLSizeInt;
begin

 while not fSocketInstanceList.Empty do begin
  fSocketInstanceList.Front.Value.Free;
 end;
 FreeAndNil(fSocketInstanceList);

 for Index:=Low(TRNLVirtualNetworkSocketInstanceHashMap) to High(TRNLVirtualNetworkSocketInstanceHashMap) do begin

  while not fSocketInstanceHashMap[Index].Empty do begin
   fSocketInstanceHashMap[Index].Front.Value.Free;
  end;
  FreeAndNil(fSocketInstanceHashMap[Index]);

  while not fAddressSocketInstanceHashMap[Index].Empty do begin
   fAddressSocketInstanceHashMap[Index].Front.Value.Free;
  end;
  FreeAndNil(fAddressSocketInstanceHashMap[Index]);

 end;

 FreeAndNil(fFreeSockets);

 FreeAndNil(fNewDataEvent);

 FreeAndNil(fLock);

 inherited Destroy;

end;

class function TRNLVirtualNetwork.HashSocket(const aSocket:TRNLSocket):TRNLUInt32;
begin
 result:=TRNLHashUtils.Hash32(aSocket,SizeOf(TRNLSocket));
end;

class function TRNLVirtualNetwork.HashAddress(const aAddress:TRNLAddress):TRNLUInt32;
begin
 result:=TRNLHashUtils.Hash32(aAddress,SizeOf(TRNLAddress));
end;

function TRNLVirtualNetwork.FindSocketInstance(const aSocket:TRNLSocket;const aCreateIfNotExist:boolean):TRNLVirtualNetworkSocketInstance;
var Hash:TRNLUInt32;
    HashBucket,HashBucketItem:TRNLVirtualNetworkSocketInstanceListNode;
begin
 if aSocket=RNL_SOCKET_NULL then begin
  result:=nil;
 end else begin
  Hash:=HashSocket(aSocket);
  HashBucket:=fSocketInstanceHashMap[Hash and RNL_VIRTUAL_NETWORK_SOCKET_HASH_MASK];
  HashBucketItem:=HashBucket.Front;
  while HashBucketItem<>HashBucket do begin
   if HashBucketItem.Value.fSocket=aSocket then begin
    result:=HashBucketItem.Value;
    exit;
   end;
   HashBucketItem:=HashBucketItem.Next;
  end;
  if aCreateIfNotExist then begin
   result:=TRNLVirtualNetworkSocketInstance.Create(self,aSocket);
   fSocketInstanceHashMap[Hash and RNL_VIRTUAL_NETWORK_SOCKET_HASH_MASK].Add(result);
   result.UpdateAddress;
   fSocketInstanceList.Add(result.fSocketInstanceListNode);
  end else begin
   result:=nil;
  end;
 end;
end;

function TRNLVirtualNetwork.FindAddressSocketInstance(const aAddress:TRNLAddress):TRNLVirtualNetworkSocketInstance;
var Hash:TRNLUInt32;
    HashBucket,HashBucketItem:TRNLVirtualNetworkSocketInstanceListNode;
begin
 Hash:=HashAddress(aAddress);
 HashBucket:=fAddressSocketInstanceHashMap[Hash and RNL_VIRTUAL_NETWORK_SOCKET_HASH_MASK];
 HashBucketItem:=HashBucket.Front;
 while HashBucketItem<>HashBucket do begin
  if (HashBucketItem.Value.fAddressHash=Hash) and
     TRNLMemory.SecureIsEqual(HashBucketItem.Value.fAddress,aAddress,SizeOf(TRNLAddress)) then begin
   result:=HashBucketItem.Value;
   exit;
  end;
  HashBucketItem:=HashBucketItem.Next;
 end;
 result:=nil;
end;

function TRNLVirtualNetwork.AddressSetHost(var aAddress:TRNLAddress;const aName:TRNLRawByteString):boolean;
 function ParseIP(const aInputString:TRNLRawByteString;out aAddress:TRNLAddress):boolean;
 var Index,Part,StringLength,Value,Base,
     FirstColonPosition,
     FirstDotPosition,
     FirstOpenBracketPosition,
     FirstCloseBracketPosition,
     ZeroCompressionLocation:TRNLSizeInt;
     IsLocalIPv6:boolean;
 begin

  result:=false;

  StringLength:=length(aInputString);

  FirstColonPosition:=0;
  FirstDotPosition:=0;
  FirstOpenBracketPosition:=0;
  FirstCloseBracketPosition:=0;

  for Index:=1 to StringLength do begin
   case aInputString[Index] of
    ':':begin
     if FirstColonPosition=0 then begin
      FirstColonPosition:=Index;
     end;
    end;
    '.':begin
     if FirstDotPosition=0 then begin
      FirstDotPosition:=Index;
     end;
    end;
    '[':begin
     if FirstOpenBracketPosition=0 then begin
      FirstOpenBracketPosition:=Index;
     end;
    end;
    ']':begin
     if FirstCloseBracketPosition=0 then begin
      FirstCloseBracketPosition:=Index;
     end;
    end;
   end;
  end;

  IsLocalIPv6:=(FirstOpenBracketPosition>0) or
               (FirstDotPosition=0) or
               ((FirstColonPosition>0) and
                ((FirstDotPosition=0) or
                 (FirstColonPosition<FirstDotPosition)));

  if IsLocalIPv6 then begin

   if (FirstOpenBracketPosition>0) and
      ((FirstCloseBracketPosition=0) or
       (FirstOpenBracketPosition>FirstCloseBracketPosition)) then begin
    exit;
   end;

   ZeroCompressionLocation:=-1;

   Index:=FirstOpenBracketPosition+1;

   Part:=0;
   while Part<16 do begin

    Value:=0;

    if (Index<=StringLength) and (aInputString[Index] in ['0'..'9','a'..'f','A'..'F']) then begin

     Base:=Index;

     while Index<=StringLength do begin
      case aInputString[Index] of
       '0'..'9':begin
        Value:=(Value shl 4) or (ord(aInputString[Index])-ord('0'));
       end;
       'a'..'f':begin
        Value:=(Value shl 4) or ((ord(aInputString[Index])-ord('a'))+$a);
       end;
       'A'..'F':begin
        Value:=(Value shl 4) or ((ord(aInputString[Index])-ord('A'))+$a);
       end;
       else begin
        break;
       end;
      end;
      inc(Index);
     end;

     if (Index<=StringLength) and (aInputString[Index]='.') then begin

      Index:=Base;

      Base:=Part;

      for Part:=0 to 3 do begin

       if not ((Index<=StringLength) and (aInputString[Index] in ['0'..'9'])) then begin
        exit;
       end;

       Value:=0;
       while (Index<=StringLength) and (aInputString[Index] in ['0'..'9']) do begin
        Value:=(Value*10)+(ord(aInputString[Index])-ord('0'));
        inc(Index);
       end;

       aAddress.Host.Addr[Base+Part]:=Value;

       if Part<>3 then begin
        if (Index<=StringLength) and (aInputString[Index]='.') then begin
         inc(Index);
        end else begin
         exit;
        end;
       end;

      end;

      Part:=Base+4;

      break;

     end else begin

      if Part<14 then begin
       if (Index<=StringLength) and (aInputString[Index]=':') then begin
        inc(Index);
       end else begin
        exit;
       end;
      end;

      aAddress.Host.Addr[Part+0]:=Value shr 8;
      aAddress.Host.Addr[Part+1]:=Value and $ff;

     end;

    end else begin

     if ZeroCompressionLocation>=0 then begin
      if Index=(FirstOpenBracketPosition+1) then begin
       dec(Part);
       break;
      end else begin
       exit;
      end;
     end;

     if (Index<=StringLength) and (aInputString[Index]=':') then begin
      if Part=0 then begin
       inc(Index);
       if (not (Index<=StringLength) and (aInputString[Index]=':')) then begin
        exit;
       end;
      end;
      inc(Index);
      ZeroCompressionLocation:=Part;
     end else begin
      exit;
     end;

    end;

    inc(Part,2);

   end;

   if FirstCloseBracketPosition>0 then begin
    Index:=FirstCloseBracketPosition+1;
   end;

   if ZeroCompressionLocation>=0 then begin
    System.Move(aAddress.Host.Addr[ZeroCompressionLocation],
                aAddress.Host.Addr[16-(Part-ZeroCompressionLocation)],
                Part-ZeroCompressionLocation);
    FillChar(aAddress.Host.Addr[ZeroCompressionLocation],(16-(Part-ZeroCompressionLocation))-ZeroCompressionLocation,#0);
   end;

  end else begin

   if (FirstDotPosition=0) or
      (FirstColonPosition>FirstDotPosition) or
      (FirstOpenBracketPosition>0) or
      (FirstCloseBracketPosition>0) then begin
    exit;
   end;

   aAddress.Host:=RNL_IPV4MAPPED_PREFIX;

   Index:=1;

   for Part:=0 to 3 do begin

    if not ((Index<=StringLength) and (aInputString[Index] in ['0'..'9'])) then begin
     exit;
    end;

    Value:=0;
    while (Index<=StringLength) and (aInputString[Index] in ['0'..'9']) do begin
     Value:=(Value*10)+(ord(aInputString[Index])-ord('0'));
     inc(Index);
    end;

    aAddress.Host.Addr[RNL_IPV4MAPPED_PREFIX_LEN+Part]:=Value;

    if Part<>3 then begin
     if (Index<=StringLength) and (aInputString[Index]='.') then begin
      inc(Index);
     end else begin
      exit;
     end;
    end;

   end;

  end;

  if (Index<=StringLength) and (aInputString[Index]=':') then begin

   inc(Index);

   if not ((Index<=StringLength) and (aInputString[Index] in ['0'..'9'])) then begin
    exit;
   end;

   Value:=0;
   while (Index<=StringLength) and (aInputString[Index] in ['0'..'9']) do begin
    Value:=(Value*10)+(ord(aInputString[Index])-ord('0'));
    inc(Index);
   end;

   aAddress.Port:=Value;

  end;

 end;
begin
 FillChar(aAddress,SizeOf(TRNLAddress),#0);
 result:=ParseIP(aName,aAddress);
end;

function TRNLVirtualNetwork.AddressGetHost(const aAddress:TRNLAddress;out aName;const aNameLength:TRNLInt32;const aFlags:TRNLInt32=0):boolean;
const HexChars:array[0..15] of TRNLUInt8=(ord('0'),ord('1'),ord('2'),ord('3'),
                                          ord('4'),ord('5'),ord('6'),ord('7'),
                                          ord('8'),ord('9'),ord('a'),ord('b'),
                                          ord('c'),ord('d'),ord('e'),ord('f'));
var Index:TRNLSizeInt;
begin
 // Do it with the most simple way => as non-zero-compressed non-beginning-zero-trimmed IPv6 address
 result:=(aNameLength>0) and (aNameLength>=40);
 if result then begin
  for Index:=0 to 7 do begin
   PRNLUInt8Array(TRNLPointer(@aName))^[(Index*5)+0]:=HexChars[(aAddress.Host.Addr[(Index shl 1) or 0] shr 4) and $f];
   PRNLUInt8Array(TRNLPointer(@aName))^[(Index*5)+1]:=HexChars[(aAddress.Host.Addr[(Index shl 1) or 0] shr 0) and $f];
   PRNLUInt8Array(TRNLPointer(@aName))^[(Index*5)+2]:=HexChars[(aAddress.Host.Addr[(Index shl 1) or 1] shr 4) and $f];
   PRNLUInt8Array(TRNLPointer(@aName))^[(Index*5)+3]:=HexChars[(aAddress.Host.Addr[(Index shl 1) or 1] shr 0) and $f];
   if Index<>7 then begin
    PRNLUInt8Array(TRNLPointer(@aName))^[(Index*5)+4]:=ord(':');
   end else begin
    PRNLUInt8Array(TRNLPointer(@aName))^[(Index*5)+4]:=0;
   end;
  end;
 end;
end;

function TRNLVirtualNetwork.AddressGetHostIP(const aAddress:TRNLAddress;out aName;const aNameLength:TRNLInt32):boolean;
begin
 result:=AddressGetHost(aAddress,aName,aNameLength,0);
end;

function TRNLVirtualNetwork.SocketCreate(const aType:TRNLSocketType;const aFamily:TRNLAddressFamily):TRNLSocket;
begin
 fLock.Acquire;
 try
  if not fFreeSockets.Pop(result) then begin
   result:=fSocketCounter;
   if result<>RNL_SOCKET_NULL then begin
    inc(fSocketCounter);
   end;
  end;
  if result<>RNL_SOCKET_NULL then begin
   FindSocketInstance(result,true);
  end;
 finally
  fLock.Release;
 end;
end;

procedure TRNLVirtualNetwork.SocketDestroy(const aSocket:TRNLSocket);
var SocketInstance:TRNLVirtualNetworkSocketInstance;
begin
 fLock.Acquire;
 try
  SocketInstance:=FindSocketInstance(aSocket,false);
  if assigned(SocketInstance) then begin
   SocketInstance.Free;
   fFreeSockets.Push(aSocket);
  end;
 finally
  fLock.Release;
 end;
end;

function TRNLVirtualNetwork.SocketShutdown(const aSocket:TRNLSocket;const aHow:TRNLSocketShutdown=RNL_SOCKET_SHUTDOWN_READ):boolean;
begin
 result:=false;
end;

function TRNLVirtualNetwork.SocketGetAddress(const aSocket:TRNLSocket;out aAddress:TRNLAddress;const aFamily:TRNLAddressFamily):boolean;
var SocketInstance:TRNLVirtualNetworkSocketInstance;
begin
 fLock.Acquire;
 try
  SocketInstance:=FindSocketInstance(aSocket,false);
  if assigned(SocketInstance) then begin
   aAddress:=SocketInstance.fAddress;
   result:=true;
  end else begin
   result:=false;
  end;
 finally
  fLock.Release;
 end;
end;

function TRNLVirtualNetwork.SocketSetOption(const aSocket:TRNLSocket;const aOption:TRNLSocketOption;const aValue:TRNLInt32):boolean;
begin
 result:=true;
end;

function TRNLVirtualNetwork.SocketGetOption(const aSocket:TRNLSocket;const aOption:TRNLSocketOption;out aValue:TRNLInt32):boolean;
begin
 result:=false;
end;

function TRNLVirtualNetwork.SocketBind(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aFamily:TRNLAddressFamily):boolean;
var SocketInstance:TRNLVirtualNetworkSocketInstance;
begin
 fLock.Acquire;
 try
  SocketInstance:=FindSocketInstance(aSocket,false);
  if assigned(SocketInstance) then begin
   if assigned(aAddress) then begin
    if TRNLMemory.SecureIsEqual(aAddress^.Host,RNL_HOST_ANY,SizeOf(TRNLHostAddress)) then begin
     SocketInstance.fAddress.Host:=RNL_HOST_IPV4_LOCALHOST;
     SocketInstance.fAddress.ScopeID:=aAddress^.ScopeID;
     SocketInstance.fAddress.Port:=aAddress^.Port;
    end else begin
     SocketInstance.fAddress:=aAddress^;
    end;
    SocketInstance.UpdateAddress;
   end;
   result:=true;
  end else begin
   result:=false;
  end;
 finally
  fLock.Release;
 end;
end;

function TRNLVirtualNetwork.SocketListen(const aSocket:TRNLSocket;const aBackLog:TRNLInt32):boolean;
begin
 result:=false;
end;

function TRNLVirtualNetwork.SocketConnect(const aSocket:TRNLSocket;const aAddress:TRNLAddress;const aFamily:TRNLAddressFamily):boolean;
begin
 result:=false;
end;

function TRNLVirtualNetwork.SocketAccept(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aFamily:TRNLAddressFamily):TRNLSocket;
begin
 result:=RNL_SOCKET_NULL;
end;

function TRNLVirtualNetwork.SocketSelect(const aMaxSocket:TRNLSocket;var aReadSet,aWriteSet:TRNLSocketSet;const aTimeout:TRNLTime):TRNLInt32;
var SocketInstanceListNode:TRNLVirtualNetworkSocketInstanceListNode;
    Socket:TRNLSocket;
    Timeout:TRNLTime;
    TimeoutDifference:TRNLInt64;
begin
 result:=0;
 Timeout:=fInstance.Time+aTimeout;
 repeat
  fLock.Acquire;
  try
   SocketInstanceListNode:=fSocketInstanceList.Front;
   while SocketInstanceListNode<>fSocketInstanceList do begin
    Socket:=SocketInstanceListNode.Value.fSocket;
    if aReadSet.Check(Socket) or aWriteSet.Check(Socket) then begin
     if SocketInstanceListNode.Value.fData.IsEmpty then begin
      aReadSet.Remove(Socket);
      aWriteSet.Remove(Socket);
     end else begin
      inc(result);
     end;
    end;
    SocketInstanceListNode:=SocketInstanceListNode.Next;
   end;
  finally
   fLock.Release;
  end;
  TimeoutDifference:=TRNLTime.RelativeDifference(Timeout,fInstance.Time);
  if (result<>0) or (TimeoutDifference<=0) then begin
   break;
  end else begin
   fNewDataEvent.WaitFor(TimeoutDifference);
  end;
 until false;
end;

function TRNLVirtualNetwork.SocketWait(const aSockets:array of TRNLSocket;var aConditions:TRNLSocketWaitConditions;const aTimeout:TRNLTime):boolean;
var Socket:TRNLSocket;
    SocketInstance:TRNLVirtualNetworkSocketInstance;
    Timeout:TRNLTime;
    TimeoutDifference:TRNLInt64;
    Conditions:TRNLSocketWaitConditions;
begin
 Conditions:=aConditions;
 aConditions:=[];
 Timeout:=fInstance.Time+aTimeout;
 repeat
  if length(aSockets)>0 then begin
   fLock.Acquire;
   try
    for Socket in aSockets do begin
     SocketInstance:=FindSocketInstance(Socket,false);
     if assigned(SocketInstance) and (RNL_SOCKET_WAIT_CONDITION_RECEIVE in Conditions) and not SocketInstance.fData.IsEmpty then begin
      Include(aConditions,RNL_SOCKET_WAIT_CONDITION_RECEIVE);
      break;
     end;
    end;
   finally
    fLock.Release;
   end;
  end;
  TimeoutDifference:=TRNLTime.RelativeDifference(Timeout,fInstance.Time);
  if (aConditions<>[]) or (TimeoutDifference<=0) then begin
   break;
  end else begin
   fNewDataEvent.WaitFor(TimeoutDifference);
  end;
 until false;
 result:=true;
end;

function TRNLVirtualNetwork.SendBuffers(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aBuffers;const aCountBuffers:TRNLUInt32;const aFamily:TRNLAddressFamily):TRNLSizeInt;
var Index:TRNLSizeInt;
    DataLength:TRNLSizeUInt;
    Data:TBytes;
begin
 result:=-1;
 if aCountBuffers=0 then begin
  result:=0;
 end else if aCountBuffers=1 then begin
  result:=Send(aSocket,aAddress,TRNLBuffer(aBuffers).Data^,TRNLBuffer(aBuffers).DataLength,aFamily);
 end else if aCountBuffers>1 then begin
  Data:=nil;
  try
   DataLength:=0;
   for Index:=0 to aCountBuffers-1 do begin
    inc(DataLength,PRNLBufferArray(TRNLPointer(@aBuffers))^[Index].DataLength);
   end;
   SetLength(Data,DataLength);
   DataLength:=0;
   for Index:=0 to aCountBuffers-1 do begin
    System.Move(PRNLBufferArray(TRNLPointer(@aBuffers))^[Index].Data^,
                Data[DataLength],
                PRNLBufferArray(TRNLPointer(@aBuffers))^[Index].DataLength);
    inc(DataLength,PRNLBufferArray(TRNLPointer(@aBuffers))^[Index].DataLength);
   end;
   result:=Send(aSocket,aAddress,Data[0],DataLength,aFamily);
  finally
   Data:=nil;
  end;
 end;
end;

function TRNLVirtualNetwork.ReceiveBuffers(const aSocket:TRNLSocket;const aAddress:PRNLAddress;var aBuffers;const aCountBuffers:TRNLUInt32;const aFamily:TRNLAddressFamily):TRNLSizeInt;
begin
 if aCountBuffers>0 then begin
  result:=Receive(aSocket,aAddress,TRNLBuffer(aBuffers).Data^,TRNLBuffer(aBuffers).DataLength,aFamily);
  if result>=0 then begin
   TRNLBuffer(aBuffers).DataLength:=result;
   result:=0;
  end;
 end else begin
  result:=-1;
 end;
end;

function TRNLVirtualNetwork.Send(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aData;const aDataLength:TRNLSizeInt;const aFamily:TRNLAddressFamily):TRNLSizeInt;
var SocketInstance,OtherSocketInstance:TRNLVirtualNetworkSocketInstance;
    Data:TRNLVirtualNetworkSocketData;
begin
 result:=-1;
 fLock.Acquire;
 try
  SocketInstance:=FindSocketInstance(aSocket,false);
  if assigned(SocketInstance) and assigned(aAddress) and (aDataLength>0) then begin
   result:=0;
   OtherSocketInstance:=FindAddressSocketInstance(aAddress^);
   if assigned(OtherSocketInstance) then begin
    Data.Address:=SocketInstance.fAddress;
    SetLength(Data.Data,aDataLength);
    Move(aData,Data.Data[0],aDataLength);
    OtherSocketInstance.fData.Enqueue(Data);
    result:=aDataLength;
   end;
  end;
 finally
  fLock.Release;
 end;
 fNewDataEvent.SetEvent;
end;

function TRNLVirtualNetwork.Receive(const aSocket:TRNLSocket;const aAddress:PRNLAddress;var aData;const aDataLength:TRNLSizeInt;const aFamily:TRNLAddressFamily):TRNLSizeInt;
var SocketInstance:TRNLVirtualNetworkSocketInstance;
    Data:TRNLVirtualNetworkSocketData;
begin
 result:=0;
 fLock.Acquire;
 try
  SocketInstance:=FindSocketInstance(aSocket,false);
  if assigned(SocketInstance) and assigned(aAddress) and (aDataLength>0) then begin
   if SocketInstance.fData.Dequeue(Data) then begin
    if length(Data.Data)<=aDataLength then begin
     aAddress^:=Data.Address;
     try
      Move(Data.Data[0],aData,length(Data.Data));
      result:=length(Data.Data);
     finally
      Data.Data:=nil;
     end;
    end else begin
     result:=-1;
    end;
   end;
  end;
 finally
  fLock.Release;
 end;
end;

constructor TRNLNetworkInterferenceSimulator.TRNLNetworkInterferenceSimulatorPacket.Create(const aNetworkInterferenceSimulator:TRNLNetworkInterferenceSimulator);
begin

 inherited Create;

 fValue:=self;

 fNetworkInterferenceSimulator:=aNetworkInterferenceSimulator;

 fTime:=0;

 fSocket:=0;

 fData:=nil;

end;

destructor TRNLNetworkInterferenceSimulator.TRNLNetworkInterferenceSimulatorPacket.Destroy;
begin

 fData:=nil;

 inherited Destroy;

end;

constructor TRNLNetworkInterferenceSimulator.Create(const aInstance:TRNLInstance;const aNetwork:TRNLNetwork);
begin

 inherited Create(aInstance);

 fNetwork:=aNetwork;

 fLock:=TCriticalSection.Create;

 fRandomGenerator:=TRNLRandomGenerator.Create;

 fNextTimeout.fValue:=TRNLUInt64(High(TRNLUInt64));

 fIncomingPacketList:=TRNLNetworkInterferenceSimulatorPacketListNode.Create;

 fOutgoingPacketList:=TRNLNetworkInterferenceSimulatorPacketListNode.Create;

 fSimulatedIncomingPacketLossProbabilityFactor:=0;

 fSimulatedOutgoingPacketLossProbabilityFactor:=0;

 fSimulatedIncomingDuplicatePacketProbabilityFactor:=0;

 fSimulatedOutgoingDuplicatePacketProbabilityFactor:=0;

 fSimulatedIncomingLatency:=0;

 fSimulatedOutgoingLatency:=0;

 fSimulatedIncomingJitter:=0;

 fSimulatedOutgoingJitter:=0;

end;

destructor TRNLNetworkInterferenceSimulator.Destroy;
begin

 while not fIncomingPacketList.Empty do begin
  fIncomingPacketList.Front.Value.Free;
 end;

 FreeAndNil(fIncomingPacketList);

 while not fOutgoingPacketList.Empty do begin
  fOutgoingPacketList.Front.Value.Free;
 end;

 FreeAndNil(fOutgoingPacketList);

 FreeAndNil(fRandomGenerator);

 FreeAndNil(fLock);

 inherited Destroy;

end;

function TRNLNetworkInterferenceSimulator.SimulateIncomingPacketLoss:boolean;
begin
 case fSimulatedIncomingPacketLossProbabilityFactor of
  0:begin
   result:=false;
  end;
  TRNLUInt32($ffffffff):begin
   result:=true;
  end;
  else begin
   fLock.Acquire;
   try
    result:=(fRandomGenerator.GetUInt32<fSimulatedIncomingPacketLossProbabilityFactor);
   finally
    fLock.Release;
   end;
  end;
 end;
end;

function TRNLNetworkInterferenceSimulator.SimulateOutgoingPacketLoss:boolean;
begin
 case fSimulatedOutgoingPacketLossProbabilityFactor of
  0:begin
   result:=false;
  end;
  TRNLUInt32($ffffffff):begin
   result:=true;
  end;
  else begin
   fLock.Acquire;
   try
    result:=(fRandomGenerator.GetUInt32<fSimulatedOutgoingPacketLossProbabilityFactor);
   finally
    fLock.Release;
   end;
  end;
 end;
end;

function TRNLNetworkInterferenceSimulator.SimulateIncomingDuplicatePacket:boolean;
begin
 case fSimulatedIncomingDuplicatePacketProbabilityFactor of
  0:begin
   result:=false;
  end;
  TRNLUInt32($ffffffff):begin
   result:=true;
  end;
  else begin
   fLock.Acquire;
   try
    result:=(fRandomGenerator.GetUInt32<fSimulatedIncomingDuplicatePacketProbabilityFactor);
   finally
    fLock.Release;
   end;
  end;
 end;
end;

function TRNLNetworkInterferenceSimulator.SimulateOutgoingDuplicatePacket:boolean;
begin
 case fSimulatedOutgoingDuplicatePacketProbabilityFactor of
  0:begin
   result:=false;
  end;
  TRNLUInt32($ffffffff):begin
   result:=true;
  end;
  else begin
   fLock.Acquire;
   try
    result:=(fRandomGenerator.GetUInt32<fSimulatedOutgoingDuplicatePacketProbabilityFactor);
   finally
    fLock.Release;
   end;
  end;
 end;
end;

procedure TRNLNetworkInterferenceSimulator.Update;
var PacketListNode,NextPacketListNode:TRNLNetworkInterferenceSimulatorPacketListNode;
    Packet:TRNLNetworkInterferenceSimulatorPacket;
    Time:TRNLTime;
begin

 fLock.Acquire;
 try

  Time:=fInstance.Time;

  fNextTimeout.fValue:=TRNLUInt64(High(TRNLUInt64));

  PacketListNode:=fIncomingPacketList.Front;
  while PacketListNode<>fIncomingPacketList do begin
   NextPacketListNode:=PacketListNode.Next;
   Packet:=PacketListNode.fValue;
   if Packet.fTime.fValue<fNextTimeout.fValue then begin
    fNextTimeout.fValue:=Packet.fTime.fValue;
   end;
   PacketListNode:=NextPacketListNode;
  end;

  PacketListNode:=fOutgoingPacketList.Front;
  while PacketListNode<>fOutgoingPacketList do begin
   NextPacketListNode:=PacketListNode.Next;
   Packet:=PacketListNode.fValue;
   if Packet.fTime.fValue<=Time.fValue then begin
    try
     if length(Packet.fData)>=0 then begin
      fNetwork.Send(Packet.fSocket,@Packet.fAddress,Packet.fData[0],length(Packet.fData),Packet.fFamily);
     end;
     Packet.Remove;
    finally
     Packet.Free;
    end;
   end else if Packet.fTime.fValue<fNextTimeout.fValue then begin
    fNextTimeout.fValue:=Packet.fTime.fValue;
   end;
   PacketListNode:=NextPacketListNode;
  end;

 finally
  fLock.Release;
 end;

end;

function TRNLNetworkInterferenceSimulator.AddressSetHost(var aAddress:TRNLAddress;const aName:TRNLRawByteString):boolean;
begin
 Update;
 result:=fNetwork.AddressSetHost(aAddress,aName);
end;

function TRNLNetworkInterferenceSimulator.AddressGetHost(const aAddress:TRNLAddress;out aName;const aNameLength:TRNLInt32;const aFlags:TRNLInt32=0):boolean;
begin
 Update;
 result:=fNetwork.AddressGetHost(aAddress,aName,aNameLength,aFlags);
end;

function TRNLNetworkInterferenceSimulator.AddressGetHostIP(const aAddress:TRNLAddress;out aName;const aNameLength:TRNLInt32):boolean;
begin
 Update;
 result:=fNetwork.AddressGetHostIP(aAddress,aName,aNameLength);
end;

function TRNLNetworkInterferenceSimulator.SocketCreate(const aType:TRNLSocketType;const aFamily:TRNLAddressFamily):TRNLSocket;
begin
 Update;
 result:=fNetwork.SocketCreate(aType,aFamily);
end;

procedure TRNLNetworkInterferenceSimulator.SocketDestroy(const aSocket:TRNLSocket);
begin
 Update;
 fNetwork.SocketDestroy(aSocket);
end;

function TRNLNetworkInterferenceSimulator.SocketShutdown(const aSocket:TRNLSocket;const aHow:TRNLSocketShutdown=RNL_SOCKET_SHUTDOWN_READ):boolean;
begin
 Update;
 result:=fNetwork.SocketShutdown(aSocket,aHow);
end;

function TRNLNetworkInterferenceSimulator.SocketGetAddress(const aSocket:TRNLSocket;out aAddress:TRNLAddress;const aFamily:TRNLAddressFamily):boolean;
begin
 Update;
 result:=fNetwork.SocketGetAddress(aSocket,aAddress,aFamily);
end;

function TRNLNetworkInterferenceSimulator.SocketSetOption(const aSocket:TRNLSocket;const aOption:TRNLSocketOption;const aValue:TRNLInt32):boolean;
begin
 Update;
 result:=fNetwork.SocketSetOption(aSocket,aOption,aValue);
end;

function TRNLNetworkInterferenceSimulator.SocketGetOption(const aSocket:TRNLSocket;const aOption:TRNLSocketOption;out aValue:TRNLInt32):boolean;
begin
 Update;
 result:=fNetwork.SocketGetOption(aSocket,aOption,aValue);
end;

function TRNLNetworkInterferenceSimulator.SocketBind(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aFamily:TRNLAddressFamily):boolean;
begin
 Update;
 result:=fNetwork.SocketBind(aSocket,aAddress,aFamily);
end;

function TRNLNetworkInterferenceSimulator.SocketListen(const aSocket:TRNLSocket;const aBackLog:TRNLInt32):boolean;
begin
 Update;
 result:=fNetwork.SocketListen(aSocket,aBackLog);
end;

function TRNLNetworkInterferenceSimulator.SocketConnect(const aSocket:TRNLSocket;const aAddress:TRNLAddress;const aFamily:TRNLAddressFamily):boolean;
begin
 Update;
 result:=fNetwork.SocketConnect(aSocket,aAddress,aFamily);
end;

function TRNLNetworkInterferenceSimulator.SocketAccept(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aFamily:TRNLAddressFamily):TRNLSocket;
begin
 Update;
 result:=fNetwork.SocketAccept(aSocket,aAddress,aFamily);
end;

function TRNLNetworkInterferenceSimulator.SocketSelect(const aMaxSocket:TRNLSocket;var aReadSet,aWriteSet:TRNLSocketSet;const aTimeout:TRNLTime):TRNLInt32;
var Time:TRNLTime;
    Timeout:TRNLInt64;
begin
 Update;
 fLock.Acquire;
 try
  if fNextTimeout.fValue<>TRNLUInt64(High(TRNLUInt64)) then begin
   Time:=fInstance.Time;
   Timeout:=Max(1,TRNLTime.RelativeDifference(TRNLTime.Minimum(Time+aTimeout,fNextTimeout),Time));
   fLock.Release;
   try
    result:=fNetwork.SocketSelect(aMaxSocket,aReadSet,aWriteSet,TRNLTime(TRNLUInt64(Timeout)));
   finally
    fLock.Acquire;
   end;
  end else begin
   fLock.Release;
   try
    result:=fNetwork.SocketSelect(aMaxSocket,aReadSet,aWriteSet,aTimeout);
   finally
    fLock.Acquire;
   end;
  end;
 finally
  fLock.Release;
 end;
end;

function TRNLNetworkInterferenceSimulator.SocketWait(const aSockets:array of TRNLSocket;var aConditions:TRNLSocketWaitConditions;const aTimeout:TRNLTime):boolean;
var Time:TRNLTime;
    Timeout:TRNLInt64;
begin
 Update;
 fLock.Acquire;
 try
  if fNextTimeout.fValue<>TRNLUInt64(High(TRNLUInt64)) then begin
   Time:=fInstance.Time;
   Timeout:=Max(1,TRNLTime.RelativeDifference(TRNLTime.Minimum(Time+aTimeout,fNextTimeout),Time));
   fLock.Release;
   try
    result:=fNetwork.SocketWait(aSockets,aConditions,TRNLTime(TRNLUInt64(Timeout)));
   finally
    fLock.Acquire;
   end;
  end else begin
   fLock.Release;
   try
    result:=fNetwork.SocketWait(aSockets,aConditions,aTimeout);
   finally
    fLock.Acquire;
   end;
  end;
 finally
  fLock.Release;
 end;
end;

function TRNLNetworkInterferenceSimulator.SendBuffers(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aBuffers;const aCountBuffers:TRNLUInt32;const aFamily:TRNLAddressFamily):TRNLSizeInt;
var Index:TRNLSizeInt;
    DataLength:TRNLSizeUInt;
    Data:TBytes;
begin
 result:=-1;
 if aCountBuffers=0 then begin
  Update;
  result:=0;
 end else if aCountBuffers=1 then begin
  result:=Send(aSocket,aAddress,TRNLBuffer(aBuffers).Data^,TRNLBuffer(aBuffers).DataLength,aFamily);
 end else if aCountBuffers>1 then begin
  Data:=nil;
  try
   DataLength:=0;
   for Index:=0 to aCountBuffers-1 do begin
    inc(DataLength,PRNLBufferArray(TRNLPointer(@aBuffers))^[Index].DataLength);
   end;
   SetLength(Data,DataLength);
   DataLength:=0;
   for Index:=0 to aCountBuffers-1 do begin
    System.Move(PRNLBufferArray(TRNLPointer(@aBuffers))^[Index].Data^,
                Data[DataLength],
                PRNLBufferArray(TRNLPointer(@aBuffers))^[Index].DataLength);
    inc(DataLength,PRNLBufferArray(TRNLPointer(@aBuffers))^[Index].DataLength);
   end;
   result:=Send(aSocket,aAddress,Data[0],DataLength,aFamily);
  finally
   Data:=nil;
  end;
 end else begin
  Update;
 end;
end;

function TRNLNetworkInterferenceSimulator.ReceiveBuffers(const aSocket:TRNLSocket;const aAddress:PRNLAddress;var aBuffers;const aCountBuffers:TRNLUInt32;const aFamily:TRNLAddressFamily):TRNLSizeInt;
begin
 if aCountBuffers>0 then begin
  result:=Receive(aSocket,aAddress,TRNLBuffer(aBuffers).Data^,TRNLBuffer(aBuffers).DataLength,aFamily);
  if result>=0 then begin
   TRNLBuffer(aBuffers).DataLength:=result;
   result:=0;
  end;
 end else begin
  Update;
  result:=-1;
 end;
end;

function TRNLNetworkInterferenceSimulator.Send(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aData;const aDataLength:TRNLSizeInt;const aFamily:TRNLAddressFamily):TRNLSizeInt;
var Time:TRNLTime;
    Delay:TRNLInt64;
    Packet:TRNLNetworkInterferenceSimulatorPacket;
begin
 Update;
 if SimulateOutgoingPacketLoss then begin
  result:=aDataLength;
 end else begin
  if (aDataLength=0) or
     (not assigned(aAddress)) or
     ((fSimulatedOutgoingLatency=0) and
      (fSimulatedOutgoingJitter=0) and
      (fSimulatedOutgoingDuplicatePacketProbabilityFactor=0)) then begin
   result:=fNetwork.Send(aSocket,aAddress,aData,aDataLength,aFamily);
  end else begin
   fLock.Acquire;
   try
    Time:=fInstance.Time;
    Delay:=(fSimulatedOutgoingLatency+(fRandomGenerator.GetUniformBoundedUInt32(fSimulatedOutgoingJitter*2)))-fSimulatedOutgoingJitter;
    if Delay>0 then begin
     Packet:=TRNLNetworkInterferenceSimulatorPacket.Create(self);
     try
      Packet.fTime.fValue:=Time.fValue+TRNLUInt64(Delay);
      Packet.fSocket:=aSocket;
      Packet.fAddress:=aAddress^;
      SetLength(Packet.fData,aDataLength);
      Move(aData,Packet.fData[0],aDataLength);
      Packet.fFamily:=aFamily;
     finally
      fOutgoingPacketList.Add(Packet);
     end;
     result:=aDataLength;
    end else begin
     Delay:=0;
     result:=fNetwork.Send(aSocket,aAddress,aData,aDataLength,aFamily);
    end;
    if (result=aDataLength) and SimulateOutgoingDuplicatePacket then begin
     inc(Delay,fRandomGenerator.GetUniformBoundedUInt32(999)+1);
     Packet:=TRNLNetworkInterferenceSimulatorPacket.Create(self);
     try
      Packet.fTime.fValue:=Time.fValue+TRNLUInt64(Delay);
      Packet.fSocket:=aSocket;
      Packet.fAddress:=aAddress^;
      SetLength(Packet.fData,aDataLength);
      Move(aData,Packet.fData[0],aDataLength);
      Packet.fFamily:=aFamily;
     finally
      fOutgoingPacketList.Add(Packet);
     end;
    end;
   finally
    fLock.Release;
   end;
  end;
 end;
end;

function TRNLNetworkInterferenceSimulator.Receive(const aSocket:TRNLSocket;const aAddress:PRNLAddress;var aData;const aDataLength:TRNLSizeInt;const aFamily:TRNLAddressFamily):TRNLSizeInt;
var PacketListNode,NextPacketListNode:TRNLNetworkInterferenceSimulatorPacketListNode;
    Packet:TRNLNetworkInterferenceSimulatorPacket;
    Time:TRNLTime;
    Delay:TRNLInt64;
    HasPacket,DelayPacket:boolean;
begin

 Update;

 result:=0;

 repeat

  if (fSimulatedIncomingLatency<>0) or
     (fSimulatedIncomingJitter<>0) or
     (fSimulatedIncomingDuplicatePacketProbabilityFactor<>0) then begin

   HasPacket:=false;

   fLock.Acquire;
   try

    if not fIncomingPacketList.Empty then begin

     Time:=fInstance.Time;

     PacketListNode:=fIncomingPacketList.Front;
     while PacketListNode<>fIncomingPacketList do begin
      NextPacketListNode:=PacketListNode.Next;
      Packet:=PacketListNode.fValue;
      if (Packet.fSocket=aSocket) and
         (Packet.fTime.fValue<=Time.fValue) then begin
       try
        result:=length(Packet.fData);
        if result<=aDataLength then begin
         if result>0 then begin
          Move(Packet.fData[0],aData,result);
         end;
         if assigned(aAddress) then begin
          aAddress^:=Packet.fAddress;
         end;
        end else begin
         result:=-1;
        end;
        HasPacket:=true;
        break;
       finally
        Packet.Free;
       end;
      end;
      PacketListNode:=NextPacketListNode;
     end;

    end;

   finally
    fLock.Release;
   end;

   if HasPacket then begin
    break;
   end;

  end;

  result:=fNetwork.Receive(aSocket,aAddress,aData,aDataLength,aFamily);

  if (result>0) and SimulateIncomingPacketLoss then begin
   continue;
  end;

  if (result>0) and
     assigned(aAddress) and
     ((fSimulatedIncomingLatency<>0) or
      (fSimulatedIncomingJitter<>0) or
      (fSimulatedIncomingDuplicatePacketProbabilityFactor<>0)) then begin

   fLock.Acquire;
   try
    Time:=fInstance.Time;
    Delay:=(fSimulatedIncomingLatency+(fRandomGenerator.GetUniformBoundedUInt32(fSimulatedIncomingJitter*2)))-fSimulatedIncomingJitter;
    DelayPacket:=Delay>0;
    if DelayPacket then begin
     Packet:=TRNLNetworkInterferenceSimulatorPacket.Create(self);
     try
      Packet.fTime.fValue:=Time.fValue+TRNLUInt64(Delay);
      Packet.fSocket:=aSocket;
      Packet.fAddress:=aAddress^;
      SetLength(Packet.fData,result);
      Move(aData,Packet.fData[0],result);
      Packet.fFamily:=aFamily;
     finally
      fIncomingPacketList.Add(Packet);
     end;
    end else begin
     Delay:=0;
    end;
    if SimulateIncomingDuplicatePacket then begin
     inc(Delay,fRandomGenerator.GetUniformBoundedUInt32(999)+1);
     Packet:=TRNLNetworkInterferenceSimulatorPacket.Create(self);
     try
      Packet.fTime.fValue:=Time.fValue+TRNLUInt64(Delay);
      Packet.fSocket:=aSocket;
      Packet.fAddress:=aAddress^;
      SetLength(Packet.fData,result);
      Move(aData,Packet.fData[0],result);
      Packet.fFamily:=aFamily;
     finally
      fIncomingPacketList.Add(Packet);
     end;
    end;
   finally
    fLock.Release;
   end;

   if DelayPacket then begin
    result:=0;
    continue;
   end;

  end;

  break;

 until false;
end;

constructor TRNLCompressor.Create;
begin
 inherited Create;
end;

destructor TRNLCompressor.Destroy;
begin
 inherited Destroy;
end;

function TRNLCompressor.Compress(const aInData:TRNLPointer;const aInSize:TRNLSizeUInt;const aOutData:TRNLPointer;const aOutLimit:TRNLSizeUInt):TRNLSizeUInt;
begin
 result:=0;
end;

function TRNLCompressor.Decompress(const aInData:TRNLPointer;const aInSize:TRNLSizeUInt;const aOutData:TRNLPointer;const aOutLimit:TRNLSizeUInt):TRNLSizeUInt;
begin
 result:=0;
end;

constructor TRNLCompressorDeflate.Create;
 procedure BuildFixedTrees(var aLT,aDT:TTree);
 var i:TRNLInt32;
 begin
  for i:=0 to 6 do begin
   aLT.Table[i]:=0;
  end;
  aLT.Table[7]:=24;
  aLT.Table[8]:=152;
  aLT.Table[9]:=112;
  for i:=0 to 23 do begin
   aLT.Translation[i]:=256+i;
  end;
  for i:=0 to 143 do begin
   aLT.Translation[24+i]:=i;
  end;
  for i:=0 to 7 do begin
   aLT.Translation[168+i]:=280+i;
  end;
  for i:=0 to 111 do begin
   aLT.Translation[176+i]:=144+i;
  end;
  for i:=0 to 4 do begin
   aDT.Table[i]:=0;
  end;
  aDT.Table[5]:=32;
  for i:=0 to 31 do begin
   aDT.Translation[i]:=i;
  end;
 end;
 procedure BuildBitsBase(aBits:PRNLUInt8Array;aBase:PRNLUInt16;aDelta,aFirst:TRNLInt32);
 var i,Sum:TRNLInt32;
 begin
  for i:=0 to aDelta-1 do begin
   aBits^[i]:=0;
  end;
  for i:=0 to (30-aDelta)-1 do begin
   aBits^[i+aDelta]:=i div aDelta;
  end;
  Sum:=aFirst;
  for i:=0 to 29 do begin
   aBase^:=Sum;
   inc(aBase);
   inc(Sum,1 shl aBits^[i]);
  end;
 end;
var Index,ValueIndex:TRNLInt32;
begin
 inherited Create;
 for Index:=0 to length(LengthCodes)-1 do begin
  for ValueIndex:=IfThen(Index=0,0,LengthCodes[Index,2]) to LengthCodes[Index,3] do begin
   fLengthCodesLookUpTable[ValueIndex]:=Index;
  end;
 end;
 for Index:=0 to length(DistanceCodes)-1 do begin
  for ValueIndex:=IfThen(Index=0,0,DistanceCodes[Index,2]) to DistanceCodes[Index,3] do begin
   fDistanceCodesLookUpTable[ValueIndex]:=Index;
  end;
 end;
 FillChar(fLengthBits,sizeof(TBits),#0);
 FillChar(fDistanceBits,sizeof(TBits),#0);
 FillChar(fLengthBase,sizeof(TBase),#0);
 FillChar(fDistanceBase,sizeof(TBase),#0);
 FillChar(fFixedSymbolLengthTree,sizeof(TTree),#0);
 FillChar(FfixedDistanceTree,sizeof(TTree),#0);
 BuildFixedTrees(fFixedSymbolLengthTree,fFixedDistanceTree);
 BuildBitsBase(TRNLPointer(@fLengthBits[0]),PRNLUInt16(TRNLPointer(@fLengthBase[0])),4,3);
 BuildBitsBase(TRNLPointer(@fDistanceBits[0]),PRNLUInt16(TRNLPointer(@fDistanceBase[0])),2,1);
 fLengthBits[28]:=0;
 fLengthBase[28]:=258;
 fWithHeader:=false;
 fGreedy:=true;
 fSkipStrength:=32;
 fMaxSteps:=128;
end;

destructor TRNLCompressorDeflate.Destroy;
begin
 inherited Destroy;
end;

function TRNLCompressorDeflate.Compress(const aInData:TRNLPointer;const aInSize:TRNLSizeUInt;const aOutData:TRNLPointer;const aOutLimit:TRNLSizeUInt):TRNLSizeUInt;
var OutputBits,CountOutputBits:TRNLUInt32;
    DestLen:TRNLSizeUInt;
    OK:boolean;
 procedure DoOutputBits(const aBits,aCountBits:TRNLUInt32);
 begin
  Assert((CountOutputBits+aCountBits)<=32);
  OutputBits:=OutputBits or (aBits shl CountOutputBits);
  inc(CountOutputBits,aCountBits);
  while CountOutputBits>=8 do begin
   if DestLen<aOutLimit then begin
    PRNLUInt8Array(aOutData)^[DestLen]:=OutputBits and $ff;
    inc(DestLen);
   end else begin
    OK:=false;
   end;
   OutputBits:=OutputBits shr 8;
   dec(CountOutputBits,8);
  end;
 end;
 procedure DoOutputLiteral(const aValue:TRNLUInt8);
 begin
  case aValue of
   0..143:begin
    DoOutputBits(MirrorBytes[$30+aValue],8);
   end;
   else begin
    DoOutputBits((MirrorBytes[$90+(aValue-144)] shl 1) or 1,9);
   end;
  end;
 end;
 procedure DoOutputCopy(const aDistance,aLength:TRNLUInt32);
 var Remain,ToDo,Index:TRNLUInt32;
 begin
  Remain:=aLength;
  while Remain>0 do begin
   case Remain of
    0..258:begin
     ToDo:=Remain;
    end;
    259..260:begin
     ToDo:=Remain-3;
    end;
    else begin
     ToDo:=258;
    end;
   end;
   dec(Remain,ToDo);
   Index:=fLengthCodesLookUpTable[Min(Max(ToDo,0),258)];
   if LengthCodes[Index,0]<=279 then begin
    DoOutputBits(MirrorBytes[(LengthCodes[Index,0]-256) shl 1],7);
   end else begin
    DoOutputBits(MirrorBytes[$c0+(LengthCodes[Index,0]-280)],8);
   end;
   if LengthCodes[Index,1]<>0 then begin
    DoOutputBits(ToDo-LengthCodes[Index,2],LengthCodes[Index,1]);
   end;
   Index:=fDistanceCodesLookUpTable[Min(Max(aDistance,0),32768)];
   DoOutputBits(MirrorBytes[DistanceCodes[Index,0] shl 3],5);
   if DistanceCodes[Index,1]<>0 then begin
    DoOutputBits(aDistance-DistanceCodes[Index,2],DistanceCodes[Index,1]);
   end;
  end;
 end;
 procedure OutputStartBlock;
 begin
  DoOutputBits(1,1); // Final block
  DoOutputBits(1,2); // Static huffman block
 end;
 procedure OutputEndBlock;
 begin
  DoOutputBits(0,7); // Close block
  DoOutputBits(0,7); // Make sure all bits are flushed
 end;
 function Adler32(const aData:TRNLPointer;const aLength:TRNLUInt32):TRNLUInt32;
 const Base=65521;
       MaximumCountAtOnce=5552;
 var Buf:PRNLUInt8;
     Remain,s1,s2,ToDo,Index:TRNLUInt32;
 begin
  s1:=1;
  s2:=0;
  Buf:=aData;
  Remain:=aLength;
  while Remain>0 do begin
   if Remain<MaximumCountAtOnce then begin
    ToDo:=Remain;
   end else begin
    ToDo:=MaximumCountAtOnce;
   end;
   dec(Remain,ToDo);
   for Index:=1 to ToDo do begin
    inc(s1,TRNLUInt8(Buf^));
    inc(s2,s1);
    inc(Buf);
   end;
   s1:=s1 mod Base;
   s2:=s2 mod Base;
  end;
  result:=(s2 shl 16) or s1;
 end;
var CurrentPointer,EndPointer,EndSearchPointer,Head,CurrentPossibleMatch:PRNLUInt8;
    BestMatchDistance,BestMatchLength,MatchLength,CheckSum,Step,Difference,Offset,
    UnsuccessfulFindMatchAttempts:TRNLUInt32;
    HashTableItem:PPRNLUInt8;
begin
 OK:=true;
 DestLen:=0;
 OutputBits:=0;
 CountOutputBits:=0;
 if fWithHeader then begin
  DoOutputBits($78,8); // CMF
  DoOutputBits($9c,8); // FLG Default Compression
 end;
 OutputStartBlock;
 FillChar(fHashTable,SizeOf(THashTable),#0);
 FillChar(fChainTable,SizeOf(TChainTable),#0);
 CurrentPointer:=aInData;
 EndPointer:={%H-}TRNLPointer(TRNLPtrUInt(TRNLPtrUInt(CurrentPointer)+TRNLPtrUInt(aInSize)));
 EndSearchPointer:={%H-}TRNLPointer(TRNLPtrUInt((TRNLPtrUInt(CurrentPointer)+TRNLPtrUInt(aInSize))-TRNLPtrUInt(TRNLInt64(Max(TRNLInt64(MinMatch),TRNLInt64(SizeOf(TRNLUInt32)))))));
 UnsuccessfulFindMatchAttempts:=TRNLUInt32(1) shl fSkipStrength;
 while {%H-}TRNLPtrUInt(CurrentPointer)<{%H-}TRNLPtrUInt(EndSearchPointer) do begin
  HashTableItem:=@fHashTable[((((PRNLUInt32(TRNLPointer(CurrentPointer))^ and TRNLUInt32({$if defined(FPC_BIG_ENDIAN)}$ffffff00{$else}$00ffffff{$ifend}){$if defined(FPC_BIG_ENDIAN)}shr 8{$ifend}))*TRNLUInt32($1e35a7bd)) shr HashShift) and HashMask];
  Head:=HashTableItem^;
  CurrentPossibleMatch:=Head;
  BestMatchDistance:=0;
  BestMatchLength:=1;
  Step:=0;
  while assigned(CurrentPossibleMatch) and
        ({%H-}TRNLPtrUInt(CurrentPointer)>{%H-}TRNLPtrUInt(CurrentPossibleMatch)) and
        (TRNLPtrInt({%H-}TRNLPtrUInt({%H-}TRNLPtrUInt(CurrentPointer)-{%H-}TRNLPtrUInt(CurrentPossibleMatch)))<TRNLPtrInt(MaxOffset)) do begin
   Difference:=PRNLUInt32(TRNLPointer(@PRNLUInt8Array(CurrentPointer)^[0]))^ xor PRNLUInt32(TRNLPointer(@PRNLUInt8Array(CurrentPossibleMatch)^[0]))^;
   if (Difference and TRNLUInt32({$if defined(FPC_BIG_ENDIAN)}$ffffff00{$else}$00ffffff{$ifend}))=0 then begin
    if (BestMatchLength<=({%H-}TRNLPtrUInt(EndPointer)-{%H-}TRNLPtrUInt(CurrentPointer))) and
       (PRNLUInt8Array(CurrentPointer)^[BestMatchLength-1]=PRNLUInt8Array(CurrentPossibleMatch)^[BestMatchLength-1]) then begin
     MatchLength:=MinMatch;
     while (({%H-}TRNLPtrUInt(@PRNLUInt8Array(CurrentPointer)^[MatchLength]) and (SizeOf(TRNLUInt32)-1))<>0) and
           (({%H-}TRNLPtrUInt(@PRNLUInt8Array(CurrentPointer)^[MatchLength])<{%H-}TRNLPtrUInt(EndPointer))) and
           (PRNLUInt8Array(CurrentPointer)^[MatchLength]=PRNLUInt8Array(CurrentPossibleMatch)^[MatchLength]) do begin
      inc(MatchLength);
     end;
     while ({%H-}TRNLPtrUInt(@PRNLUInt8Array(CurrentPointer)^[MatchLength+(SizeOf(TRNLUInt32)-1)])<{%H-}TRNLPtrUInt(EndPointer)) do begin
      Difference:=PRNLUInt32(TRNLPointer(@PRNLUInt8Array(CurrentPointer)^[MatchLength]))^ xor PRNLUInt32(TRNLPointer(@PRNLUInt8Array(CurrentPossibleMatch)^[MatchLength]))^;
      if Difference=0 then begin
       inc(MatchLength,SizeOf(TRNLUInt32));
      end else begin
{$if defined(FPC_BIG_ENDIAN)}
       if (Difference shr 16)<>0 then begin
        inc(MatchLength,not (Difference shr 24));
       end else begin
        inc(MatchLength,2+(not (Difference shr 8)));
       end;
{$else}
       inc(MatchLength,MultiplyDeBruijnBytePosition[TRNLUInt32(TRNLUInt32(Difference and (-Difference))*TRNLUInt32($077cb531)) shr 27]);
{$ifend}
       break;
      end;
     end;
     if BestMatchLength<MatchLength then begin
      BestMatchDistance:={%H-}TRNLPtrUInt({%H-}TRNLPtrUInt(CurrentPointer)-{%H-}TRNLPtrUInt(CurrentPossibleMatch));
      BestMatchLength:=MatchLength;
     end;
    end;
   end;
   inc(Step);
   if Step<fMaxSteps then begin
    CurrentPossibleMatch:=fChainTable[({%H-}TRNLPtrUInt(CurrentPossibleMatch)-{%H-}TRNLPtrUInt(aInData)) and WindowMask];
   end else begin
    break;
   end;
  end;
  if (BestMatchDistance>0) and (BestMatchLength>1) then begin
   DoOutputCopy(BestMatchDistance,BestMatchLength);
   UnsuccessfulFindMatchAttempts:=TRNLUInt32(1) shl fSkipStrength;
  end else begin
   if fSkipStrength>31 then begin
    DoOutputLiteral(CurrentPointer^);
   end else begin
    Step:=UnsuccessfulFindMatchAttempts shr fSkipStrength;
    Offset:=0;
    while (Offset<Step) and (({%H-}TRNLPtrUInt(CurrentPointer)+Offset)<{%H-}TRNLPtrUInt(EndSearchPointer)) do begin
     DoOutputLiteral(PRNLUInt8Array(CurrentPointer)^[Offset]);
     inc(Offset);
    end;
    BestMatchLength:=Offset;
    inc(UnsuccessfulFindMatchAttempts,ord(UnsuccessfulFindMatchAttempts<TRNLUInt32($ffffffff)) and 1);
   end;
  end;
  if not OK then begin
   break;
  end;
  HashTableItem^:=CurrentPointer;
  fChainTable[({%H-}TRNLPtrUInt(CurrentPointer)-{%H-}TRNLPtrUInt(aInData)) and WindowMask]:=Head;
  if fGreedy then begin
   inc(CurrentPointer);
   dec(BestMatchLength);
   while (BestMatchLength>0) and ({%H-}TRNLPtrUInt(CurrentPointer)<{%H-}TRNLPtrUInt(EndSearchPointer)) do begin
    HashTableItem:=@fHashTable[((((PRNLUInt32(TRNLPointer(CurrentPointer))^ and TRNLUInt32({$if defined(FPC_BIG_ENDIAN)}$ffffff00{$else}$00ffffff{$ifend}){$if defined(FPC_BIG_ENDIAN)}shr 8{$ifend}))*TRNLUInt32($1e35a7bd)) shr HashShift) and HashMask];
    Head:=HashTableItem^;
    HashTableItem^:=CurrentPointer;
    fChainTable[({%H-}TRNLPtrUInt(CurrentPointer)-{%H-}TRNLPtrUInt(aInData)) and WindowMask]:=Head;
    inc(CurrentPointer);
    dec(BestMatchLength);
   end;
  end;
  inc(CurrentPointer,BestMatchLength);
 end;
 while {%H-}TRNLPtrUInt(CurrentPointer)<{%H-}TRNLPtrUInt(EndPointer) do begin
  DoOutputLiteral(CurrentPointer^);
  if not OK then begin
   break;
  end;
  inc(CurrentPointer);
 end;
 OutputEndBlock;
 if fWithHeader then begin
  CheckSum:=Adler32(aInData,aInSize);
  if (DestLen+4)<aOutLimit then begin
   PRNLUInt8Array(aOutData)^[DestLen+0]:=(CheckSum shr 24) and $ff;
   PRNLUInt8Array(aOutData)^[DestLen+1]:=(CheckSum shr 16) and $ff;
   PRNLUInt8Array(aOutData)^[DestLen+2]:=(CheckSum shr 8) and $ff;
   PRNLUInt8Array(aOutData)^[DestLen+3]:=(CheckSum shr 0) and $ff;
   inc(DestLen,4);
  end;
 end;
 if OK then begin
  result:=DestLen;
 end else begin
  result:=0;
 end;
end;

function TRNLCompressorDeflate.Decompress(const aInData:TRNLPointer;const aInSize:TRNLSizeUInt;const aOutData:TRNLPointer;const aOutLimit:TRNLSizeUInt):TRNLSizeUInt;
var Tag,BitCount:TRNLUInt32;
    Source,SourceEnd:PRNLUInt8;
    Dest:PRNLUInt8;
    DestLen:TRNLSizeUInt;
 function Adler32(aData:TRNLPointer;aLength:TRNLUInt32):TRNLUInt32;
 const BASE=65521;
       NMAX=5552;
 var buf:PRNLUInt8;
     s1,s2,k,i:TRNLUInt32;
 begin
  s1:=1;
  s2:=0;
  buf:=aData;
  while aLength>0 do begin
   if aLength<NMAX then begin
    k:=aLength;
   end else begin
    k:=NMAX;
   end;
   dec(aLength,k);
   for i:=1 to k do begin
    inc(s1,TRNLUInt8(buf^));
    inc(s2,s1);
    inc(buf);
   end;
   s1:=s1 mod Base;
   s2:=s2 mod Base;
  end;
  result:=(s2 shl 16) or s1;
 end;
 procedure BuildTree(var aTree:TTree;aLengths:PRNLUInt8Array;aNum:TRNLInt32);
 var Offsets:POffsets;
     i:TRNLInt32;
     Sum:TRNLUInt32;
 begin
  New(Offsets);
  try
   for i:=0 to 15 do begin
    aTree.Table[i]:=0;
   end;
   for i:=0 to aNum-1 do begin
    inc(aTree.Table[TRNLUInt8(aLengths^[i])]);
   end;
   aTree.Table[0]:=0;
   Sum:=0;
   for i:=0 to 15 do begin
    Offsets^[i]:=Sum;
    inc(Sum,aTree.Table[i]);
   end;
   for i:=0 to aNum-1 do begin
    if aLengths^[i]<>0 then begin
     aTree.Translation[Offsets^[TRNLUInt8(aLengths^[i])]]:=i;
     inc(Offsets^[TRNLUInt8(aLengths^[i])]);
    end;
   end;
  finally
   Dispose(Offsets);
  end;
 end;
 function GetBit:TRNLUInt32;
 begin
  if BitCount=0 then begin
   Tag:=TRNLUInt8(Source^);
   inc(Source);
   BitCount:=7;
  end else begin
   dec(BitCount);
  end;
  result:=Tag and 1;
  Tag:=Tag shr 1;
 end;
 function ReadBits(aNum,aBase:TRNLUInt32):TRNLUInt32;
 var Limit,Mask:TRNLUInt32;
 begin
  result:=0;
  if aNum<>0 then begin
   Limit:=1 shl aNum;
   Mask:=1;
   while Mask<Limit do begin
    if GetBit<>0 then begin
     inc(result,Mask);
    end;
    Mask:=Mask shl 1;
   end;
  end;
  inc(result,aBase);
 end;
 function DecodeSymbol(const aTree:TTree):TRNLUInt32;
 var Sum,c,l:TRNLInt32;
 begin
  Sum:=0;
  c:=0;
  l:=0;
  repeat
   c:=(c*2)+TRNLInt32(GetBit);
   inc(l);
   inc(Sum,aTree.Table[l]);
   dec(c,aTree.Table[l]);
  until not (c>=0);
  result:=aTree.Translation[Sum+c];
 end;
 procedure DecodeTrees(var aLT,aDT:TTree);
 var hlit,hdist,hclen,i,Num,Len,clen,Symbol,Prev:TRNLUInt32;
 begin
  FillChar(fCodeTree,sizeof(TTree),#0);
  FillChar(fLengths,sizeof(TLengths),#0);
  hlit:=ReadBits(5,257);
  hdist:=ReadBits(5,1);
  hclen:=ReadBits(4,4);
  for i:=0 to 18 do begin
   fLengths[i]:=0;
  end;
  for i:=1 to hclen do begin
   clen:=ReadBits(3,0);
   fLengths[CLCIndex[i-1]]:=clen;
  end;
  BuildTree(fCodeTree,TRNLPointer(@fLengths[0]),19);
  Num:=0;
  while Num<(hlit+hdist) do begin
   Symbol:=DecodeSymbol(fCodeTree);
   case Symbol of
    16:begin
     prev:=fLengths[Num-1];
     Len:=ReadBits(2,3);
     while Len>0 do begin
      fLengths[Num]:=prev;
      inc(Num);
      dec(Len);
     end;
    end;
    17:begin
     Len:=ReadBits(3,3);
     while Len>0 do begin
      fLengths[Num]:=0;
      inc(Num);
      dec(Len);
     end;
    end;
    18:begin
     Len:=ReadBits(7,11);
     while Len>0 do begin
      fLengths[Num]:=0;
      inc(Num);
      dec(Len);
     end;
    end;
    else begin
     fLengths[Num]:=Symbol;
     inc(Num);
    end;
   end;
  end;
  BuildTree(aLT,TRNLPointer(@fLengths[0]),hlit);
  BuildTree(aDT,TRNLPointer(@fLengths[hlit]),hdist);
 end;
 function InflateBlockData(const aLT,aDT:TTree):boolean;
 var Symbol:TRNLUInt32;
     Len,Distance,Offset:TRNLInt32;
     t:PRNLUInt8;
 begin
  result:=false;
  while ({%H-}TRNLPtrUInt(TRNLPointer(Source))<{%H-}TRNLPtrUInt(TRNLPointer(SourceEnd))) or (BitCount>0) do begin
   Symbol:=DecodeSymbol(aLT);
   if Symbol=256 then begin
    result:=true;
    break;
   end;
   if Symbol<256 then begin
    if (DestLen+1)<=aOutLimit then begin
     Dest^:=TRNLUInt8(Symbol);
     inc(Dest);
     inc(DestLen);
    end else begin
     exit;
    end;
   end else begin
    dec(Symbol,257);
    Len:=ReadBits(fLengthBits[Symbol],fLengthBase[Symbol]);
    Distance:=DecodeSymbol(aDT);
    Offset:=ReadBits(fDistanceBits[Distance],fDistanceBase[Distance]);
    if (DestLen+TRNLSizeUInt(Len))<=aOutLimit then begin
     t:=TRNLPointer(Dest);
     dec(t,Offset);
     RLELikeSideEffectAwareMemoryMove(t^,Dest^,Len);
     inc(Dest,Len);
     inc(DestLen,Len);
    end else begin
     exit;
    end;
   end;
  end;
 end;
 function InflateUncompressedBlock:boolean;
 var Len,InvLen:TRNLUInt32;
 begin
  result:=false;
  Len:=(TRNLUInt8(PRNLUInt8Array(Source)^[1]) shl 8) or TRNLUInt8(PRNLUInt8Array(Source)^[0]);
  InvLen:=(TRNLUInt8(PRNLUInt8Array(Source)^[3]) shl 8) or TRNLUInt8(PRNLUInt8Array(Source)^[2]);
  if Len<>((not InvLen) and $ffff) then begin
   exit;
  end;
  inc(Source,4);
  if Len>0 then begin
   if (DestLen+Len)<aOutLimit then begin
    Move(Source^,Dest^,Len);
    inc(Source,Len);
    inc(Dest,Len);
   end else begin
    exit;
   end;
  end;
  BitCount:=0;
  inc(DestLen,Len);
  result:=true;
 end;
 function InflateFixedBlock:boolean;
 begin
  result:=InflateBlockData(fFixedSymbolLengthTree,fFixedDistanceTree);
 end;
 function InflateDynamicBlock:boolean;
 begin
  FillChar(fSymbolLengthTree,sizeof(TTree),#0);
  FillChar(fDistanceTree,sizeof(TTree),#0);
  DecodeTrees(fSymbolLengthTree,fDistanceTree);
  result:=InflateBlockData(fSymbolLengthTree,fDistanceTree);
 end;
 function Uncompress:boolean;
 var FinalBlock:boolean;
     BlockType:TRNLUInt32;
 begin
  BitCount:=0;
  repeat
   FinalBlock:=GetBit<>0;
   BlockType:=ReadBits(2,0);
   case BlockType of
    0:begin
     result:=InflateUncompressedBlock;
    end;
    1:begin
     result:=InflateFixedBlock;
    end;
    2:begin
     result:=InflateDynamicBlock;
    end;
    else begin
     result:=false;
    end;
   end;
  until FinalBlock or not result;
 end;
 function UncompressZLIB:boolean;
 var cmf,flg:TRNLUInt8;
     a32:TRNLUInt32;
 begin
  result:=false;
  Source:=aInData;
  cmf:=TRNLUInt8(PRNLUInt8Array(Source)^[0]);
  flg:=TRNLUInt8(PRNLUInt8Array(Source)^[1]);
  if ((((cmf shl 8)+flg) mod 31)<>0) or ((cmf and $f)<>8) or ((cmf shr 4)>7) or ((flg and $20)<>0) then begin
   exit;
  end;
  a32:=(TRNLUInt8(PRNLUInt8Array(Source)^[aInSize-4]) shl 24) or
       (TRNLUInt8(PRNLUInt8Array(Source)^[aInSize-3]) shl 16) or
       (TRNLUInt8(PRNLUInt8Array(Source)^[aInSize-2]) shl 8) or
       (TRNLUInt8(PRNLUInt8Array(Source)^[aInSize-1]) shl 0);
  inc(Source,2);
  SourceEnd:=@PRNLUInt8Array(Source)^[aInSize-6];
  result:=Uncompress;
  if not result then begin
   exit;
  end;
  result:=Adler32(aOutData,DestLen)=a32;
 end;
 function UncompressDirect:boolean;
 begin
  Source:=aInData;
  SourceEnd:=@PRNLUInt8Array(Source)^[aInSize];
  result:=Uncompress;
 end;
begin
 Dest:=aOutData;
 DestLen:=0;
 result:=0;
 if fWithHeader then begin
  if UncompressZLIB then begin
   result:=DestLen;
  end;
 end else begin
  if UncompressDirect then begin
   result:=DestLen;
  end;
 end;
end;

constructor TRNLCompressorLZBRRC.Create;
begin
 inherited Create;
 fGreedy:=true;
 fSkipStrength:=32;
 fMaxSteps:=128;
end;

destructor TRNLCompressorLZBRRC.Destroy;
begin
 inherited Destroy;
end;

function TRNLCompressorLZBRRC.Compress(const aInData:TRNLPointer;const aInSize:TRNLSizeUInt;const aOutData:TRNLPointer;const aOutLimit:TRNLSizeUInt):TRNLSizeUInt;
var {$ifndef CPU64}Code,{$endif}Range,Cache,CountFFBytes:TRNLUInt32;
    {$ifdef CPU64}Code:TRNLUInt64;{$endif}
    Model:array[0..SizeModels-1] of TRNLUInt32;
    LastWasMatch,FirstByte{$ifndef CPU64},Carry{$endif},OK:boolean;
    DestLen,MinDestLen:TRNLUInt32;
 procedure EncoderShift;
{$ifdef CPU64}
 var Carry:boolean;
{$endif}
 begin
{$ifdef CPU64}
  Carry:=PRNLUInt64Record(TRNLPointer(@Code))^.Hi<>0; // or (Code shr 32)<>0; or also (Code and TRNLUInt64($ffffffff00000000))<>0;
{$endif}
  if (Code<$ff000000) or Carry then begin
   if FirstByte then begin
    FirstByte:=false;
   end else begin
    if TRNLSizeUInt(DestLen)<TRNLSizeUInt(aOutLimit) then begin
     PRNLUInt8Array(aOutData)^[DestLen]:=Cache+TRNLUInt8(ord(Carry) and 1);
     inc(DestLen);
    end else begin
     OK:=false;
     exit;
    end;
   end;
   while CountFFBytes<>0 do begin
    dec(CountFFBytes);
    if TRNLSizeUInt(DestLen)<TRNLSizeUInt(aOutLimit) then begin
     PRNLUInt8Array(aOutData)^[DestLen]:=$ff+TRNLUInt8(ord(Carry) and 1);
     inc(DestLen);
    end else begin
     OK:=false;
     exit;
    end;
   end;
   Cache:=(Code shr 24) and $ff;
  end else begin
   inc(CountFFBytes);
  end;
  Code:=(Code shl 8){$ifdef CPU64}and TRNLUInt32($ffffffff){$endif};
  Carry:=false;
 end;
 function EncodeBit(ModelIndex,Move,Bit:TRNLInt32):TRNLInt32;
 var Bound{$ifndef CPU64},OldCode{$endif}:TRNLUInt32;
 begin
  Bound:=(Range shr 12)*Model[ModelIndex];
  if Bit=0 then begin
   Range:=Bound;
   inc(Model[ModelIndex],(4096-Model[ModelIndex]) shr Move);
  end else begin
{$ifndef CPU64}
   OldCode:=Code;
{$endif}
   inc(Code,Bound);
{$ifndef CPU64}
   Carry:=Carry or (Code<OldCode);
{$endif}
   dec(Range,Bound);
   dec(Model[ModelIndex],Model[ModelIndex] shr Move);
  end;
  while Range<$1000000 do begin
   Range:=Range shl 8;
   EncoderShift;
  end;
  result:=Bit;
 end;
 procedure EncoderFlush;
 var Counter:TRNLInt32;
 begin
  for Counter:=1 to 5 do begin
   EncoderShift;
  end;
 end;
 procedure EncodeTree(ModelIndex,Bits,Move,Value:TRNLInt32);
 var Context:TRNLInt32;
 begin
  Context:=1;
  while Bits>0 do begin
   dec(Bits);
   Context:=(Context shl 1) or EncodeBit(ModelIndex+Context,Move,(Value shr Bits) and 1);
  end;
 end;
 procedure EncodeGamma(ModelIndex,Value:TRNLUInt32);
{$if true}
 var Index:TRNLInt32;
     Context:TRNLUInt8;
 begin
  Context:=1;
  for Index:=Max(1,BSRDWord(Value))-1 downto 0 do begin
   Context:=(Context shl 1) or TRNLUInt32(EncodeBit(ModelIndex+Context,5,TRNLUInt32(-Index) shr 31));
   Context:=(Context shl 1) or TRNLUInt32(EncodeBit(ModelIndex+Context,5,TRNLUInt32(-((Value shr Index) and 1)) shr 31));
  end;
 end;
{$else}
 var Mask:TRNLUInt32;
     Context:TRNLUInt8;
 begin
  Mask:=Value shr 1;
  while (Mask and (Mask-1))<>0 do begin
   Mask:=Mask and (Mask-1);
  end;
  Context:=1;
  while Mask<>0 do begin
   Context:=(Context shl 1) or TRNLUInt32(EncodeBit(ModelIndex+Context,5,TRNLUInt32(-(Mask shr 1)) shr 31));
   Context:=(Context shl 1) or TRNLUInt32(EncodeBit(ModelIndex+Context,5,TRNLUInt32(-(Value and Mask)) shr 31));
   Mask:=Mask shr 1;
  end;
 end;
{$ifend}
 procedure EncodeEnd(ModelIndex:TRNLInt32);
 var Bits:TRNLUInt32;
     Context:TRNLUInt8;
 begin
  Context:=1;
  Bits:=32;
  while Bits>0 do begin
   dec(Bits);
   Context:=(Context shl 1) or EncodeBit(ModelIndex+Context,5,TRNLUInt32(-Bits) shr 31);
   EncodeBit(ModelIndex+Context,5,0);
   Context:=Context shl 1;
  end;
 end;
var CurrentPointer,EndPointer,EndSearchPointer,Head,CurrentPossibleMatch:PRNLUInt8;
    BestMatchDistance,BestMatchLength,MatchLength,Offset,Step,Difference,
    LastMatchDistance,UnsuccessfulFindMatchAttempts:TRNLUInt32;
    HashTableItem:PPRNLUInt8;
    First:boolean;
begin
 DestLen:=0;
 LastWasMatch:=false;
 FirstByte:=true;
 OK:=true;
 CountFFBytes:=0;
 Range:=$ffffffff;
 Code:=0;
 LastMatchDistance:=$ffffffff;
 for Step:=0 to SizeModels-1 do begin
  Model[Step]:=2048;
 end;
 FillChar(fHashTable,SizeOf(THashTable),#0);
 FillChar(fChainTable,SizeOf(TChainTable),#0);
 CurrentPointer:=aInData;
 EndPointer:={%H-}TRNLPointer(TRNLPtrUInt(TRNLPtrUInt(CurrentPointer)+TRNLPtrUInt(aInSize)));
 EndSearchPointer:={%H-}TRNLPointer(TRNLPtrUInt((TRNLPtrUInt(CurrentPointer)+TRNLPtrUInt(aInSize))-TRNLPtrUInt(TRNLInt64(Max(TRNLInt64(MinMatch),TRNLInt64(SizeOf(TRNLUInt32)))))));
 First:=true;
 UnsuccessfulFindMatchAttempts:=TRNLUInt32(1) shl fSkipStrength;
 while {%H-}TRNLPtrUInt(CurrentPointer)<{%H-}TRNLPtrUInt(EndSearchPointer) do begin
  HashTableItem:=@fHashTable[((((PRNLUInt32(TRNLPointer(CurrentPointer))^ and TRNLUInt32({$if defined(FPC_BIG_ENDIAN)}$ffff0000{$else}$0000ffff{$ifend}){$if defined(FPC_BIG_ENDIAN)}shr 16{$ifend}))*TRNLUInt32($1e35a7bd)) shr HashShift) and HashMask];
  Head:=HashTableItem^;
  CurrentPossibleMatch:=Head;
  BestMatchDistance:=0;
  BestMatchLength:=1;
  if First then begin
   First:=false;
   EncodeTree(LiteralModel,8,4,PRNLUInt8(CurrentPointer)^);
  end else begin
   Step:=0;
   while assigned(CurrentPossibleMatch) and
         ({%H-}TRNLPtrUInt(CurrentPointer)>{%H-}TRNLPtrUInt(CurrentPossibleMatch)) and
         (TRNLPtrInt({%H-}TRNLPtrUInt({%H-}TRNLPtrUInt(CurrentPointer)-{%H-}TRNLPtrUInt(CurrentPossibleMatch)))<TRNLPtrInt(MaxOffset)) do begin
    Difference:=PRNLUInt32(TRNLPointer(@PRNLUInt8Array(CurrentPointer)^[0]))^ xor PRNLUInt32(TRNLPointer(@PRNLUInt8Array(CurrentPossibleMatch)^[0]))^;
    if (Difference and TRNLUInt32({$if defined(FPC_BIG_ENDIAN)}$ffff0000{$else}$0000ffff{$ifend}))=0 then begin
     if (BestMatchLength<=({%H-}TRNLPtrUInt(EndPointer)-{%H-}TRNLPtrUInt(CurrentPointer))) and
        (PRNLUInt8Array(CurrentPointer)^[BestMatchLength-1]=PRNLUInt8Array(CurrentPossibleMatch)^[BestMatchLength-1]) then begin
      MatchLength:=MinMatch;
      while (({%H-}TRNLPtrUInt(@PRNLUInt8Array(CurrentPointer)^[MatchLength]) and (SizeOf(TRNLUInt32)-1))<>0) and
            (({%H-}TRNLPtrUInt(@PRNLUInt8Array(CurrentPointer)^[MatchLength])<{%H-}TRNLPtrUInt(EndPointer))) and
            (PRNLUInt8Array(CurrentPointer)^[MatchLength]=PRNLUInt8Array(CurrentPossibleMatch)^[MatchLength]) do begin
       inc(MatchLength);
      end;
      while ({%H-}TRNLPtrUInt(@PRNLUInt8Array(CurrentPointer)^[MatchLength+(SizeOf(TRNLUInt32)-1)])<{%H-}TRNLPtrUInt(EndPointer)) do begin
       Difference:=PRNLUInt32(TRNLPointer(@PRNLUInt8Array(CurrentPointer)^[MatchLength]))^ xor PRNLUInt32(TRNLPointer(@PRNLUInt8Array(CurrentPossibleMatch)^[MatchLength]))^;
       if Difference=0 then begin
        inc(MatchLength,SizeOf(TRNLUInt32));
       end else begin
{$if defined(BIG_ENDIAN)}
        if (Difference shr 16)<>0 then begin
         inc(MatchLength,not (Difference shr 24));
        end else begin
         inc(MatchLength,2+(not (Difference shr 8)));
        end;
{$else}
        inc(MatchLength,MultiplyDeBruijnBytePosition[TRNLUInt32(TRNLUInt32(Difference and (-Difference))*TRNLUInt32($077cb531)) shr 27]);
{$ifend}
        break;
       end;
      end;
      if BestMatchLength<MatchLength then begin
       BestMatchDistance:={%H-}TRNLPtrUInt({%H-}TRNLPtrUInt(CurrentPointer)-{%H-}TRNLPtrUInt(CurrentPossibleMatch));
       BestMatchLength:=MatchLength;
      end;
     end;
    end;
    inc(Step);
    if Step<fMaxSteps then begin
     CurrentPossibleMatch:=fChainTable[({%H-}TRNLPtrUInt(CurrentPossibleMatch)-{%H-}TRNLPtrUInt(aInData)) and WindowMask];
    end else begin
     break;
    end;
   end;
   if (BestMatchDistance>0) and
      (((BestMatchDistance<96) and (BestMatchLength>1)) or
       ((BestMatchDistance>=96) and (BestMatchLength>3)) or
       ((BestMatchDistance>=2048) and (BestMatchLength>4))) then begin
//  writeln('C: ',BestMatchLength,' ',{%H-}TRNLPtrUInt(CurrentPointer)-{%H-}TRNLPtrUInt(aInData),' ',({%H-}TRNLPtrUInt(CurrentPointer)-{%H-}TRNLPtrUInt(aInData))+BestMatchLength);
    MatchLength:=BestMatchLength;
    EncodeBit(FlagModel+TRNLUInt8(ord(LastWasMatch) and 1),5,1);
    if (not LastWasMatch) and (BestMatchDistance=LastMatchDistance) then begin
     EncodeBit(PreviousMatchModel,5,1);
    end else begin
     if not LastWasMatch then begin
      EncodeBit(PreviousMatchModel,5,0);
     end;
     Offset:=BestMatchDistance-1;
     EncodeGamma(Gamma0Model,(Offset shr 4)+2);
     EncodeTree(MatchLowModel+((ord((Offset shr 4)<>0) and 1) shl 4),4,5,Offset and $f);
     dec(MatchLength,(ord(BestMatchDistance>=96) and 1)+(ord(BestMatchDistance>=2048) and 1));
    end;
    EncodeGamma(Gamma1Model,MatchLength);
    LastWasMatch:=true;
    LastMatchDistance:=BestMatchDistance;
    UnsuccessfulFindMatchAttempts:=TRNLUInt32(1) shl fSkipStrength;
   end else begin
    if (fSkipStrength>31) and (BestMatchLength=1) then begin
     EncodeBit(FlagModel+TRNLUInt8(ord(LastWasMatch) and 1),5,0);
     EncodeTree(LiteralModel,8,4,CurrentPointer^);
     LastWasMatch:=false;
    end else begin
     if BestMatchLength=1 then begin
      Step:=UnsuccessfulFindMatchAttempts shr fSkipStrength;
     end else begin
      Step:=BestMatchLength;
     end;
     Offset:=0;
     while (Offset<Step) and (({%H-}TRNLPtrUInt(CurrentPointer)+Offset)<{%H-}TRNLPtrUInt(EndSearchPointer)) do begin
      EncodeBit(FlagModel+TRNLUInt8(ord(LastWasMatch) and 1),5,0);
      EncodeTree(LiteralModel,8,4,PRNLUInt8Array(CurrentPointer)^[Offset]);
      LastWasMatch:=false;
      inc(Offset);
     end;
     if BestMatchLength=1 then begin
      BestMatchLength:=Offset;
      inc(UnsuccessfulFindMatchAttempts,ord(UnsuccessfulFindMatchAttempts<TRNLUInt32($ffffffff)) and 1);
     end;
    end;
   end;
  end;
  if not OK then begin
   break;
  end;
  HashTableItem^:=CurrentPointer;
  fChainTable[({%H-}TRNLPtrUInt(CurrentPointer)-{%H-}TRNLPtrUInt(aInData)) and WindowMask]:=Head;
  if fGreedy then begin
   inc(CurrentPointer);
   dec(BestMatchLength);
   while (BestMatchLength>0) and ({%H-}TRNLPtrUInt(CurrentPointer)<{%H-}TRNLPtrUInt(EndSearchPointer)) do begin
    HashTableItem:=@fHashTable[((((PRNLUInt32(TRNLPointer(CurrentPointer))^ and TRNLUInt32({$if defined(FPC_BIG_ENDIAN)}$ffff0000{$else}$0000ffff{$ifend}){$if defined(FPC_BIG_ENDIAN)}shr 16{$ifend}))*TRNLUInt32($1e35a7bd)) shr HashShift) and HashMask];
    Head:=HashTableItem^;
    HashTableItem^:=CurrentPointer;
    fChainTable[({%H-}TRNLPtrUInt(CurrentPointer)-{%H-}TRNLPtrUInt(aInData)) and WindowMask]:=Head;
    inc(CurrentPointer);
    dec(BestMatchLength);
   end;
  end;
  inc(CurrentPointer,BestMatchLength);
 end;
 while {%H-}TRNLPtrUInt(CurrentPointer)<{%H-}TRNLPtrUInt(EndPointer) do begin
  EncodeBit(FlagModel+TRNLUInt8(ord(LastWasMatch) and 1),5,0);
  EncodeTree(LiteralModel,8,4,CurrentPointer^);
  LastWasMatch:=false;
  inc(CurrentPointer);
 end;
 EncodeBit(FlagModel+TRNLUInt8(ord(LastWasMatch) and 1),5,1);
 if not LastWasMatch then begin
  EncodeBit(PreviousMatchModel,5,0);
 end;
 EncodeEnd(Gamma0Model);
 MinDestLen:=Max(2,DestLen+1);
 EncoderFlush;
 if OK then begin
  while (DestLen>MinDestLen) and (PRNLUInt8Array(aOutData)^[DestLen-1]=0) do begin
   dec(DestLen);
  end;
  result:=DestLen;
 end else begin
  result:=0;
 end;
end;

function TRNLCompressorLZBRRC.Decompress(const aInData:TRNLPointer;const aInSize:TRNLSizeUInt;const aOutData:TRNLPointer;const aOutLimit:TRNLSizeUInt):TRNLSizeUInt;
var Code,Range,Position:TRNLUInt32;
    Model:array[0..SizeModels-1] of TRNLUInt32;
    OK:boolean;
 function DecodeBit(ModelIndex,Move:TRNLInt32):TRNLInt32;
 var Bound:TRNLUInt32;
 begin
  Bound:=(Range shr 12)*Model[ModelIndex];
  if Code<Bound then begin
   Range:=Bound;
   inc(Model[ModelIndex],(4096-Model[ModelIndex]) shr Move);
   result:=0;
  end else begin
   dec(Code,Bound);
   dec(Range,Bound);
   dec(Model[ModelIndex],Model[ModelIndex] shr Move);
   result:=1;
  end;
  while Range<$1000000 do begin
   if Position<aInSize then begin
    Code:=(Code shl 8) or PRNLUInt8Array(aInData)^[Position];
   end else begin
    if Position<(aInSize+5) then begin
     Code:=Code shl 8;
    end else begin
     OK:=false;
     break;
    end;
   end;
   inc(Position);
   Range:=Range shl 8;
  end;
 end;
 function DecodeTree(ModelIndex,MaxValue,Move:TRNLInt32):TRNLInt32;
 begin
  result:=1;
  while OK and (result<MaxValue) do begin
   result:=(result shl 1) or DecodeBit(ModelIndex+result,Move);
  end;
  dec(result,MaxValue);
 end;
 function DecodeGamma(ModelIndex:TRNLInt32):TRNLInt32;
 var Context:TRNLUInt8;
 begin
  result:=1;
  Context:=1;
  repeat
   Context:=(Context shl 1) or DecodeBit(ModelIndex+Context,5);
   result:=(result shl 1) or DecodeBit(ModelIndex+Context,5);
   Context:=(Context shl 1) or (result and 1);
  until (not OK) or ((Context and 2)=0);
 end;
var Len,Offset,LastOffset,DestLen,Value:TRNLInt32;
    Flag,LastWasMatch:boolean;
begin
 result:=0;
 if aInSize>=3 then begin
  OK:=true;
  Code:=(PRNLUInt8Array(aInData)^[0] shl 24) or
        (PRNLUInt8Array(aInData)^[1] shl 16) or
        (PRNLUInt8Array(aInData)^[2] shl 8) or
        (PRNLUInt8Array(aInData)^[3] shl 0);
  Position:=4;
  Range:=$ffffffff;
  for Value:=0 to SizeModels-1 do begin
   Model[Value]:=2048;
  end;
  LastOffset:=0;
  LastWasMatch:=false;
  Flag:=false;
  DestLen:=0;
  repeat
   if Flag then begin
    if (not LastWasMatch) and (DecodeBit(PreviousMatchModel,5)<>0) then begin
     if OK then begin
      Offset:=LastOffset;
      Len:=0;
     end else begin
      exit;
     end;
    end else begin
     Offset:=DecodeGamma(Gamma0Model);
     if OK then begin
      if Offset=0 then begin
       break;
      end else begin
       dec(Offset,2);
       Offset:=((Offset shl 4)+DecodeTree(MatchLowModel+((ord(Offset<>0) and 1) shl 4),16,5))+1;
       Len:=(ord(Offset>=96) and 1)+(ord(Offset>=2048) and 1);
      end;
     end else begin
      exit;
     end;
    end;
    LastOffset:=Offset;
    LastWasMatch:=true;
    inc(Len,DecodeGamma(Gamma1Model));
//  writeln('D: ',DestLen,' ',Len,' ',DestLen+Len);
    if (TRNLSizeUInt(DestLen+Len)<=TRNLSizeUInt(aOutLimit)) and
       (TRNLSizeUInt(Offset)<=TRNLSizeUInt(DestLen)) then begin
     RLELikeSideEffectAwareMemoryMove(PRNLUInt8Array(aOutData)^[DestLen-Offset],
                                      PRNLUInt8Array(aOutData)^[DestLen],
                                      Len);
     inc(DestLen,Len);
    end else begin
     exit;
    end;
   end else begin
    Value:=DecodeTree(LiteralModel,256,4);
    if OK and (TRNLSizeUInt(DestLen)<TRNLSizeUInt(aOutLimit)) then begin
     PRNLUInt8Array(aOutData)^[DestLen]:=Value;
     inc(DestLen);
     LastWasMatch:=false;
    end else begin
     exit;
    end;
   end;
   Flag:=boolean(byte(DecodeBit(FlagModel+TRNLUInt8(ord(LastWasMatch) and 1),5)));
  until false;
  result:=DestLen;
 end;
end;

constructor TRNLCompressorBRRC.Create;
begin
 inherited Create;
end;

destructor TRNLCompressorBRRC.Destroy;
begin
 inherited Destroy;
end;

function TRNLCompressorBRRC.Compress(const aInData:TRNLPointer;const aInSize:TRNLSizeUInt;const aOutData:TRNLPointer;const aOutLimit:TRNLSizeUInt):TRNLSizeUInt;
var {$ifndef CPU64}Code,{$endif}Range,Cache,CountFFBytes:TRNLUInt32;
    {$ifdef CPU64}Code:TRNLUInt64;{$endif}
    Model:array[0..SizeModels-1] of TRNLUInt32;
    OK,FirstByte{$ifndef CPU64},Carry{$endif}:boolean;
    DestLen:TRNLInt32;
 procedure EncoderShift;
{$ifdef CPU64}
 var Carry:boolean;
{$endif}
 begin
{$ifdef CPU64}
  Carry:=PRNLUInt64Record(TRNLPointer(@Code))^.Hi<>0; // or (Code shr 32)<>0; or also (Code and TRNLUInt64($ffffffff00000000))<>0;
{$endif}
  if (Code<$ff000000) or Carry then begin
   if FirstByte then begin
    FirstByte:=false;
   end else begin
    if TRNLSizeUInt(DestLen)<TRNLSizeUInt(aOutLimit) then begin
     PRNLUInt8Array(aOutData)^[DestLen]:=Cache+TRNLUInt8(ord(Carry) and 1);
     inc(DestLen);
    end else begin
     OK:=false;
     exit;
    end;
   end;
   while CountFFBytes<>0 do begin
    dec(CountFFBytes);
    if TRNLSizeUInt(DestLen)<TRNLSizeUInt(aOutLimit) then begin
     PRNLUInt8Array(aOutData)^[DestLen]:=$ff+TRNLUInt8(ord(Carry) and 1);
     inc(DestLen);
    end else begin
     OK:=false;
     exit;
    end;
   end;
   Cache:=(Code shr 24) and $ff;
  end else begin
   inc(CountFFBytes);
  end;
  Code:=(Code shl 8){$ifdef CPU64}and TRNLUInt32($ffffffff){$endif};
  Carry:=false;
 end;
 function EncodeBit(ModelIndex,Move,Bit:TRNLInt32):TRNLInt32;
 var Bound{$ifndef CPU64},OldCode{$endif}:TRNLUInt32;
 begin
  Bound:=(Range shr 12)*Model[ModelIndex];
  if Bit=0 then begin
   Range:=Bound;
   inc(Model[ModelIndex],(4096-Model[ModelIndex]) shr Move);
  end else begin
{$ifndef CPU64}
   OldCode:=Code;
{$endif}
   inc(Code,Bound);
{$ifndef CPU64}
   Carry:=Carry or (Code<OldCode);
{$endif}
   dec(Range,Bound);
   dec(Model[ModelIndex],Model[ModelIndex] shr Move);
  end;
  while Range<$1000000 do begin
   Range:=Range shl 8;
   EncoderShift;
  end;
  result:=Bit;
 end;
 procedure EncoderFlush;
 var Counter:TRNLInt32;
 begin
  for Counter:=1 to 5 do begin
   EncoderShift;
  end;
 end;
 procedure EncodeTree(ModelIndex,Bits,Move,Value:TRNLInt32);
 var Context:TRNLInt32;
 begin
  Context:=1;
  while Bits>0 do begin
   dec(Bits);
   Context:=(Context shl 1) or EncodeBit(ModelIndex+Context,Move,(Value shr Bits) and 1);
  end;
 end;
var CurrentPointer,EndPointer:PRNLUInt8;
    Len,MinDestLen:TRNLInt32;
begin
 DestLen:=0;
 FirstByte:=true;
 OK:=true;
 CountFFBytes:=0;
 Range:=$ffffffff;
 Code:=0;
 for Len:=0 to SizeModels-1 do begin
  Model[Len]:=2048;
 end;
 CurrentPointer:=aInData;
 EndPointer:={%H-}TRNLPointer(TRNLPtrUInt(TRNLPtrUInt(CurrentPointer)+TRNLPtrUInt(aInSize)));
 while {%H-}TRNLPtrUInt(CurrentPointer)<{%H-}TRNLPtrUInt(EndPointer) do begin
  EncodeBit(FlagModel,1,1);
  EncodeTree(LiteralModel,8,4,PRNLUInt8(CurrentPointer)^);
  if not OK then begin
   break;
  end;
  inc(CurrentPointer);
 end;
 EncodeBit(FlagModel,1,0);
 MinDestLen:=Max(2,DestLen+1);
 EncoderFlush;
 if OK then begin
  while (DestLen>MinDestLen) and (PRNLUInt8Array(aOutData)^[DestLen-1]=0) do begin
   dec(DestLen);
  end;
  result:=DestLen;
 end else begin
  result:=0;
 end;
end;

function TRNLCompressorBRRC.Decompress(const aInData:TRNLPointer;const aInSize:TRNLSizeUInt;const aOutData:TRNLPointer;const aOutLimit:TRNLSizeUInt):TRNLSizeUInt;
var Code,Range,Position:TRNLUInt32;
    Model:array[0..SizeModels-1] of TRNLUInt32;
    OK:boolean;
 function DecodeBit(ModelIndex,Move:TRNLInt32):TRNLInt32;
 var Bound:TRNLUInt32;
 begin
  Bound:=(Range shr 12)*Model[ModelIndex];
  if Code<Bound then begin
   Range:=Bound;
   inc(Model[ModelIndex],(4096-Model[ModelIndex]) shr Move);
   result:=0;
  end else begin
   dec(Code,Bound);
   dec(Range,Bound);
   dec(Model[ModelIndex],Model[ModelIndex] shr Move);
   result:=1;
  end;
  while Range<$1000000 do begin
   if Position<aInSize then begin
    Code:=(Code shl 8) or PRNLUInt8Array(aInData)^[Position];
   end else begin
    if Position<(aInSize+4+5) then begin
     Code:=Code shl 8;
    end else begin
     OK:=false;
     break;
    end;
   end;
   inc(Position);
   Range:=Range shl 8;
  end;
 end;
 function DecodeTree(ModelIndex,MaxValue,Move:TRNLInt32):TRNLInt32;
 begin
  result:=1;
  while OK and (result<MaxValue) do begin
   result:=(result shl 1) or DecodeBit(ModelIndex+result,Move);
  end;
  dec(result,MaxValue);
 end;
var DestLen,Value:TRNLInt32;
begin
 result:=0;
 if aInSize>=3 then begin
  OK:=true;
  Code:=(PRNLUInt8Array(aInData)^[0] shl 24) or
        (PRNLUInt8Array(aInData)^[1] shl 16) or
        (PRNLUInt8Array(aInData)^[2] shl 8) or
        (PRNLUInt8Array(aInData)^[3] shl 0);
  Position:=4;
  Range:=$ffffffff;
  for Value:=0 to SizeModels-1 do begin
   Model[Value]:=2048;
  end;
  DestLen:=0;
  repeat
   Value:=DecodeBit(FlagModel,1);
   if OK then begin
    if Value<>0 then begin
     Value:=DecodeTree(LiteralModel,256,4);
     if OK and (TRNLSizeUInt(DestLen)<TRNLSizeUInt(aOutLimit)) then begin
      PRNLUInt8Array(aOutData)^[DestLen]:=Value;
      inc(DestLen);
     end else begin
      exit;
     end;
    end else begin
     break;
    end;
   end else begin
    exit;
   end;
  until false;
  result:=DestLen;
 end;
end;

constructor TRNLPeerPendingConnectionHandshakeSendData.Create(const aPeer:TRNLPeer);
begin
 fPeer:=aPeer;
 FillChar(fHandshakePacket,SizeOf(TRNLProtocolHandshakePacket),#0);
end;

function TRNLPeerPendingConnectionHandshakeSendData.Send:boolean;
var PacketSize:TRNLSizeInt;
begin
 fPeer.fHost.AddHandshakePacketChecksum(fHandshakePacket);
 PacketSize:=RNLProtocolHandshakePacketSizes[TRNLProtocolHandshakePacketType(TRNLInt32(fHandshakePacket.Header.PacketType))];
 result:=(PacketSize>0) and (fPeer.SendPacket(fHandshakePacket,PacketSize)<>RNL_NETWORK_SEND_RESULT_ERROR);
end;

constructor TRNLPeerBlockPacket.Create(const aPeer:TRNLPeer);
begin
 inherited Create;
 fPeer:=aPeer;
 fValue:=self;
 fChannel:=$ff;
 fSequenceNumber:=0;
 fCountSendAttempts:=0;
 fRoundTripTimeout:=0;
 fRoundTripTimeoutLimit:=0;
 fSentTime:=0;
 fReceivedTime:=0;
 fBlockPacketData:=nil;
 fBlockPacketDataLength:=0;
 fReferenceCounter:=1;
 fPendingResendOutgoingBlockPacketsList:=nil;
end;

destructor TRNLPeerBlockPacket.Destroy;
begin
 fBlockPacketData:=nil;
 inherited Destroy;
end;

procedure TRNLPeerBlockPacket.IncRef;
begin
 inc(fReferenceCounter);
end;

procedure TRNLPeerBlockPacket.DecRef;
begin
 if assigned(self) and (fReferenceCounter>0) then begin
  dec(fReferenceCounter);
  if fReferenceCounter=0 then begin
   Free;
  end;
 end;
end;

procedure TRNLPeerBlockPacket.Clear;
begin
 if self<>fNext then begin
  Remove;
 end;
 fChannel:=$ff;
 fSequenceNumber:=0;
 fCountSendAttempts:=0;
 fRoundTripTimeout:=0;
 fRoundTripTimeoutLimit:=0;
 fSentTime:=0;
 fReceivedTime:=0;
 fBlockPacketDataLength:=0;
 fPendingResendOutgoingBlockPacketsList:=nil;
end;

function TRNLPeerBlockPacket.GetPointerToBlockPacket:PRNLProtocolBlockPacket;
begin
 result:=@fBlockPacket;
end;

function TRNLPeerBlockPacket.GetSize:TRNLSizeUInt;
begin
 result:=RNLProtocolBlockPacketSizes[TRNLProtocolBlockPacketType(TRNLInt32(fBlockPacket.Header.TypeAndSubtype and $f))]+
         fBlockPacketDataLength;
end;

function TRNLPeerBlockPacket.AppendTo(var aOutgoingPacketBuffer:TRNLOutgoingPacketBuffer):boolean;
begin
 aOutgoingPacketBuffer.Write(fBlockPacket,RNLProtocolBlockPacketSizes[TRNLProtocolBlockPacketType(TRNLInt32(fBlockPacket.Header.TypeAndSubtype and $f))]);
 if fBlockPacketDataLength>0 then begin
  aOutgoingPacketBuffer.Write(fBlockPacketData[0],fBlockPacketDataLength);
 end;
 result:=true;
end;

constructor TRNLPeerChannel.Create(const aPeer:TRNLPeer;const aChannelNumber:TRNLUInt16);
begin
 inherited Create;

 fPeer:=aPeer;

 fHost:=fPeer.fHost;

 fChannelNumber:=aChannelNumber;

 fIncomingMessageQueue:=TRNLMessageQueue.Create;

 fOutgoingMessageQueue:=TRNLMessageQueue.Create;

end;

destructor TRNLPeerChannel.Destroy;
var Message:TRNLMessage;
begin

 while fIncomingMessageQueue.Dequeue(Message) do begin
  Message.DecRef;
 end;

 while fOutgoingMessageQueue.Dequeue(Message) do begin
  Message.DecRef;
 end;

 fIncomingMessageQueue.Free;

 fOutgoingMessageQueue.Free;

 inherited Destroy;
end;

procedure TRNLPeerChannel.DispatchOutgoingBlockPackets;
begin
end;

procedure TRNLPeerChannel.DispatchIncomingBlockPacket(const aBlockPacket:TRNLPeerBlockPacket);
begin
end;

procedure TRNLPeerChannel.DispatchIncomingMessages;
var Message:TRNLMessage;
    HostEvent:TRNLHostEvent;
begin
 while fIncomingMessageQueue.Dequeue(Message) do begin
  try
   HostEvent.Type_:=RNL_HOST_EVENT_TYPE_RECEIVE;
   HostEvent.Receive.Peer:=fPeer;
   HostEvent.Receive.Channel:=fChannelNumber;
   HostEvent.Receive.Message:=Message;
  finally
   fHost.fEventQueue.Enqueue(HostEvent);
  end;
 end;
end;

function TRNLPeerChannel.GetMaximumUnfragmentedMessageSize:TRNLSizeUInt;
begin
 result:=fPeer.fMTU-(RNL_IP_HEADER_SIZE+
                     RNL_UDP_HEADER_SIZE+
                     SizeOf(TRNLProtocolNormalPacketHeader)+
                     SizeOf(TRNLProtocolBlockPacketChannel));
end;

procedure TRNLPeerChannel.SendMessage(const aMessage:TRNLMessage);
begin
 if aMessage.fDataLength<=fHost.fMaximumMessageSize then begin
  try
   aMessage.IncRef;
  finally
   fOutgoingMessageQueue.Enqueue(aMessage);
  end;
 end;
end;

procedure TRNLPeerChannel.SendMessageData(const aData:TRNLPointer;const aDataLength:TRNLUInt32;const aFlags:TRNLMessageFlags=[]);
var Message:TRNLMessage;
begin
 Message:=TRNLMessage.CreateFromMemory(aData,aDataLength,aFlags);
 try
  SendMessage(Message);
 finally
  Message.DecRef;
 end;
end;

procedure TRNLPeerChannel.SendMessageString(const aString:TRNLRawByteString;const aFlags:TRNLMessageFlags=[]);
var Message:TRNLMessage;
begin
 Message:=TRNLMessage.CreateFromString(aString,aFlags);
 try
  SendMessage(Message);
 finally
  Message.DecRef;
 end;
end;

procedure TRNLPeerChannel.SendMessageStream(const aStream:TStream;const aFlags:TRNLMessageFlags=[]);
var Message:TRNLMessage;
begin
 Message:=TRNLMessage.CreateFromStream(aStream,aFlags);
 try
  SendMessage(Message);
 finally
  Message.DecRef;
 end;
end;

constructor TRNLPeerReliableChannel.Create(const aPeer:TRNLPeer;const aChannelNumber:TRNLUInt16);
begin

 inherited Create(aPeer,aChannelNumber);

 fOrdered:=true;

 fIncomingBlockPackets:=nil;
 SetLength(fIncomingBlockPackets,fHost.fReliableChannelBlockPacketWindowSize);
 FillChar(fIncomingBlockPackets[0],fHost.fReliableChannelBlockPacketWindowSize*SizeOf(TRNLPeerBlockPacket),#0);
 fIncomingBlockPacketSequenceNumber:=0;

 fIncomingAcknowledgements:=nil;
 SetLength(fIncomingAcknowledgements,fHost.fReliableChannelBlockPacketWindowSize);
 FillChar(fIncomingAcknowledgements[0],fHost.fReliableChannelBlockPacketWindowSize*SizeOf(TRNLInt32),#$ff);
 fIncomingAcknowledgementSequenceNumber:=0;

 fOutgoingBlockPackets:=nil;
 SetLength(fOutgoingBlockPackets,fHost.fReliableChannelBlockPacketWindowSize);
 FillChar(fOutgoingBlockPackets[0],fHost.fReliableChannelBlockPacketWindowSize*SizeOf(TRNLPeerBlockPacket),#0);
 fOutgoingBlockPacketSequenceNumber:=0;

 fOutgoingAcknowledgementQueue:=TRNLSequenceNumberQueue.Create;

 fOutgoingAcknowledgementArray:=nil;
 SetLength(fOutgoingAcknowledgementArray,fHost.fReliableChannelBlockPacketWindowSize);

 fOutgoingAcknowledgementData:=nil;

 fOutgoingBlockPacketQueue:=TRNLPeerBlockPacketQueue.Create;

 fSentOutgoingBlockPackets:=TRNLPeerBlockPacketCircularDoublyLinkedListNode.Create;

end;

destructor TRNLPeerReliableChannel.Destroy;
var BlockPacket:TRNLPeerBlockPacket;
begin

 for BlockPacket in fIncomingBlockPackets do begin
  BlockPacket.DecRef;
 end;
 fIncomingBlockPackets:=nil;

 for BlockPacket in fOutgoingBlockPackets do begin
  BlockPacket.DecRef;
 end;
 fOutgoingBlockPackets:=nil;

 fIncomingAcknowledgements:=nil;

 FreeAndNil(fOutgoingAcknowledgementQueue);

 fOutgoingAcknowledgementArray:=nil;

 fOutgoingAcknowledgementData:=nil;

 while fOutgoingBlockPacketQueue.Dequeue(BlockPacket) do begin
  BlockPacket.DecRef;
 end;
 FreeAndNil(fOutgoingBlockPacketQueue);

 while not fSentOutgoingBlockPackets.Empty do begin
  fSentOutgoingBlockPackets.Front.Value.DecRef;
 end;
 FreeAndNil(fSentOutgoingBlockPackets);

 inherited Destroy;

end;

function TRNLPeerReliableChannel.GetMaximumUnfragmentedMessageSize:TRNLSizeUInt;
begin
 result:=fPeer.fMTU-(RNL_IP_HEADER_SIZE+
                     RNL_UDP_HEADER_SIZE+
                     SizeOf(TRNLProtocolNormalPacketHeader)+
                     SizeOf(TRNLProtocolBlockPacketChannel)+
                     SizeOf(TRNLPeerReliableChannelShortMessagePacketHeader));
end;

procedure TRNLPeerReliableChannel.DispatchOutgoingBlockPacketsTimeout;
var CurrentBlockPacketListNode,
    NextBlockPacketListNode:TRNLPeerBlockPacketCircularDoublyLinkedListNode;
    BlockPacket:TRNLPeerBlockPacket;
begin

 CurrentBlockPacketListNode:=fSentOutgoingBlockPackets.Front;
 while CurrentBlockPacketListNode<>fSentOutgoingBlockPackets do begin

  NextBlockPacketListNode:=CurrentBlockPacketListNode.Next;

  BlockPacket:=CurrentBlockPacketListNode.fValue;

  if TRNLTime.Difference(fHost.fTime,BlockPacket.fSentTime)>=BlockPacket.fRoundTripTimeout then begin

   inc(fPeer.fCountPacketLoss);

   inc(BlockPacket.fRoundTripTimeout,BlockPacket.fRoundTripTimeout);

   if BlockPacket.fRoundTripTimeout>BlockPacket.fRoundTripTimeoutLimit then begin
    BlockPacket.fRoundTripTimeout:=BlockPacket.fRoundTripTimeoutLimit;
   end;

   BlockPacket.Remove;

   BlockPacket.fPendingResendOutgoingBlockPacketsList:=fSentOutgoingBlockPackets;

   fPeer.fOutgoingBlockPackets.EnqueueAtFront(BlockPacket);

  end;

  CurrentBlockPacketListNode:=NextBlockPacketListNode;

 end;

end;

function TRNLPeerReliableChannelSortOutgoingAcknowledgementSequenceNumbers(const a,b:TRNLSequenceNumber):TRNLInt32;
begin
 result:=TRNLSequenceNumber.RelativeDifference(a,b);
end;

procedure TRNLPeerReliableChannel.DispatchOutgoingAcknowledgementBlockPackets;
var CountAcknowledgements,AcknowledgementIndex,MaximumAcknowledgementBits,
    AcknowledgementDataLength,AcknowledgementDataPosition:TRNLSizeUInt;
    BlockPacketSequenceNumber,StartSequenceNumber:TRNLSequenceNumber;
    AcknowledgmentBitIndex:TRNLInt32;
    BlockPacket:TRNLPeerBlockPacket;
    AcknowledgementPacketHeader:PRNLPeerReliableChannelAcknowledgementPacketHeader;
    AcknowledgementsPacketHeader:PRNLPeerReliableChannelAcknowledgementsPacketHeader;
    DoNeedSort:boolean;
begin

 // Dispatch outgoing enqueued incoming acknowledgements to outgoing acknowledgement(s) block packets

 MaximumAcknowledgementBits:=(fPeer.fMTU-(RNL_IP_HEADER_SIZE+
                                          RNL_UDP_HEADER_SIZE+
                                          SizeOf(TRNLProtocolNormalPacketHeader)+
                                          SizeOf(TRNLProtocolBlockPacketChannel)+
                                          SizeOf(TRNLPeerReliableChannelAcknowledgementPacketHeader))) shl 3;

 DoNeedSort:=false;

 CountAcknowledgements:=0;
 while fOutgoingAcknowledgementQueue.Dequeue(BlockPacketSequenceNumber) do begin
  DoNeedSort:=DoNeedSort or
              ((CountAcknowledgements>0) and
               (fOutgoingAcknowledgementArray[CountAcknowledgements-1]>BlockPacketSequenceNumber));
  fOutgoingAcknowledgementArray[CountAcknowledgements]:=BlockPacketSequenceNumber;
  inc(CountAcknowledgements);
 end;

 if CountAcknowledgements>0 then begin

  if (CountAcknowledgements>1) and DoNeedSort then begin
   TRNLTypedSort<TRNLSequenceNumber>.IntroSort(@fOutgoingAcknowledgementArray[0],0,CountAcknowledgements-1,TRNLPeerReliableChannelSortOutgoingAcknowledgementSequenceNumbers);
  end;

  AcknowledgementIndex:=0;
  while AcknowledgementIndex<CountAcknowledgements do begin

   StartSequenceNumber:=fOutgoingAcknowledgementArray[AcknowledgementIndex];

   AcknowledgementDataLength:=0;

   while AcknowledgementIndex<CountAcknowledgements do begin

    AcknowledgmentBitIndex:=TRNLSequenceNumber.RelativeDifference(fOutgoingAcknowledgementArray[AcknowledgementIndex],
                                                                  StartSequenceNumber);

    if AcknowledgmentBitIndex>=TRNLSizeInt(MaximumAcknowledgementBits) then begin
     break;
    end;

    AcknowledgementDataPosition:=AcknowledgmentBitIndex shr 3;

    if AcknowledgementDataLength<=AcknowledgementDataPosition then begin
     if TRNLSizeUInt(length(fOutgoingAcknowledgementData))<=AcknowledgementDataPosition then begin
      SetLength(fOutgoingAcknowledgementData,(AcknowledgementDataPosition+1)*2);
     end;
     FillChar(fOutgoingAcknowledgementData[AcknowledgementDataLength],
              (AcknowledgementDataPosition-AcknowledgementDataLength)+1,
              #0);
     AcknowledgementDataLength:=AcknowledgementDataPosition+1;
    end;

    fOutgoingAcknowledgementData[AcknowledgementDataPosition]:=fOutgoingAcknowledgementData[AcknowledgementDataPosition] or (TRNLUInt8(1) shl TRNLSizeUInt(AcknowledgmentBitIndex and 7));

    inc(AcknowledgementIndex);
   end;

   if (AcknowledgementDataLength=1) and (fOutgoingAcknowledgementData[0]=1) then begin

    BlockPacket:=TRNLPeerBlockPacket.Create(fPeer);
    try

     BlockPacket.fBlockPacket.Channel.Header.TypeAndSubtype:=(TRNLInt32(TRNLProtocolBlockPacketType(RNL_PROTOCOL_BLOCK_PACKET_TYPE_CHANNEL)) shl 0) or
                                                             (TRNLInt32(TRNLPeerReliableChannelCommandType(RNL_PEER_RELIABLE_CHANNEL_COMMAND_TYPE_ACKNOWLEDGEMENT)) shl 4);
     BlockPacket.fBlockPacket.Channel.ChannelNumber:=fChannelNumber;
     BlockPacket.fBlockPacket.Channel.PayloadDataLength:=TRNLEndianness.HostToLittleEndian16(SizeOf(TRNLPeerReliableChannelAcknowledgementPacketHeader));

     BlockPacket.fBlockPacketDataLength:=SizeOf(TRNLPeerReliableChannelAcknowledgementPacketHeader);

     SetLength(BlockPacket.fBlockPacketData,BlockPacket.fBlockPacketDataLength);

     AcknowledgementPacketHeader:=TRNLPointer(@BlockPacket.fBlockPacketData[0]);
     AcknowledgementPacketHeader^.Header.SequenceNumber:=TRNLEndianness.HostToLittleEndian16(StartSequenceNumber);

     BlockPacket.fPendingResendOutgoingBlockPacketsList:=nil; // No resend timeout

    finally
     fPeer.fOutgoingBlockPackets.Enqueue(BlockPacket);
    end;

   end else if AcknowledgementDataLength>0 then begin

    BlockPacket:=TRNLPeerBlockPacket.Create(fPeer);
    try

     BlockPacket.fBlockPacket.Channel.Header.TypeAndSubtype:=(TRNLInt32(TRNLProtocolBlockPacketType(RNL_PROTOCOL_BLOCK_PACKET_TYPE_CHANNEL)) shl 0) or
                                                             (TRNLInt32(TRNLPeerReliableChannelCommandType(RNL_PEER_RELIABLE_CHANNEL_COMMAND_TYPE_ACKNOWLEDGEMENTS)) shl 4);
     BlockPacket.fBlockPacket.Channel.ChannelNumber:=fChannelNumber;
     BlockPacket.fBlockPacket.Channel.PayloadDataLength:=TRNLEndianness.HostToLittleEndian16(SizeOf(TRNLPeerReliableChannelAcknowledgementsPacketHeader)+AcknowledgementDataLength);

     BlockPacket.fBlockPacketDataLength:=SizeOf(TRNLPeerReliableChannelAcknowledgementsPacketHeader)+AcknowledgementDataLength;

     SetLength(BlockPacket.fBlockPacketData,BlockPacket.fBlockPacketDataLength);

     AcknowledgementsPacketHeader:=TRNLPointer(@BlockPacket.fBlockPacketData[0]);
     AcknowledgementsPacketHeader^.Header.SequenceNumber:=TRNLEndianness.HostToLittleEndian16(StartSequenceNumber);

     Move(fOutgoingAcknowledgementData[0],
          BlockPacket.fBlockPacketData[SizeOf(TRNLPeerReliableChannelAcknowledgementsPacketHeader)],
          AcknowledgementDataLength);

     BlockPacket.fPendingResendOutgoingBlockPacketsList:=nil; // No resend timeout

    finally
     fPeer.fOutgoingBlockPackets.Enqueue(BlockPacket);
    end;

   end;

  end;

 end;

end;

procedure TRNLPeerReliableChannel.DispatchOutgoingBlockPackets;
var Index:TRNLSizeUInt;
    BlockPacket:TRNLPeerBlockPacket;
    IndirectBlockPacket:PRNLPeerBlockPacket;
begin

 DispatchOutgoingBlockPacketsTimeout;

 DispatchOutgoingAcknowledgementBlockPackets;

 DispatchOutgoingMessageBlockPackets;

 // Move local enqueued outgoing block packets into the peer global outgoing block packet queue
 // as much as possible in a single straight row.
 // This intermediate step is necessary in order to be able to keep the acknowledgement and
 // sent window sizes, so that the receiver side will not be spammed with too much
 // window-size-technical-early packets.
 for Index:=1 to fHost.fReliableChannelBlockPacketWindowSize-
                  (((fOutgoingBlockPacketSequenceNumber+fHost.fReliableChannelBlockPacketWindowSize)-
                    fIncomingAcknowledgementSequenceNumber) and
                   fHost.fReliableChannelBlockPacketWindowMask) do begin
  IndirectBlockPacket:=@fOutgoingBlockPackets[fOutgoingBlockPacketSequenceNumber.fValue and fHost.fReliableChannelBlockPacketWindowMask];
  if (not assigned(IndirectBlockPacket^)) and
     fOutgoingBlockPacketQueue.Peek(BlockPacket) and
     (TRNLUInt16(BlockPacket.fSequenceNumber)=fOutgoingBlockPacketSequenceNumber) then begin
   try
    IndirectBlockPacket^:=BlockPacket;
    BlockPacket.fPendingResendOutgoingBlockPacketsList:=fSentOutgoingBlockPackets;
    fPeer.fOutgoingBlockPackets.Enqueue(BlockPacket);
   finally
    fOutgoingBlockPacketQueue.Dequeue;
   end;
   inc(fOutgoingBlockPacketSequenceNumber);
  end else begin
   break;
  end;
 end;

end;

procedure TRNLPeerReliableChannel.DispatchIncomingBlockPacketAcknowledgement(const aBlockPacketSequenceNumber:TRNLSequenceNumber;const aBlockPacketReceivedTime:TRNLTime);
var IndirectBlockPacket:PRNLPeerBlockPacket;
    Acknowledgement:PRNLPeerReliableChannelAcknowledgement;
begin

 if (aBlockPacketSequenceNumber>=fIncomingAcknowledgementSequenceNumber) and
    (aBlockPacketSequenceNumber<=fOutgoingBlockPacketSequenceNumber) then begin

  // Dispatch received block packet acknowledgement
  if fIncomingAcknowledgements[aBlockPacketSequenceNumber.fValue and fHost.fReliableChannelBlockPacketWindowMask]<0 then begin
   IndirectBlockPacket:=@fOutgoingBlockPackets[aBlockPacketSequenceNumber.fValue and fHost.fReliableChannelBlockPacketWindowMask];
   if assigned(IndirectBlockPacket^) and
      (IndirectBlockPacket^.fSequenceNumber.fValue=aBlockPacketSequenceNumber.fValue) then begin
    try
     fIncomingAcknowledgements[aBlockPacketSequenceNumber.fValue and fHost.fReliableChannelBlockPacketWindowMask]:=fIncomingAcknowledgementSequenceNumber.fValue;
     fPeer.UpdateRoundTripTime(abs(TRNLInt16(TRNLUInt16(IndirectBlockPacket^.fSentTime.fValue-aBlockPacketReceivedTime.fValue))));
     dec(fPeer.fUnacknowlegmentedBlockPackets);
     IndirectBlockPacket^.Remove;
    finally
     IndirectBlockPacket^.DecRef;
     IndirectBlockPacket^:=nil;
    end;
   end;
  end;

  // Catch up so many received block packet acknowledgement sequence numbers as much as possible in a single straight row
  repeat
   Acknowledgement:=@fIncomingAcknowledgements[fIncomingAcknowledgementSequenceNumber.fValue and fHost.fReliableChannelBlockPacketWindowMask];
   if Acknowledgement^=fIncomingAcknowledgementSequenceNumber.fValue then begin
    Acknowledgement^:=-1;
    inc(fIncomingAcknowledgementSequenceNumber.fValue);
   end else begin
    break;
   end;
  until false;

 end;

end;

procedure TRNLPeerReliableChannel.DispatchIncomingAcknowledgementsBlockPacket(const aBlockPacket:TRNLPeerBlockPacket);
var BlockPacketDataPosition,AcknowledgementBits,AcknowledgementBitIndex:TRNLSizeUInt;
    BlockPacketSequenceNumber:TRNLSequenceNumber;
begin
 BlockPacketSequenceNumber:=TRNLEndianness.LittleEndianToHost16(PRNLPeerReliableChannelPacketHeader(TRNLPointer(@aBlockPacket.fBlockPacketData[0]))^.SequenceNumber);
 BlockPacketDataPosition:=SizeOf(TRNLPeerReliableChannelAcknowledgementsPacketHeader);
 while BlockPacketDataPosition<aBlockPacket.fBlockPacketDataLength do begin
  AcknowledgementBits:=aBlockPacket.fBlockPacketData[BlockPacketDataPosition];
  while AcknowledgementBits<>0 do begin
   AcknowledgementBitIndex:={$ifdef fpc}BSFDWord{$else}RawBitScanForwardUInt32{$endif}(AcknowledgementBits);
   DispatchIncomingBlockPacketAcknowledgement(BlockPacketSequenceNumber+AcknowledgementBitIndex,aBlockPacket.fReceivedTime);
   AcknowledgementBits:=AcknowledgementBits and (AcknowledgementBits-1);
  end;
  inc(BlockPacketSequenceNumber.fValue,8);
  inc(BlockPacketDataPosition);
 end;
end;

procedure TRNLPeerReliableChannel.DispatchIncomingBlockPacket(const aBlockPacket:TRNLPeerBlockPacket);
var BlockPacketDataPosition:TRNLSizeUInt;
    BlockPacketSequenceNumber:TRNLSequenceNumber;
    RelativeSequenceNumber:TRNLInt32;
    PacketHeader:PRNLPeerReliableChannelPacketHeader;
    IndirectBlockPacket:PRNLPeerBlockPacket;
    ChannelCommandType:TRNLPeerReliableChannelCommandType;
begin

 BlockPacketDataPosition:=0;

 if (BlockPacketDataPosition+(SizeOf(TRNLPeerReliableChannelPacketHeader)-1))>=aBlockPacket.fBlockPacketDataLength then begin
  exit;
 end;

 PacketHeader:=TRNLPointer(@aBlockPacket.fBlockPacketData[BlockPacketDataPosition]);

 BlockPacketSequenceNumber:=TRNLEndianness.LittleEndianToHost16(PacketHeader^.SequenceNumber);

 ChannelCommandType:=TRNLPeerReliableChannelCommandType(TRNLInt32(aBlockPacket.fBlockPacket.Channel.Header.TypeAndSubtype shr 4));

 case ChannelCommandType of
  RNL_PEER_RELIABLE_CHANNEL_COMMAND_TYPE_SHORT_MESSAGE,
  RNL_PEER_RELIABLE_CHANNEL_COMMAND_TYPE_LONG_MESSAGE:begin

   // if < 0 then it's too late arrived or a duplicate packet => drop but send an acknowledgment
   // if = 0 then it's arrived in time => accept and send an acknowledgment
   // if > 0 and < WindowSize then it's too early, but not much too early arrived => accept with withheld for later and send an acknowledgment also already
   // if >= WindowSize then it's much too early arrived => drop and NOT send an acknowledgment, so the sender can send it again at a better time point, even if the sender can be missing-acknowledgment-resend-spamming us then in this case
   RelativeSequenceNumber:=TRNLSequenceNumber.RelativeDifference(BlockPacketSequenceNumber,
                                                                 fIncomingBlockPacketSequenceNumber);

   if RelativeSequenceNumber<TRNLSizeInt(fHost.fReliableChannelBlockPacketWindowSize) then begin

    if RelativeSequenceNumber>=0 then begin

     // Enqueue (and, if not ordered channel, dispatch) received block packet
     IndirectBlockPacket:=@fIncomingBlockPackets[BlockPacketSequenceNumber.fValue and fHost.fReliableChannelBlockPacketWindowMask];
     try
      if assigned(IndirectBlockPacket^) then begin
       try
        IndirectBlockPacket^.DecRef;
       finally
        IndirectBlockPacket^:=nil;
       end;
      end;
      aBlockPacket.fSequenceNumber:=BlockPacketSequenceNumber;
      IndirectBlockPacket^:=aBlockPacket;
      if not fOrdered then begin
       DispatchIncomingMessageBlockPacket(aBlockPacket);
       aBlockPacket.fBlockPacketData:=nil; // The actual block packet payload data are no more needed
       aBlockPacket.fBlockPacketDataLength:=0;
      end;
     finally
      IndirectBlockPacket^.IncRef;
     end;

     // Dequeue (and, if ordered channel, dispatch) so many received block packets as much as possible in a single straight row
     repeat
      IndirectBlockPacket:=@fIncomingBlockPackets[fIncomingBlockPacketSequenceNumber.fValue and fHost.fReliableChannelBlockPacketWindowMask];
      if assigned(IndirectBlockPacket^) and
         (IndirectBlockPacket^.fSequenceNumber.fValue=fIncomingBlockPacketSequenceNumber.fValue) then begin
       try
        if fOrdered then begin
         DispatchIncomingMessageBlockPacket(IndirectBlockPacket^);
        end;
        inc(fIncomingBlockPacketSequenceNumber.fValue);
       finally
        IndirectBlockPacket^.DecRef;
        IndirectBlockPacket^:=nil;
       end;
      end else begin
       break;
      end;
     until false;

    end;

    // Queue outgoing acknowledgement if needed
    fOutgoingAcknowledgementQueue.Enqueue(BlockPacketSequenceNumber);

   end;

  end;

  RNL_PEER_RELIABLE_CHANNEL_COMMAND_TYPE_ACKNOWLEDGEMENT:begin

   DispatchIncomingBlockPacketAcknowledgement(BlockPacketSequenceNumber,aBlockPacket.fReceivedTime);

  end;

  RNL_PEER_RELIABLE_CHANNEL_COMMAND_TYPE_ACKNOWLEDGEMENTS:begin

   DispatchIncomingAcknowledgementsBlockPacket(aBlockPacket);

  end;

 end;

end;

constructor TRNLPeerReliableOrderedChannel.Create(const aPeer:TRNLPeer;const aChannelNumber:TRNLUInt16);
begin

 inherited Create(aPeer,aChannelNumber);

 fOrdered:=true;

 fOutgoingMessageBlockPacketSequenceNumber:=0;

 fOutgoingMessageNumber:=0;

 fIncomingMessageNumber:=$ffff;

 fIncomingMessageLength:=0;

 fIncomingMessageReceiveBufferData:=nil;

end;

destructor TRNLPeerReliableOrderedChannel.Destroy;
begin

 fIncomingMessageReceiveBufferData:=nil;

 inherited Destroy;

end;

procedure TRNLPeerReliableOrderedChannel.DispatchOutgoingMessageBlockPackets;
var Message:TRNLMessage;
    MaximumShortMessageBlockPacketSize,
    MaximumLongMessageBlockPacketSize,
    MessagePartLength,
    MessagePosition:TRNLSizeUInt;
    BlockPacket:TRNLPeerBlockPacket;
    ShortMessagePacketHeader:PRNLPeerReliableChannelShortMessagePacketHeader;
    LongMessagePacketHeader:PRNLPeerReliableChannelLongMessagePacketHeader;
begin

 // Dispatch outgoing enqueued messages to outgoing short and long message (fragment) block packets

 if fOutgoingMessageQueue.IsEmpty then begin
  exit;
 end;

 MaximumShortMessageBlockPacketSize:=fPeer.fMTU-(RNL_IP_HEADER_SIZE+
                                                 RNL_UDP_HEADER_SIZE+
                                                 SizeOf(TRNLProtocolNormalPacketHeader)+
                                                 SizeOf(TRNLProtocolBlockPacketChannel)+
                                                 SizeOf(TRNLPeerReliableChannelShortMessagePacketHeader));

 MaximumLongMessageBlockPacketSize:=fPeer.fMTU-(RNL_IP_HEADER_SIZE+
                                                RNL_UDP_HEADER_SIZE+
                                                SizeOf(TRNLProtocolNormalPacketHeader)+
                                                SizeOf(TRNLProtocolBlockPacketChannel)+
                                                SizeOf(TRNLPeerReliableChannelLongMessagePacketHeader));

 while fOutgoingMessageQueue.Dequeue(Message) do begin

  try

   if Message.fDataLength>0 then begin

    if Message.fDataLength<=MaximumShortMessageBlockPacketSize then begin

     BlockPacket:=TRNLPeerBlockPacket.Create(fPeer);
     try

      BlockPacket.fBlockPacket.Channel.Header.TypeAndSubtype:=(TRNLInt32(TRNLProtocolBlockPacketType(RNL_PROTOCOL_BLOCK_PACKET_TYPE_CHANNEL)) shl 0) or
                                                              (TRNLInt32(TRNLPeerReliableChannelCommandType(RNL_PEER_RELIABLE_CHANNEL_COMMAND_TYPE_SHORT_MESSAGE)) shl 4);
      BlockPacket.fBlockPacket.Channel.ChannelNumber:=fChannelNumber;
      BlockPacket.fBlockPacket.Channel.PayloadDataLength:=TRNLEndianness.HostToLittleEndian16(SizeOf(TRNLPeerReliableChannelShortMessagePacketHeader)+Message.fDataLength);

      BlockPacket.fBlockPacketDataLength:=SizeOf(TRNLPeerReliableChannelShortMessagePacketHeader)+Message.fDataLength;

      SetLength(BlockPacket.fBlockPacketData,BlockPacket.fBlockPacketDataLength);

      ShortMessagePacketHeader:=TRNLPointer(@BlockPacket.fBlockPacketData[0]);
      ShortMessagePacketHeader^.Header.SequenceNumber:=TRNLEndianness.HostToLittleEndian16(fOutgoingMessageBlockPacketSequenceNumber);

      Move(Message.fData^,
           BlockPacket.fBlockPacketData[SizeOf(TRNLPeerReliableChannelShortMessagePacketHeader)],
           Message.fDataLength);

      BlockPacket.fSequenceNumber:=fOutgoingMessageBlockPacketSequenceNumber;

      inc(fOutgoingMessageBlockPacketSequenceNumber);

      inc(fPeer.fUnacknowlegmentedBlockPackets);

     finally
      fOutgoingBlockPacketQueue.Enqueue(BlockPacket);
     end;

    end else begin

     MessagePosition:=0;
     while MessagePosition<Message.fDataLength do begin

      MessagePartLength:=Min(Max(TRNLInt64(Message.fDataLength-MessagePosition),TRNLInt64(1)),TRNLInt64(MaximumLongMessageBlockPacketSize));

      BlockPacket:=TRNLPeerBlockPacket.Create(fPeer);
      try

       BlockPacket.fBlockPacket.Channel.Header.TypeAndSubtype:=(TRNLInt32(TRNLProtocolBlockPacketType(RNL_PROTOCOL_BLOCK_PACKET_TYPE_CHANNEL)) shl 0) or
                                                               (TRNLInt32(TRNLPeerReliableChannelCommandType(RNL_PEER_RELIABLE_CHANNEL_COMMAND_TYPE_LONG_MESSAGE)) shl 4);
       BlockPacket.fBlockPacket.Channel.ChannelNumber:=fChannelNumber;
       BlockPacket.fBlockPacket.Channel.PayloadDataLength:=TRNLEndianness.HostToLittleEndian16(SizeOf(TRNLPeerReliableChannelLongMessagePacketHeader)+MessagePartLength);

       BlockPacket.fBlockPacketDataLength:=SizeOf(TRNLPeerReliableChannelLongMessagePacketHeader)+MessagePartLength;

       SetLength(BlockPacket.fBlockPacketData,BlockPacket.fBlockPacketDataLength);

       LongMessagePacketHeader:=TRNLPointer(@BlockPacket.fBlockPacketData[0]);
       LongMessagePacketHeader^.Header.SequenceNumber:=TRNLEndianness.HostToLittleEndian16(fOutgoingMessageBlockPacketSequenceNumber);
       LongMessagePacketHeader^.MessageNumber:=TRNLEndianness.HostToLittleEndian16(fOutgoingMessageNumber);
       LongMessagePacketHeader^.Offset:=TRNLEndianness.HostToLittleEndian32(MessagePosition);
       LongMessagePacketHeader^.Length:=TRNLEndianness.HostToLittleEndian32(Message.fDataLength);

       Move(PRNLUInt8Array(TRNLPointer(Message.fData))^[MessagePosition],
            BlockPacket.fBlockPacketData[SizeOf(TRNLPeerReliableChannelLongMessagePacketHeader)],
            MessagePartLength);

       BlockPacket.fSequenceNumber:=fOutgoingMessageBlockPacketSequenceNumber;

       inc(fOutgoingMessageBlockPacketSequenceNumber);

       inc(fPeer.fUnacknowlegmentedBlockPackets);

      finally
       fOutgoingBlockPacketQueue.Enqueue(BlockPacket);
      end;

      inc(MessagePosition,MessagePartLength);

     end;

     inc(fOutgoingMessageNumber);

    end;

   end;

  finally
   Message.DecRef;
  end;

 end;

end;

procedure TRNLPeerReliableOrderedChannel.DispatchIncomingMessageBlockPacket(const aBlockPacket:TRNLPeerBlockPacket);
var ChannelCommandType:TRNLPeerReliableChannelCommandType;
    BlockPacketDataPosition,BlockDataLength,FragmentOffset:TRNLSizeUInt;
    LongMessagePacketHeader:PRNLPeerReliableChannelLongMessagePacketHeader;
begin

 BlockPacketDataPosition:=0;

 ChannelCommandType:=TRNLPeerReliableChannelCommandType(TRNLInt32(aBlockPacket.fBlockPacket.Channel.Header.TypeAndSubtype shr 4));

 case ChannelCommandType of

  RNL_PEER_RELIABLE_CHANNEL_COMMAND_TYPE_SHORT_MESSAGE:begin

   fIncomingMessageLength:=0;
   if assigned(fIncomingMessageReceiveBufferData) then begin
    FreeMem(fIncomingMessageReceiveBufferData);
    fIncomingMessageReceiveBufferData:=nil;
   end;

   if (BlockPacketDataPosition+(SizeOf(TRNLPeerReliableChannelShortMessagePacketHeader)-1))>=aBlockPacket.fBlockPacketDataLength then begin
    exit;
   end;

   BlockPacketDataPosition:=SizeOf(TRNLPeerReliableChannelShortMessagePacketHeader);
   BlockDataLength:=aBlockPacket.fBlockPacketDataLength-BlockPacketDataPosition;

   if (BlockPacketDataPosition+BlockDataLength)>aBlockPacket.fBlockPacketDataLength then begin
    exit;
   end;

   fIncomingMessageQueue.Enqueue(TRNLMessage.CreateFromMemory(TRNLPointer(@aBlockPacket.fBlockPacketData[BlockPacketDataPosition]),
                                                              BlockDataLength,
                                                              []));

  end;

  RNL_PEER_RELIABLE_CHANNEL_COMMAND_TYPE_LONG_MESSAGE:begin

   if (BlockPacketDataPosition+(SizeOf(TRNLPeerReliableChannelLongMessagePacketHeader)-1))>=aBlockPacket.fBlockPacketDataLength then begin
    fIncomingMessageLength:=0;
    if assigned(fIncomingMessageReceiveBufferData) then begin
     FreeMem(fIncomingMessageReceiveBufferData);
     fIncomingMessageReceiveBufferData:=nil;
    end;
    exit;
   end;

   LongMessagePacketHeader:=TRNLPointer(@aBlockPacket.fBlockPacketData[BlockPacketDataPosition]);

   LongMessagePacketHeader^.MessageNumber:=TRNLEndianness.LittleEndianToHost16(LongMessagePacketHeader^.MessageNumber);
   LongMessagePacketHeader^.Offset:=TRNLEndianness.LittleEndianToHost32(LongMessagePacketHeader^.Offset);
   LongMessagePacketHeader^.Length:=TRNLEndianness.LittleEndianToHost32(LongMessagePacketHeader^.Length);

   if LongMessagePacketHeader^.Offset=0 then begin

    fIncomingMessageNumber:=LongMessagePacketHeader^.MessageNumber;

    fIncomingReceivedMessageDataLength:=0;

    fIncomingMessageLength:=LongMessagePacketHeader^.Length;

    if assigned(fIncomingMessageReceiveBufferData) then begin
     FreeMem(fIncomingMessageReceiveBufferData);
     fIncomingMessageReceiveBufferData:=nil;
    end;

    GetMem(fIncomingMessageReceiveBufferData,LongMessagePacketHeader^.Length);

   end else begin

    if (fIncomingMessageNumber<>LongMessagePacketHeader^.MessageNumber) or
       (not assigned(fIncomingMessageReceiveBufferData)) or
       (fIncomingMessageLength<>LongMessagePacketHeader^.Length) then begin
     // Reject
     fIncomingMessageLength:=0;
     if assigned(fIncomingMessageReceiveBufferData) then begin
      FreeMem(fIncomingMessageReceiveBufferData);
      fIncomingMessageReceiveBufferData:=nil;
     end;
     exit;
    end;

   end;

   if not assigned(fIncomingMessageReceiveBufferData) then begin
    fIncomingReceivedMessageDataLength:=0;
   end;

   BlockPacketDataPosition:=SizeOf(TRNLPeerReliableChannelLongMessagePacketHeader);
   BlockDataLength:=aBlockPacket.fBlockPacketDataLength-BlockPacketDataPosition;

   if (BlockPacketDataPosition+BlockDataLength)>aBlockPacket.fBlockPacketDataLength then begin
    fIncomingMessageLength:=0;
    if assigned(fIncomingMessageReceiveBufferData) then begin
     FreeMem(fIncomingMessageReceiveBufferData);
     fIncomingMessageReceiveBufferData:=nil;
    end;
    exit;
   end;

   FragmentOffset:=LongMessagePacketHeader^.Offset;

   if (FragmentOffset+BlockDataLength)>fIncomingMessageLength then begin
    fIncomingMessageLength:=0;
    if assigned(fIncomingMessageReceiveBufferData) then begin
     FreeMem(fIncomingMessageReceiveBufferData);
     fIncomingMessageReceiveBufferData:=nil;
    end;
    exit;
   end;

   Move(aBlockPacket.fBlockPacketData[BlockPacketDataPosition],
        PRNLUInt8Array(TRNLPointer(fIncomingMessageReceiveBufferData))^[FragmentOffset],
        BlockDataLength);

   inc(fIncomingReceivedMessageDataLength,BlockDataLength);

   if fIncomingReceivedMessageDataLength=fIncomingMessageLength then begin
    fIncomingMessageQueue.Enqueue(TRNLMessage.CreateFromMemory(fIncomingMessageReceiveBufferData,
                                                               fIncomingMessageLength,
                                                               [RNL_MESSAGE_FLAG_NO_ALLOCATE]));
    fIncomingMessageLength:=0;
    fIncomingMessageReceiveBufferData:=nil;
   end;

  end;

  else begin

   fIncomingMessageLength:=0;
   if assigned(fIncomingMessageReceiveBufferData) then begin
    FreeMem(fIncomingMessageReceiveBufferData);
    fIncomingMessageReceiveBufferData:=nil;
   end;

  end;

 end;

end;

constructor TRNLPeerReliableUnorderedChannelLongMessage.Create(const aChannel:TRNLPeerReliableUnorderedChannel;const aMessageNumber,aMessageLength:TRNLUInt32);
begin

 inherited Create;

 fValue:=self;

 fChannel:=aChannel;

 fMessageNumber:=aMessageNumber;

 fIncomingMessageLength:=aMessageLength;

 fIncomingReceivedMessageDataLength:=0;

 fIncomingMessageReceiveBufferData:=nil;
 GetMem(fIncomingMessageReceiveBufferData,fIncomingMessageLength);
 FillChar(fIncomingMessageReceiveBufferData^,fIncomingMessageLength,#0);

 fIncomingMessageReceiveBufferFlagData:=nil;
 GetMem(fIncomingMessageReceiveBufferFlagData,fIncomingMessageLength);
 FillChar(fIncomingMessageReceiveBufferFlagData^,fIncomingMessageLength,#0);

end;

destructor TRNLPeerReliableUnorderedChannelLongMessage.Destroy;
begin

 if assigned(fIncomingMessageReceiveBufferData) then begin
  FreeMem(fIncomingMessageReceiveBufferData);
  fIncomingMessageReceiveBufferData:=nil;
 end;

 if assigned(fIncomingMessageReceiveBufferFlagData) then begin
  FreeMem(fIncomingMessageReceiveBufferFlagData);
  fIncomingMessageReceiveBufferFlagData:=nil;
 end;

 inherited Destroy;

end;

procedure TRNLPeerReliableUnorderedChannelLongMessage.DispatchIncomingData(const aOffset,aLength:TRNLUInt32;const aData:TRNLPointer);
var Index:TRNLSizeUInt;
begin

 if aLength=0 then begin
  exit;
 end;

 if (aOffset+aLength)>fIncomingMessageLength then begin
  Free;
  exit;
 end;

 for Index:=aOffset to aOffset+(aLength-1) do begin
  if PRNLUInt8Array(TRNLPointer(fIncomingMessageReceiveBufferFlagData))^[Index]<>0 then begin
   Free;
   exit;
  end;
 end;

 FillChar(PRNLUInt8Array(TRNLPointer(fIncomingMessageReceiveBufferFlagData))^[aOffset],
          aLength,
          #$ff);

 System.Move(aData^,
             PRNLUInt8Array(TRNLPointer(fIncomingMessageReceiveBufferData))^[aOffset],
             aLength);

 inc(fIncomingReceivedMessageDataLength,aLength);

 if fIncomingReceivedMessageDataLength=fIncomingMessageLength then begin
  fChannel.fIncomingMessageQueue.Enqueue(TRNLMessage.CreateFromMemory(fIncomingMessageReceiveBufferData,
                                                                      fIncomingMessageLength,
                                                                      [RNL_MESSAGE_FLAG_NO_ALLOCATE]));
  fIncomingMessageLength:=0;
  fIncomingMessageReceiveBufferData:=nil;
  Free;
  exit;
 end;

end;

constructor TRNLPeerReliableUnorderedChannel.Create(const aPeer:TRNLPeer;const aChannelNumber:TRNLUInt16);
begin

 inherited Create(aPeer,aChannelNumber);

 fOrdered:=false;

 fIncomingLongMessages:=TRNLPeerReliableUnorderedChannelLongMessageListNode.Create;
 fIncomingLongMessages.fValue:=nil;

 fOutgoingMessageBlockPacketSequenceNumber:=0;

 fOutgoingMessageNumber:=0;

end;

destructor TRNLPeerReliableUnorderedChannel.Destroy;
begin

 while not fIncomingLongMessages.Empty do begin
  fIncomingLongMessages.Front.Value.Free;
 end;

 FreeAndNil(fIncomingLongMessages);

 inherited Destroy;

end;

procedure TRNLPeerReliableUnorderedChannel.DispatchOutgoingMessageBlockPackets;
var Message:TRNLMessage;
    MaximumShortMessageBlockPacketSize,
    MaximumLongMessageBlockPacketSize,
    MessagePartLength,
    MessagePosition:TRNLSizeUInt;
    BlockPacket:TRNLPeerBlockPacket;
    ShortMessagePacketHeader:PRNLPeerReliableChannelShortMessagePacketHeader;
    LongMessagePacketHeader:PRNLPeerReliableChannelLongMessagePacketHeader;
begin

 // Dispatch outgoing enqueued messages to outgoing short and long message (fragment) block packets

 if fOutgoingMessageQueue.IsEmpty then begin
  exit;
 end;

 MaximumShortMessageBlockPacketSize:=fPeer.fMTU-(RNL_IP_HEADER_SIZE+
                                                 RNL_UDP_HEADER_SIZE+
                                                 SizeOf(TRNLProtocolNormalPacketHeader)+
                                                 SizeOf(TRNLProtocolBlockPacketChannel)+
                                                 SizeOf(TRNLPeerReliableChannelShortMessagePacketHeader));

 MaximumLongMessageBlockPacketSize:=fPeer.fMTU-(RNL_IP_HEADER_SIZE+
                                                RNL_UDP_HEADER_SIZE+
                                                SizeOf(TRNLProtocolNormalPacketHeader)+
                                                SizeOf(TRNLProtocolBlockPacketChannel)+
                                                SizeOf(TRNLPeerReliableChannelLongMessagePacketHeader));

 while fOutgoingMessageQueue.Dequeue(Message) do begin

  try

   if Message.fDataLength>0 then begin

    if Message.fDataLength<=MaximumShortMessageBlockPacketSize then begin

     BlockPacket:=TRNLPeerBlockPacket.Create(fPeer);
     try

      BlockPacket.fBlockPacket.Channel.Header.TypeAndSubtype:=(TRNLInt32(TRNLProtocolBlockPacketType(RNL_PROTOCOL_BLOCK_PACKET_TYPE_CHANNEL)) shl 0) or
                                                              (TRNLInt32(TRNLPeerReliableChannelCommandType(RNL_PEER_RELIABLE_CHANNEL_COMMAND_TYPE_SHORT_MESSAGE)) shl 4);
      BlockPacket.fBlockPacket.Channel.ChannelNumber:=fChannelNumber;
      BlockPacket.fBlockPacket.Channel.PayloadDataLength:=TRNLEndianness.HostToLittleEndian16(SizeOf(TRNLPeerReliableChannelShortMessagePacketHeader)+Message.fDataLength);

      BlockPacket.fBlockPacketDataLength:=SizeOf(TRNLPeerReliableChannelShortMessagePacketHeader)+Message.fDataLength;

      SetLength(BlockPacket.fBlockPacketData,BlockPacket.fBlockPacketDataLength);

      ShortMessagePacketHeader:=TRNLPointer(@BlockPacket.fBlockPacketData[0]);
      ShortMessagePacketHeader^.Header.SequenceNumber:=TRNLEndianness.HostToLittleEndian16(fOutgoingMessageBlockPacketSequenceNumber);

      Move(Message.fData^,
           BlockPacket.fBlockPacketData[SizeOf(TRNLPeerReliableChannelShortMessagePacketHeader)],
           Message.fDataLength);

      BlockPacket.fSequenceNumber:=fOutgoingMessageBlockPacketSequenceNumber;

      inc(fOutgoingMessageBlockPacketSequenceNumber);

      inc(fPeer.fUnacknowlegmentedBlockPackets);

     finally
      fOutgoingBlockPacketQueue.Enqueue(BlockPacket);
     end;

    end else begin

     MessagePosition:=0;
     while MessagePosition<Message.fDataLength do begin

      MessagePartLength:=Min(Max(TRNLInt64(Message.fDataLength-MessagePosition),TRNLInt64(1)),TRNLInt64(MaximumLongMessageBlockPacketSize));

      BlockPacket:=TRNLPeerBlockPacket.Create(fPeer);
      try

       BlockPacket.fBlockPacket.Channel.Header.TypeAndSubtype:=(TRNLInt32(TRNLProtocolBlockPacketType(RNL_PROTOCOL_BLOCK_PACKET_TYPE_CHANNEL)) shl 0) or
                                                               (TRNLInt32(TRNLPeerReliableChannelCommandType(RNL_PEER_RELIABLE_CHANNEL_COMMAND_TYPE_LONG_MESSAGE)) shl 4);
       BlockPacket.fBlockPacket.Channel.ChannelNumber:=fChannelNumber;
       BlockPacket.fBlockPacket.Channel.PayloadDataLength:=TRNLEndianness.HostToLittleEndian16(SizeOf(TRNLPeerReliableChannelLongMessagePacketHeader)+MessagePartLength);

       BlockPacket.fBlockPacketDataLength:=SizeOf(TRNLPeerReliableChannelLongMessagePacketHeader)+MessagePartLength;

       SetLength(BlockPacket.fBlockPacketData,BlockPacket.fBlockPacketDataLength);

       LongMessagePacketHeader:=TRNLPointer(@BlockPacket.fBlockPacketData[0]);
       LongMessagePacketHeader^.Header.SequenceNumber:=TRNLEndianness.HostToLittleEndian16(fOutgoingMessageBlockPacketSequenceNumber);
       LongMessagePacketHeader^.MessageNumber:=TRNLEndianness.HostToLittleEndian16(fOutgoingMessageNumber);
       LongMessagePacketHeader^.Offset:=TRNLEndianness.HostToLittleEndian32(MessagePosition);
       LongMessagePacketHeader^.Length:=TRNLEndianness.HostToLittleEndian32(Message.fDataLength);

       Move(PRNLUInt8Array(TRNLPointer(Message.fData))^[MessagePosition],
            BlockPacket.fBlockPacketData[SizeOf(TRNLPeerReliableChannelLongMessagePacketHeader)],
            MessagePartLength);

       BlockPacket.fSequenceNumber:=fOutgoingMessageBlockPacketSequenceNumber;

       inc(fOutgoingMessageBlockPacketSequenceNumber);

       inc(fPeer.fUnacknowlegmentedBlockPackets);

      finally
       fOutgoingBlockPacketQueue.Enqueue(BlockPacket);
      end;

      inc(MessagePosition,MessagePartLength);

     end;

     inc(fOutgoingMessageNumber);

    end;

   end;

  finally
   Message.DecRef;
  end;

 end;

end;

procedure TRNLPeerReliableUnorderedChannel.DispatchIncomingMessageBlockPacket(const aBlockPacket:TRNLPeerBlockPacket);
var ChannelCommandType:TRNLPeerReliableChannelCommandType;
    BlockPacketDataPosition,BlockDataLength:TRNLSizeUInt;
    LongMessagePacketHeader:PRNLPeerReliableChannelLongMessagePacketHeader;
    CurrentLongMessageListNode,NextLongMessageListNode:TRNLPeerReliableUnorderedChannelLongMessageListNode;
    LongMessage:TRNLPeerReliableUnorderedChannelLongMessage;
begin

 BlockPacketDataPosition:=0;

 ChannelCommandType:=TRNLPeerReliableChannelCommandType(TRNLInt32(aBlockPacket.fBlockPacket.Channel.Header.TypeAndSubtype shr 4));

 case ChannelCommandType of

  RNL_PEER_RELIABLE_CHANNEL_COMMAND_TYPE_SHORT_MESSAGE:begin

   if (BlockPacketDataPosition+(SizeOf(TRNLPeerReliableChannelShortMessagePacketHeader)-1))>=aBlockPacket.fBlockPacketDataLength then begin
    exit;
   end;

   BlockPacketDataPosition:=SizeOf(TRNLPeerReliableChannelShortMessagePacketHeader);
   BlockDataLength:=aBlockPacket.fBlockPacketDataLength-BlockPacketDataPosition;

   if (BlockPacketDataPosition+BlockDataLength)>aBlockPacket.fBlockPacketDataLength then begin
    exit;
   end;

   fIncomingMessageQueue.Enqueue(TRNLMessage.CreateFromMemory(TRNLPointer(@aBlockPacket.fBlockPacketData[BlockPacketDataPosition]),
                                                              BlockDataLength,
                                                              []));

  end;

  RNL_PEER_RELIABLE_CHANNEL_COMMAND_TYPE_LONG_MESSAGE:begin

   if (BlockPacketDataPosition+(SizeOf(TRNLPeerReliableChannelLongMessagePacketHeader)-1))>=aBlockPacket.fBlockPacketDataLength then begin
    exit;
   end;

   LongMessagePacketHeader:=TRNLPointer(@aBlockPacket.fBlockPacketData[BlockPacketDataPosition]);

   LongMessagePacketHeader^.MessageNumber:=TRNLEndianness.LittleEndianToHost16(LongMessagePacketHeader^.MessageNumber);
   LongMessagePacketHeader^.Offset:=TRNLEndianness.LittleEndianToHost32(LongMessagePacketHeader^.Offset);
   LongMessagePacketHeader^.Length:=TRNLEndianness.LittleEndianToHost32(LongMessagePacketHeader^.Length);

   BlockPacketDataPosition:=SizeOf(TRNLPeerReliableChannelLongMessagePacketHeader);
   BlockDataLength:=aBlockPacket.fBlockPacketDataLength-BlockPacketDataPosition;

   if (BlockPacketDataPosition+BlockDataLength)>aBlockPacket.fBlockPacketDataLength then begin
    exit;
   end;

   LongMessage:=nil;

   CurrentLongMessageListNode:=fIncomingLongMessages.Front;
   while CurrentLongMessageListNode<>fIncomingLongMessages do begin
    NextLongMessageListNode:=CurrentLongMessageListNode.fNext;
    try
     if assigned(CurrentLongMessageListNode.fValue) and
        (CurrentLongMessageListNode.fValue.fMessageNumber=LongMessagePacketHeader^.MessageNumber) then begin
      LongMessage:=CurrentLongMessageListNode.fValue;
      break;
     end;
    finally
     CurrentLongMessageListNode:=NextLongMessageListNode;
    end;
   end;

   if not assigned(LongMessage) then begin
    LongMessage:=TRNLPeerReliableUnorderedChannelLongMessage.Create(self,
                                                                    LongMessagePacketHeader^.MessageNumber,
                                                                    LongMessagePacketHeader^.Length);
    fIncomingLongMessages.Add(LongMessage);
   end;

   LongMessage.DispatchIncomingData(LongMessagePacketHeader^.Offset,
                                    BlockDataLength,
                                    @aBlockPacket.fBlockPacketData[BlockPacketDataPosition]);

  end;

 end;

end;

constructor TRNLPeerUnreliableOrderedChannel.Create(const aPeer:TRNLPeer;const aChannelNumber:TRNLUInt16);
begin
 inherited Create(aPeer,aChannelNumber);
 fIncomingSequenceNumber:=$ffff;
 fIncomingMessageNumber:=$ffff;
 fIncomingMessageLength:=0;
 fIncomingMessageReceiveBufferData:=nil;
 fOutgoingSequenceNumber:=0;
 fOutgoingMessageNumber:=0;
end;

destructor TRNLPeerUnreliableOrderedChannel.Destroy;
begin
 if assigned(fIncomingMessageReceiveBufferData) then begin
  FreeMem(fIncomingMessageReceiveBufferData);
  fIncomingMessageReceiveBufferData:=nil;
 end;
 inherited Destroy;
end;

function TRNLPeerUnreliableOrderedChannel.GetMaximumUnfragmentedMessageSize:TRNLSizeUInt;
begin
 result:=fPeer.fMTU-(RNL_IP_HEADER_SIZE+
                     RNL_UDP_HEADER_SIZE+
                     SizeOf(TRNLProtocolNormalPacketHeader)+
                     SizeOf(TRNLProtocolBlockPacketChannel)+
                     SizeOf(TRNLPeerUnreliableOrderedChannelShortMessagePacketHeader));
end;

procedure TRNLPeerUnreliableOrderedChannel.DispatchOutgoingBlockPackets;
var Message:TRNLMessage;
    MaximumShortMessageBlockPacketSize,
    MaximumLongMessageBlockPacketSize,
    MessagePartLength,
    MessagePosition:TRNLSizeUInt;
    BlockPacket:TRNLPeerBlockPacket;
    ShortMessagePacketHeader:PRNLPeerUnreliableOrderedChannelShortMessagePacketHeader;
    LongMessagePacketHeader:PRNLPeerUnreliableOrderedChannelLongMessagePacketHeader;
begin

 if fOutgoingMessageQueue.IsEmpty then begin
  exit;
 end;

 MaximumShortMessageBlockPacketSize:=fPeer.fMTU-(RNL_IP_HEADER_SIZE+
                                                 RNL_UDP_HEADER_SIZE+
                                                 SizeOf(TRNLProtocolNormalPacketHeader)+
                                                 SizeOf(TRNLProtocolBlockPacketChannel)+
                                                 SizeOf(TRNLPeerUnreliableOrderedChannelShortMessagePacketHeader));

 MaximumLongMessageBlockPacketSize:=fPeer.fMTU-(RNL_IP_HEADER_SIZE+
                                                RNL_UDP_HEADER_SIZE+
                                                SizeOf(TRNLProtocolNormalPacketHeader)+
                                                SizeOf(TRNLProtocolBlockPacketChannel)+
                                                SizeOf(TRNLPeerUnreliableOrderedChannelLongMessagePacketHeader));

 while fOutgoingMessageQueue.Dequeue(Message) do begin

  try

   if Message.fDataLength>0 then begin

    if Message.fDataLength<=MaximumShortMessageBlockPacketSize then begin

     BlockPacket:=TRNLPeerBlockPacket.Create(fPeer);
     try

      BlockPacket.fBlockPacket.Channel.Header.TypeAndSubtype:=(TRNLInt32(TRNLProtocolBlockPacketType(RNL_PROTOCOL_BLOCK_PACKET_TYPE_CHANNEL)) shl 0) or
                                                              (TRNLInt32(TRNLPeerUnreliableOrderedChannelCommandType(RNL_PEER_UNRELIABLE_ORDERED_CHANNEL_COMMAND_TYPE_SHORT_MESSAGE)) shl 4);
      BlockPacket.fBlockPacket.Channel.ChannelNumber:=fChannelNumber;
      BlockPacket.fBlockPacket.Channel.PayloadDataLength:=TRNLEndianness.HostToLittleEndian16(SizeOf(TRNLPeerUnreliableOrderedChannelShortMessagePacketHeader)+Message.fDataLength);

      BlockPacket.fBlockPacketDataLength:=SizeOf(TRNLPeerUnreliableOrderedChannelShortMessagePacketHeader)+Message.fDataLength;

      SetLength(BlockPacket.fBlockPacketData,BlockPacket.fBlockPacketDataLength);

      ShortMessagePacketHeader:=TRNLPointer(@BlockPacket.fBlockPacketData[0]);
      ShortMessagePacketHeader^.SequenceNumber:=TRNLEndianness.HostToLittleEndian16(fOutgoingSequenceNumber);
      inc(fOutgoingSequenceNumber);

      Move(Message.fData^,
           BlockPacket.fBlockPacketData[SizeOf(TRNLPeerUnreliableOrderedChannelShortMessagePacketHeader)],
           Message.fDataLength);

     finally
      fPeer.fOutgoingBlockPackets.Enqueue(BlockPacket);
     end;

    end else begin

     MessagePosition:=0;
     while MessagePosition<Message.fDataLength do begin

      MessagePartLength:=Min(Max(TRNLInt64(Message.fDataLength-MessagePosition),TRNLInt64(1)),TRNLInt64(MaximumLongMessageBlockPacketSize));

      BlockPacket:=TRNLPeerBlockPacket.Create(fPeer);
      try

       BlockPacket.fBlockPacket.Channel.Header.TypeAndSubtype:=(TRNLInt32(TRNLProtocolBlockPacketType(RNL_PROTOCOL_BLOCK_PACKET_TYPE_CHANNEL)) shl 0) or
                                                               (TRNLInt32(TRNLPeerUnreliableOrderedChannelCommandType(RNL_PEER_UNRELIABLE_ORDERED_CHANNEL_COMMAND_TYPE_LONG_MESSAGE)) shl 4);
       BlockPacket.fBlockPacket.Channel.ChannelNumber:=fChannelNumber;
       BlockPacket.fBlockPacket.Channel.PayloadDataLength:=TRNLEndianness.HostToLittleEndian16(SizeOf(TRNLPeerUnreliableOrderedChannelLongMessagePacketHeader)+MessagePartLength);

       BlockPacket.fBlockPacketDataLength:=SizeOf(TRNLPeerUnreliableOrderedChannelLongMessagePacketHeader)+MessagePartLength;

       SetLength(BlockPacket.fBlockPacketData,BlockPacket.fBlockPacketDataLength);

       LongMessagePacketHeader:=TRNLPointer(@BlockPacket.fBlockPacketData[0]);
       LongMessagePacketHeader^.SequenceNumber:=TRNLEndianness.HostToLittleEndian16(fOutgoingSequenceNumber);
       LongMessagePacketHeader^.MessageNumber:=TRNLEndianness.HostToLittleEndian16(fOutgoingMessageNumber);
       LongMessagePacketHeader^.Offset:=TRNLEndianness.HostToLittleEndian32(MessagePosition);
       LongMessagePacketHeader^.Length:=TRNLEndianness.HostToLittleEndian32(Message.fDataLength);
       inc(fOutgoingSequenceNumber);

       Move(PRNLUInt8Array(TRNLPointer(Message.fData))^[MessagePosition],
            BlockPacket.fBlockPacketData[SizeOf(TRNLPeerUnreliableOrderedChannelLongMessagePacketHeader)],
            MessagePartLength);

      finally
       fPeer.fOutgoingBlockPackets.Enqueue(BlockPacket);
      end;

      inc(MessagePosition,MessagePartLength);

     end;

     inc(fOutgoingMessageNumber);

    end;

   end;

  finally
   Message.DecRef;
  end;

 end;

end;

procedure TRNLPeerUnreliableOrderedChannel.DispatchIncomingBlockPacket(const aBlockPacket:TRNLPeerBlockPacket);
var ChannelCommandType:TRNLPeerUnreliableOrderedChannelCommandType;
    BlockPacketDataPosition,BlockDataLength,FragmentOffset:TRNLSizeUInt;
    BlockSequenceNumber,LastSequenceNumber:TRNLSequenceNumber;
    ShortMessagePacketHeader:PRNLPeerUnreliableOrderedChannelShortMessagePacketHeader;
    LongMessagePacketHeader:PRNLPeerUnreliableOrderedChannelLongMessagePacketHeader;
begin

 BlockPacketDataPosition:=0;

 ChannelCommandType:=TRNLPeerUnreliableOrderedChannelCommandType(TRNLInt32(aBlockPacket.fBlockPacket.Channel.Header.TypeAndSubtype shr 4));

 case ChannelCommandType of

  RNL_PEER_UNRELIABLE_ORDERED_CHANNEL_COMMAND_TYPE_SHORT_MESSAGE:begin

   fIncomingMessageLength:=0;
   if assigned(fIncomingMessageReceiveBufferData) then begin
    FreeMem(fIncomingMessageReceiveBufferData);
    fIncomingMessageReceiveBufferData:=nil;
   end;

   if (BlockPacketDataPosition+(SizeOf(TRNLPeerUnreliableOrderedChannelShortMessagePacketHeader)-1))>=aBlockPacket.fBlockPacketDataLength then begin
    exit;
   end;

   ShortMessagePacketHeader:=TRNLPointer(@aBlockPacket.fBlockPacketData[BlockPacketDataPosition]);

   BlockSequenceNumber:=TRNLEndianness.LittleEndianToHost16(ShortMessagePacketHeader^.SequenceNumber);

   if fIncomingSequenceNumber>=BlockSequenceNumber then begin
    // Reject, it is anyway on an unreliable channel
    exit;
   end;

   fIncomingSequenceNumber:=BlockSequenceNumber;

   BlockPacketDataPosition:=SizeOf(TRNLPeerUnreliableOrderedChannelShortMessagePacketHeader);
   BlockDataLength:=aBlockPacket.fBlockPacketDataLength-BlockPacketDataPosition;

   if (BlockPacketDataPosition+BlockDataLength)>aBlockPacket.fBlockPacketDataLength then begin
    exit;
   end;

   fIncomingMessageQueue.Enqueue(TRNLMessage.CreateFromMemory(TRNLPointer(@aBlockPacket.fBlockPacketData[BlockPacketDataPosition]),
                                                              BlockDataLength,
                                                              []));

  end;

  RNL_PEER_UNRELIABLE_ORDERED_CHANNEL_COMMAND_TYPE_LONG_MESSAGE:begin

   if (BlockPacketDataPosition+(SizeOf(TRNLPeerUnreliableOrderedChannelLongMessagePacketHeader)-1))>=aBlockPacket.fBlockPacketDataLength then begin
    fIncomingMessageLength:=0;
    if assigned(fIncomingMessageReceiveBufferData) then begin
     FreeMem(fIncomingMessageReceiveBufferData);
     fIncomingMessageReceiveBufferData:=nil;
    end;
    exit;
   end;

   LongMessagePacketHeader:=TRNLPointer(@aBlockPacket.fBlockPacketData[BlockPacketDataPosition]);

   BlockSequenceNumber:=TRNLEndianness.LittleEndianToHost16(LongMessagePacketHeader^.SequenceNumber);

   LastSequenceNumber:=fIncomingSequenceNumber;

   if LastSequenceNumber>=BlockSequenceNumber then begin
    // Reject, it is anyway on an unreliable channel
    fIncomingMessageLength:=0;
    if assigned(fIncomingMessageReceiveBufferData) then begin
     FreeMem(fIncomingMessageReceiveBufferData);
     fIncomingMessageReceiveBufferData:=nil;
    end;
    exit;
   end;

   fIncomingSequenceNumber:=BlockSequenceNumber;

   LongMessagePacketHeader^.MessageNumber:=TRNLEndianness.LittleEndianToHost16(LongMessagePacketHeader^.MessageNumber);
   LongMessagePacketHeader^.Offset:=TRNLEndianness.LittleEndianToHost32(LongMessagePacketHeader^.Offset);
   LongMessagePacketHeader^.Length:=TRNLEndianness.LittleEndianToHost32(LongMessagePacketHeader^.Length);

   if LongMessagePacketHeader^.Offset=0 then begin

    fIncomingMessageNumber:=LongMessagePacketHeader^.MessageNumber;

    fIncomingReceivedMessageDataLength:=0;

    fIncomingMessageLength:=LongMessagePacketHeader^.Length;

    if assigned(fIncomingMessageReceiveBufferData) then begin
     FreeMem(fIncomingMessageReceiveBufferData);
     fIncomingMessageReceiveBufferData:=nil;
    end;

    GetMem(fIncomingMessageReceiveBufferData,LongMessagePacketHeader^.Length);

   end else begin

    if (fIncomingMessageNumber<>LongMessagePacketHeader^.MessageNumber) or
       (not assigned(fIncomingMessageReceiveBufferData)) or
       (fIncomingMessageLength<>LongMessagePacketHeader^.Length) or
       ((BlockSequenceNumber-LastSequenceNumber).fValue>=2) then begin
     // Reject, it is anyway on an unreliable channel
     fIncomingMessageLength:=0;
     if assigned(fIncomingMessageReceiveBufferData) then begin
      FreeMem(fIncomingMessageReceiveBufferData);
      fIncomingMessageReceiveBufferData:=nil;
     end;
     exit;
    end;

   end;

   if not assigned(fIncomingMessageReceiveBufferData) then begin
    fIncomingReceivedMessageDataLength:=0;
   end;

   BlockPacketDataPosition:=SizeOf(TRNLPeerUnreliableOrderedChannelLongMessagePacketHeader);
   BlockDataLength:=aBlockPacket.fBlockPacketDataLength-BlockPacketDataPosition;

   if (BlockPacketDataPosition+BlockDataLength)>aBlockPacket.fBlockPacketDataLength then begin
    fIncomingMessageLength:=0;
    if assigned(fIncomingMessageReceiveBufferData) then begin
     FreeMem(fIncomingMessageReceiveBufferData);
     fIncomingMessageReceiveBufferData:=nil;
    end;
    exit;
   end;

   FragmentOffset:=LongMessagePacketHeader^.Offset;

   if (FragmentOffset+BlockDataLength)>fIncomingMessageLength then begin
    fIncomingMessageLength:=0;
    if assigned(fIncomingMessageReceiveBufferData) then begin
     FreeMem(fIncomingMessageReceiveBufferData);
     fIncomingMessageReceiveBufferData:=nil;
    end;
    exit;
   end;

   Move(aBlockPacket.fBlockPacketData[BlockPacketDataPosition],
        PRNLUInt8Array(TRNLPointer(fIncomingMessageReceiveBufferData))^[FragmentOffset],
        BlockDataLength);

   inc(fIncomingReceivedMessageDataLength,BlockDataLength);

   if fIncomingReceivedMessageDataLength=fIncomingMessageLength then begin
    fIncomingMessageQueue.Enqueue(TRNLMessage.CreateFromMemory(fIncomingMessageReceiveBufferData,
                                                               fIncomingMessageLength,
                                                               [RNL_MESSAGE_FLAG_NO_ALLOCATE]));
    fIncomingMessageLength:=0;
    fIncomingMessageReceiveBufferData:=nil;
   end;

  end;

  else begin

   fIncomingMessageLength:=0;
   if assigned(fIncomingMessageReceiveBufferData) then begin
    FreeMem(fIncomingMessageReceiveBufferData);
    fIncomingMessageReceiveBufferData:=nil;
   end;

  end;

 end;

end;

constructor TRNLPeerUnreliableUnorderedChannel.Create(const aPeer:TRNLPeer;const aChannelNumber:TRNLUInt16);
begin
 inherited Create(aPeer,aChannelNumber);
 fIncomingMessageNumber:=$ffff;
 fIncomingMessageLength:=0;
 fIncomingMessageReceiveBufferData:=nil;
 fIncomingMessageReceiveBufferFlagData:=nil;
 fOutgoingMessageNumber:=0;
end;

destructor TRNLPeerUnreliableUnorderedChannel.Destroy;
begin
 if assigned(fIncomingMessageReceiveBufferData) then begin
  FreeMem(fIncomingMessageReceiveBufferData);
  fIncomingMessageReceiveBufferData:=nil;
 end;
 if assigned(fIncomingMessageReceiveBufferFlagData) then begin
  FreeMem(fIncomingMessageReceiveBufferFlagData);
  fIncomingMessageReceiveBufferFlagData:=nil;
 end;
 inherited Destroy;
end;

function TRNLPeerUnreliableUnorderedChannel.GetMaximumUnfragmentedMessageSize:TRNLSizeUInt;
begin
 result:=fPeer.fMTU-(RNL_IP_HEADER_SIZE+
                     RNL_UDP_HEADER_SIZE+
                     SizeOf(TRNLProtocolNormalPacketHeader)+
                     SizeOf(TRNLProtocolBlockPacketChannel)+
                     SizeOf(TRNLPeerUnreliableUnorderedChannelShortMessagePacketHeader));
end;

procedure TRNLPeerUnreliableUnorderedChannel.DispatchOutgoingBlockPackets;
var Message:TRNLMessage;
    MaximumShortMessageBlockPacketSize,
    MaximumLongMessageBlockPacketSize,
    MessagePartLength,
    MessagePosition:TRNLSizeUInt;
    BlockPacket:TRNLPeerBlockPacket;
    LongMessagePacketHeader:PRNLPeerUnreliableUnorderedChannelLongMessagePacketHeader;
begin

 if fOutgoingMessageQueue.IsEmpty then begin
  exit;
 end;

 MaximumShortMessageBlockPacketSize:=fPeer.fMTU-(RNL_IP_HEADER_SIZE+
                                                 RNL_UDP_HEADER_SIZE+
                                                 SizeOf(TRNLProtocolNormalPacketHeader)+
                                                 SizeOf(TRNLProtocolBlockPacketChannel)+
                                                 SizeOf(TRNLPeerUnreliableUnorderedChannelShortMessagePacketHeader));

 MaximumLongMessageBlockPacketSize:=fPeer.fMTU-(RNL_IP_HEADER_SIZE+
                                                RNL_UDP_HEADER_SIZE+
                                                SizeOf(TRNLProtocolNormalPacketHeader)+
                                                SizeOf(TRNLProtocolBlockPacketChannel)+
                                                SizeOf(TRNLPeerUnreliableUnorderedChannelLongMessagePacketHeader));

 while fOutgoingMessageQueue.Dequeue(Message) do begin

  try

   if Message.fDataLength>0 then begin

    if Message.fDataLength<=MaximumShortMessageBlockPacketSize then begin

     BlockPacket:=TRNLPeerBlockPacket.Create(fPeer);
     try

      BlockPacket.fBlockPacket.Channel.Header.TypeAndSubtype:=(TRNLInt32(TRNLProtocolBlockPacketType(RNL_PROTOCOL_BLOCK_PACKET_TYPE_CHANNEL)) shl 0) or
                                                              (TRNLInt32(TRNLPeerUnreliableUnorderedChannelCommandType(RNL_PEER_UNRELIABLE_UNORDERED_CHANNEL_COMMAND_TYPE_SHORT_MESSAGE)) shl 4);
      BlockPacket.fBlockPacket.Channel.ChannelNumber:=fChannelNumber;
      BlockPacket.fBlockPacket.Channel.PayloadDataLength:=TRNLEndianness.HostToLittleEndian16(SizeOf(TRNLPeerUnreliableUnorderedChannelShortMessagePacketHeader)+Message.fDataLength);

      BlockPacket.fBlockPacketDataLength:=SizeOf(TRNLPeerUnreliableUnorderedChannelShortMessagePacketHeader)+Message.fDataLength;

      SetLength(BlockPacket.fBlockPacketData,BlockPacket.fBlockPacketDataLength);

      Move(Message.fData^,
           BlockPacket.fBlockPacketData[SizeOf(TRNLPeerUnreliableUnorderedChannelShortMessagePacketHeader)],
           Message.fDataLength);

     finally
      fPeer.fOutgoingBlockPackets.Enqueue(BlockPacket);
     end;

    end else begin

     MessagePosition:=0;
     while MessagePosition<Message.fDataLength do begin

      MessagePartLength:=Min(Max(TRNLInt64(Message.fDataLength-MessagePosition),TRNLInt64(1)),TRNLInt64(MaximumLongMessageBlockPacketSize));

      BlockPacket:=TRNLPeerBlockPacket.Create(fPeer);
      try

       BlockPacket.fBlockPacket.Channel.Header.TypeAndSubtype:=(TRNLInt32(TRNLProtocolBlockPacketType(RNL_PROTOCOL_BLOCK_PACKET_TYPE_CHANNEL)) shl 0) or
                                                               (TRNLInt32(TRNLPeerUnreliableUnorderedChannelCommandType(RNL_PEER_UNRELIABLE_UNORDERED_CHANNEL_COMMAND_TYPE_LONG_MESSAGE)) shl 4);
       BlockPacket.fBlockPacket.Channel.ChannelNumber:=fChannelNumber;
       BlockPacket.fBlockPacket.Channel.PayloadDataLength:=TRNLEndianness.HostToLittleEndian16(SizeOf(TRNLPeerUnreliableUnorderedChannelLongMessagePacketHeader)+MessagePartLength);

       BlockPacket.fBlockPacketDataLength:=SizeOf(TRNLPeerUnreliableUnorderedChannelLongMessagePacketHeader)+MessagePartLength;

       SetLength(BlockPacket.fBlockPacketData,BlockPacket.fBlockPacketDataLength);

       LongMessagePacketHeader:=TRNLPointer(@BlockPacket.fBlockPacketData[0]);
       LongMessagePacketHeader^.MessageNumber:=TRNLEndianness.HostToLittleEndian16(fOutgoingMessageNumber);
       LongMessagePacketHeader^.Offset:=TRNLEndianness.HostToLittleEndian32(MessagePosition);
       LongMessagePacketHeader^.Length:=TRNLEndianness.HostToLittleEndian32(Message.fDataLength);

       Move(PRNLUInt8Array(TRNLPointer(Message.fData))^[MessagePosition],
            BlockPacket.fBlockPacketData[SizeOf(TRNLPeerUnreliableUnorderedChannelLongMessagePacketHeader)],
            MessagePartLength);

      finally
       fPeer.fOutgoingBlockPackets.Enqueue(BlockPacket);
      end;

      inc(MessagePosition,MessagePartLength);

     end;

     inc(fOutgoingMessageNumber);

    end;

   end;

  finally
   Message.DecRef;
  end;

 end;
end;

procedure TRNLPeerUnreliableUnorderedChannel.DispatchIncomingBlockPacket(const aBlockPacket:TRNLPeerBlockPacket);
var ChannelCommandType:TRNLPeerUnreliableUnorderedChannelCommandType;
    BlockPacketDataPosition,BlockDataLength,FragmentOffset,Index:TRNLSizeUInt;
    LongMessagePacketHeader:PRNLPeerUnreliableUnorderedChannelLongMessagePacketHeader;
begin

 BlockPacketDataPosition:=0;

 ChannelCommandType:=TRNLPeerUnreliableUnorderedChannelCommandType(TRNLInt32(aBlockPacket.fBlockPacket.Channel.Header.TypeAndSubtype shr 4));

 case ChannelCommandType of

  RNL_PEER_UNRELIABLE_UNORDERED_CHANNEL_COMMAND_TYPE_SHORT_MESSAGE:begin

   if (BlockPacketDataPosition+TRNLSizeUInt(SizeOf(TRNLPeerUnreliableUnorderedChannelShortMessagePacketHeader)))>aBlockPacket.fBlockPacketDataLength then begin
    exit;
   end;

   BlockPacketDataPosition:=SizeOf(TRNLPeerUnreliableUnorderedChannelShortMessagePacketHeader);
   BlockDataLength:=aBlockPacket.fBlockPacketDataLength-BlockPacketDataPosition;

   if (BlockPacketDataPosition+BlockDataLength)>aBlockPacket.fBlockPacketDataLength then begin
    exit;
   end;

   fIncomingMessageQueue.Enqueue(TRNLMessage.CreateFromMemory(TRNLPointer(@aBlockPacket.fBlockPacketData[BlockPacketDataPosition]),
                                                              BlockDataLength,
                                                              []));

  end;

  RNL_PEER_UNRELIABLE_UNORDERED_CHANNEL_COMMAND_TYPE_LONG_MESSAGE:begin

   if (BlockPacketDataPosition+(SizeOf(TRNLPeerUnreliableUnorderedChannelLongMessagePacketHeader)-1))>=aBlockPacket.fBlockPacketDataLength then begin
    exit;
   end;

   LongMessagePacketHeader:=TRNLPointer(@aBlockPacket.fBlockPacketData[BlockPacketDataPosition]);

   LongMessagePacketHeader^.MessageNumber:=TRNLEndianness.LittleEndianToHost16(LongMessagePacketHeader^.MessageNumber);
   LongMessagePacketHeader^.Offset:=TRNLEndianness.LittleEndianToHost32(LongMessagePacketHeader^.Offset);
   LongMessagePacketHeader^.Length:=TRNLEndianness.LittleEndianToHost32(LongMessagePacketHeader^.Length);

   if fIncomingMessageNumber<>LongMessagePacketHeader^.MessageNumber then begin

    fIncomingMessageNumber:=LongMessagePacketHeader^.MessageNumber;

    fIncomingReceivedMessageDataLength:=0;

    fIncomingMessageLength:=LongMessagePacketHeader^.Length;

    if assigned(fIncomingMessageReceiveBufferData) then begin
     FreeMem(fIncomingMessageReceiveBufferData);
     fIncomingMessageReceiveBufferData:=nil;
    end;

    if assigned(fIncomingMessageReceiveBufferFlagData) then begin
     FreeMem(fIncomingMessageReceiveBufferFlagData);
     fIncomingMessageReceiveBufferFlagData:=nil;
    end;

    GetMem(fIncomingMessageReceiveBufferData,LongMessagePacketHeader^.Length);

    GetMem(fIncomingMessageReceiveBufferFlagData,LongMessagePacketHeader^.Length);

    FillChar(fIncomingMessageReceiveBufferFlagData^,LongMessagePacketHeader^.Length,#0);

   end else begin

    if (fIncomingMessageNumber<>LongMessagePacketHeader^.MessageNumber) or
       (not assigned(fIncomingMessageReceiveBufferData)) or
       (fIncomingMessageLength<>LongMessagePacketHeader^.Length) then begin
     // Reject, it is anyway on an unreliable channel
     fIncomingMessageLength:=0;
     if assigned(fIncomingMessageReceiveBufferData) then begin
      FreeMem(fIncomingMessageReceiveBufferData);
      fIncomingMessageReceiveBufferData:=nil;
     end;
     if assigned(fIncomingMessageReceiveBufferFlagData) then begin
      FreeMem(fIncomingMessageReceiveBufferFlagData);
      fIncomingMessageReceiveBufferFlagData:=nil;
     end;
     exit;
    end;

   end;

   if not (assigned(fIncomingMessageReceiveBufferData) and
           assigned(fIncomingMessageReceiveBufferFlagData)) then begin
    fIncomingReceivedMessageDataLength:=0;
   end;

   BlockPacketDataPosition:=SizeOf(TRNLPeerUnreliableUnorderedChannelLongMessagePacketHeader);
   BlockDataLength:=aBlockPacket.fBlockPacketDataLength-BlockPacketDataPosition;

   if (BlockPacketDataPosition+BlockDataLength)>aBlockPacket.fBlockPacketDataLength then begin
    fIncomingMessageLength:=0;
    if assigned(fIncomingMessageReceiveBufferData) then begin
     FreeMem(fIncomingMessageReceiveBufferData);
     fIncomingMessageReceiveBufferData:=nil;
    end;
    if assigned(fIncomingMessageReceiveBufferFlagData) then begin
     FreeMem(fIncomingMessageReceiveBufferFlagData);
     fIncomingMessageReceiveBufferFlagData:=nil;
    end;
    exit;
   end;

   FragmentOffset:=LongMessagePacketHeader^.Offset;

   if (FragmentOffset+BlockDataLength)>fIncomingMessageLength then begin
    fIncomingMessageLength:=0;
    if assigned(fIncomingMessageReceiveBufferData) then begin
     FreeMem(fIncomingMessageReceiveBufferData);
     fIncomingMessageReceiveBufferData:=nil;
    end;
    if assigned(fIncomingMessageReceiveBufferFlagData) then begin
     FreeMem(fIncomingMessageReceiveBufferFlagData);
     fIncomingMessageReceiveBufferFlagData:=nil;
    end;
    exit;
   end;

   for Index:=FragmentOffset to FragmentOffset+(BlockDataLength-1) do begin
    if PRNLUInt8Array(TRNLPointer(fIncomingMessageReceiveBufferFlagData))^[Index]<>0 then begin
     fIncomingMessageLength:=0;
     if assigned(fIncomingMessageReceiveBufferData) then begin
      FreeMem(fIncomingMessageReceiveBufferData);
      fIncomingMessageReceiveBufferData:=nil;
     end;
     if assigned(fIncomingMessageReceiveBufferFlagData) then begin
      FreeMem(fIncomingMessageReceiveBufferFlagData);
      fIncomingMessageReceiveBufferFlagData:=nil;
     end;
     exit;
    end;
   end;

   Move(aBlockPacket.fBlockPacketData[BlockPacketDataPosition],
        PRNLUInt8Array(TRNLPointer(fIncomingMessageReceiveBufferData))^[FragmentOffset],
        BlockDataLength);

   FillChar(PRNLUInt8Array(TRNLPointer(fIncomingMessageReceiveBufferFlagData))^[FragmentOffset],
            BlockDataLength,
            #$ff);

   inc(fIncomingReceivedMessageDataLength,BlockDataLength);

   if fIncomingReceivedMessageDataLength=fIncomingMessageLength then begin
    fIncomingMessageQueue.Enqueue(TRNLMessage.CreateFromMemory(fIncomingMessageReceiveBufferData,
                                                               fIncomingMessageLength,
                                                               [RNL_MESSAGE_FLAG_NO_ALLOCATE]));
    fIncomingMessageLength:=0;
    fIncomingMessageReceiveBufferData:=nil;
    if assigned(fIncomingMessageReceiveBufferFlagData) then begin
     FreeMem(fIncomingMessageReceiveBufferFlagData);
     fIncomingMessageReceiveBufferFlagData:=nil;
    end;
   end;

  end;

  else begin

   fIncomingMessageLength:=0;
   if assigned(fIncomingMessageReceiveBufferData) then begin
    FreeMem(fIncomingMessageReceiveBufferData);
    fIncomingMessageReceiveBufferData:=nil;
   end;
   if assigned(fIncomingMessageReceiveBufferFlagData) then begin
    FreeMem(fIncomingMessageReceiveBufferFlagData);
    fIncomingMessageReceiveBufferFlagData:=nil;
   end;

  end;

 end;

end;

constructor TRNLPeer.Create(const aHost:TRNLHost);
begin
 inherited Create;

 fHost:=aHost;

 fCurrentThreadIndex:=0;

 fLocalPeerID:=fHost.fPeerIDManager.AllocateID;

 fRemotePeerID:=0;

 fPeerListIndex:=fHost.fPeerList.Add(self);

 inc(fHost.fCountPeers);

 fHost.fPeerIDMap[fLocalPeerID]:=self;

 fIncomingPacketQueue:=TRNLPeerIncomingPacketQueue.Create;

 fChannels:=TRNLPeerChannelList.Create(true);

 fAddress.Host:=RNL_HOST_ANY;
 fAddress.Port:=0;

 fPointerToAddress:=@fAddress;

 fRemoteHostSalt:=0;

 fMTU:=fHost.fMTU;

 fOutgoingEncryptedPacketSequenceNumber:=0;
 fIncomingEncryptedPacketSequenceNumber:=0;
 fIncomingEncryptedPacketSequenceBuffer:=nil;

 fNextCheckTimeoutsTimeout:=0;

 fNextReliableBlockPacketTimeout:=0;

 fNextPendingConnectionSendTimeout:=0;

 fNextPendingDisconnectionSendTimeout:=0;

 fDisconnectionTimeout:=0;

 fDisconnectionSequenceNumber:=0;

 fDisconnectData:=0;

 fPendingConnectionHandshakeSendData:=nil;

 fConnectionChallengeResponse:=nil;

 fConnectionToken:=nil;

 fAuthenticationToken:=nil;

 fUnacknowlegmentedBlockPackets:=0;

 fRoundTripTime:=TRNLUInt64(500) shl 32;

 fRoundTripTimeVariance:=0;

 fRetransmissionTimeOut:=TRNLUInt64(500) shl 32;

 fPacketLoss:=0;

 fPacketLossVariance:=0;

 fCountPacketLoss:=0;

 fCountSentPackets:=0;

 fLastPacketLossUpdateTime:=fHost.fTime;

 fLastSentDataTime:=fHost.fTime;

 fLastReceivedDataTime:=fHost.fTime;

 fLastPingSentTime:=fHost.fTime;

 fNextPingSendTime:=0;

 fOutgoingPingSequenceNumber:=0;

 FillChar(fKeepAlivePingTimes,SizeOf(TRNLPeerKeepAliveTimes),#0);

 FillChar(fKeepAlivePongTimes,SizeOf(TRNLPeerKeepAliveTimes),#0);

 fIncomingBlockPackets:=TRNLPeerBlockPacketQueue.Create;

 fOutgoingBlockPackets:=TRNLPeerBlockPacketQueue.Create;

 fOutgoingMTUProbeBlockPackets:=TRNLPeerBlockPacketQueue.Create;

 fDeferredOutgoingBlockPackets:=TRNLPeerBlockPacketQueue.Create;

 fState:=RNL_PEER_STATE_DISCONNECTED;

 fRemoteIncomingBandwidthLimit:=0;

 fRemoteOutgoingBandwidthLimit:=0;

 fMTUProbeIndex:=-1;

 fMTUProbeSequenceNumber:=$ffff;

 fSendNewHostBandwidthLimits:=false;

 fReceivedNewHostBandwidthLimitsSequenceNumber:=$ff;

 fSendNewHostBandwidthLimitsSequenceNumber:=$ff;

 fIncomingBandwidthRateTracker.Reset;

 fOutgoingBandwidthRateTracker.Reset;

 fIncomingBandwidthRateTracker.SetTime(fHost.fTime);

 fOutgoingBandwidthRateTracker.SetTime(fHost.fTime);

 fIncomingBandwidthRateTracker.Update;

 fOutgoingBandwidthRateTracker.Update;

 UpdateOutgoingBandwidthRateLimiter;

 fOutgoingBandwidthRateLimiter.Reset(fHost.fTime);

end;

destructor TRNLPeer.Destroy;
var BlockPacket:TRNLPeerBlockPacket;
    OtherPeer:TRNLPeer;
    OtherPeerListIndex:TRNLSizeInt;
begin

 if assigned(fConnectionChallengeResponse) then begin
  FreeMem(fConnectionChallengeResponse);
  fConnectionChallengeResponse:=nil;
 end;

 if assigned(fConnectionToken) then begin
  FreeMem(fConnectionToken);
  fConnectionToken:=nil;
 end;

 if assigned(fAuthenticationToken) then begin
  FreeMem(fAuthenticationToken);
  fAuthenticationToken:=nil;
 end;

 fIncomingEncryptedPacketSequenceBuffer:=nil;

 while fDeferredOutgoingBlockPackets.Dequeue(BlockPacket) do begin
  BlockPacket.DecRef;
 end;
 FreeAndNil(fDeferredOutgoingBlockPackets);

 while fOutgoingMTUProbeBlockPackets.Dequeue(BlockPacket) do begin
  BlockPacket.DecRef;
 end;
 FreeAndNil(fOutgoingMTUProbeBlockPackets);

 while fOutgoingBlockPackets.Dequeue(BlockPacket) do begin
  BlockPacket.DecRef;
 end;
 FreeAndNil(fOutgoingBlockPackets);

 while fIncomingBlockPackets.Dequeue(BlockPacket) do begin
  BlockPacket.DecRef;
 end;
 FreeAndNil(fIncomingBlockPackets);

 FreeAndNil(fPendingConnectionHandshakeSendData);

 FreeAndNil(fChannels);

 FreeAndNil(fIncomingPacketQueue);

 dec(fHost.fCountPeers);

 fHost.fPeerIDMap[fLocalPeerID]:=nil;

 fHost.fPeerIDManager.FreeID(fLocalPeerID);

 OtherPeerListIndex:=fHost.fPeerList.Count-1;
 if OtherPeerListIndex<>OtherPeerListIndex then begin
  OtherPeer:=fHost.fPeerList[OtherPeerListIndex];
  fHost.fPeerList.Exchange(fPeerListIndex,OtherPeerListIndex);
  OtherPeer.fPeerListIndex:=fPeerListIndex;
  fHost.fPeerList.Delete(OtherPeerListIndex);
 end else begin
  fHost.fPeerList.Delete(fPeerListIndex);
 end;

 fPeerListIndex:=-1;

 inherited Destroy;
end;

procedure TRNLPeer.UpdateOutgoingBandwidthRateLimiter;
begin
 fOutgoingBandwidthRateLimiter.Setup(fRemoteIncomingBandwidthLimit,1000);
end;

function TRNLPeer.GetIncomingBandwidthRate:TRNLUInt32;
begin
 result:=fIncomingBandwidthRateTracker.UnitsPerSecond;
end;

function TRNLPeer.GetOutgoingBandwidthRate:TRNLUInt32;
begin
 result:=fOutgoingBandwidthRateTracker.UnitsPerSecond;
end;

function TRNLPeer.GetCountChannels:TRNLSizeInt;
begin
 result:=fCountChannels;
end;

procedure TRNLPeer.SetCountChannels(aCountChannels:TRNLSizeInt);
var ChannelNumber:TRNLSizeInt;
begin
 fCountChannels:=aCountChannels;
 while fChannels.Count>aCountChannels do begin
  fChannels.Delete(fChannels.Count-1);
 end;
 while fChannels.Count<aCountChannels do begin
  ChannelNumber:=fChannels.Count;
  case fHost.fChannelTypes[ChannelNumber] of
   RNL_PEER_RELIABLE_ORDERED_CHANNEL:begin
    fChannels.Add(TRNLPeerReliableOrderedChannel.Create(self,ChannelNumber));
   end;
   RNL_PEER_RELIABLE_UNORDERED_CHANNEL:begin
    fChannels.Add(TRNLPeerReliableUnorderedChannel.Create(self,ChannelNumber));
   end;
   RNL_PEER_UNRELIABLE_ORDERED_CHANNEL:begin
    fChannels.Add(TRNLPeerUnreliableOrderedChannel.Create(self,ChannelNumber));
   end;
   RNL_PEER_UNRELIABLE_UNORDERED_CHANNEL:begin
    fChannels.Add(TRNLPeerUnreliableUnorderedChannel.Create(self,ChannelNumber));
   end;
   else begin
    Assert(false);
    break;
   end;
  end;
 end;
end;

procedure TRNLPeer.UpdateRoundTripTime(const aRoundTripTime:TRNLInt64);
var ValueError:TRNLInt64;
begin
 ValueError:=(aRoundTripTime shl 32)-fRoundTripTime;
 inc(fRoundTripTime,SARInt64(ValueError,3));
 inc(fRoundTripTimeVariance,SARInt64(abs(ValueError),2)-SARInt64(fRoundTripTimeVariance,2));
 fRetransmissionTimeOut:=fRoundTripTime+(fRoundTripTimeVariance shl 2);
end;

procedure TRNLPeer.UpdatePatchLossStatistics;
var Value64Bit:TRNLInt64;
begin

 if fLastPacketLossUpdateTime.fValue=0 then begin

  fLastPacketLossUpdateTime:=fHost.fTime;

 end else if (TRNLTime.Difference(fHost.fTime,fLastPacketLossUpdateTime)>=RNL_PEER_PACKET_LOSS_INTERVAL) and
             (fCountSentPackets>0) then begin

  // Jacobson's variance algorithm with 32.32bit fixed point
  // Error = Measured - OldPrediction
  // NewPrediction = OldPrediction + (Error / 8)
  //               = (OldPrediction * (7 / 8)) + (Measured / 8)
  // NewVariation = (OldVariation - (OldVariation / 4)) + (Error / 4)
  //              = (OldVariation * (3 / 4)) + (Error / 4)
  // RTO = Prediction + (Variation * 4)
  Value64Bit:=((TRNLInt64(fCountPacketLoss) shl 32) div TRNLInt64(fCountSentPackets))-fPacketLoss;
  inc(fPacketLoss,SARInt64(Value64Bit,3));
  inc(fPacketLossVariance,SARInt64(abs(Value64Bit),2)-SARInt64(fPacketLossVariance,2));

{$if defined(RNL_DEBUG)}
  fHost.fInstance.fDebugLock.Acquire;
  try
   writeln('Peer ',fLocalPeerID,': ', //' [',TypInfo.GetEnumName(TypeInfo(TRNLPeerState),TRNLInt32(fState)),']: ',
           fCountPacketLoss,' Packets lost at last measured time frame, ',
           fPacketLoss*OneDiv32Bit:1:8,'+-',
           fPacketLossVariance*OneDiv32Bit:1:8,
           ' Packet loss, ',
           fRoundTripTime*OneDiv32Bit:1:2,'+-',fRoundTripTimeVariance*OneDiv32Bit:1:2,
           ' ms round trip time, ',
           fIncomingBandwidthRateTracker.UnitsPerSecond/1024.0:1:3,
           ' incoming kbps, ',
           fOutgoingBandwidthRateTracker.UnitsPerSecond/1024.0:1:3,
           ' outgoing kbps');
  finally
   fHost.fInstance.fDebugLock.Release;
  end;
{$ifend}

  fCountPacketLoss:=0;

  fCountSentPackets:=0;

  fLastPacketLossUpdateTime:=fHost.fTime;

 end;

end;

procedure TRNLPeer.DispatchIncomingMTUProbeBlockPacket(const aIncomingBlockPacket:TRNLPeerBlockPacket);
var OutgoingBlockPacket:TRNLPeerBlockPacket;
    HostEvent:TRNLHostEvent;
begin

{$if defined(RNL_DEBUG) and defined(RNL_DEBUG_MTU)}
 fHost.fInstance.fDebugLock.Acquire;
 try
  writeln('Peer ',fLocalPeerID,': ',
          'Incoming MTU probe with phase ',aIncomingBlockPacket.fBlockPacket.MTUProbe.Phase,' ',
          'and MTU size ',TRNLEndianness.LittleEndianToHost16(aIncomingBlockPacket.fBlockPacket.MTUProbe.Size));
 finally
  fHost.fInstance.fDebugLock.Release;
 end;
{$ifend}

 if ((aIncomingBlockPacket.fBlockPacket.MTUProbe.Phase and 1)<>0) and
    (TRNLEndianness.LittleEndianToHost16(aIncomingBlockPacket.fBlockPacket.MTUProbe.SequenceNumber)<>fMTUProbeSequenceNumber.fValue) then begin
  exit;
 end;

 case aIncomingBlockPacket.fBlockPacket.MTUProbe.Phase of
  2:begin
   fMTU:=TRNLEndianness.LittleEndianToHost16(aIncomingBlockPacket.fBlockPacket.MTUProbe.Size);
   HostEvent.Type_:=RNL_HOST_EVENT_TYPE_MTU;
   HostEvent.MTU.Peer:=self;
   HostEvent.MTU.MTU:=fMTU;
   fHost.fEventQueue.Enqueue(HostEvent);
  end;
  3..$ff:begin
   fMTU:=TRNLEndianness.LittleEndianToHost16(aIncomingBlockPacket.fBlockPacket.MTUProbe.Size);
   HostEvent.Type_:=RNL_HOST_EVENT_TYPE_MTU;
   HostEvent.MTU.Peer:=self;
   HostEvent.MTU.MTU:=fMTU;
   fHost.fEventQueue.Enqueue(HostEvent);
   fMTUProbeIndex:=-1;
   fMTUProbeNextTimeout:=0;
   exit;
  end;
 end;

 if aIncomingBlockPacket.fBlockPacket.MTUProbe.Phase<5 then begin
  OutgoingBlockPacket:=TRNLPeerBlockPacket.Create(self);
  try
   OutgoingBlockPacket.fBlockPacket.Header.TypeAndSubtype:=TRNLInt32(TRNLProtocolBlockPacketType(RNL_PROTOCOL_BLOCK_PACKET_TYPE_MTU_PROBE));
   OutgoingBlockPacket.fBlockPacket.MTUProbe.SequenceNumber:=aIncomingBlockPacket.fBlockPacket.MTUProbe.SequenceNumber;
   OutgoingBlockPacket.fBlockPacket.MTUProbe.Phase:=aIncomingBlockPacket.fBlockPacket.MTUProbe.Phase+1;
   OutgoingBlockPacket.fBlockPacket.MTUProbe.Size:=aIncomingBlockPacket.fBlockPacket.MTUProbe.Size;
   OutgoingBlockPacket.fBlockPacketDataLength:=TRNLEndianness.LittleEndianToHost16(aIncomingBlockPacket.fBlockPacket.MTUProbe.Size)-(RNL_IP_HEADER_SIZE+
                                                                                                                                     RNL_UDP_HEADER_SIZE+
                                                                                                                                     SizeOf(TRNLProtocolNormalPacketHeader)+
                                                                                                                                     SizeOf(TRNLProtocolBlockPacketMTUProbe));
   SetLength(OutgoingBlockPacket.fBlockPacketData,OutgoingBlockPacket.fBlockPacketDataLength);
   OutgoingBlockPacket.fBlockPacket.MTUProbe.PayloadDataLength:=TRNLEndianness.LittleEndianToHost16(OutgoingBlockPacket.fBlockPacketDataLength);
   if OutgoingBlockPacket.fBlockPacketDataLength>0 then begin
    fHost.fRandomGenerator.GetRandomBytes(OutgoingBlockPacket.fBlockPacketData[0],OutgoingBlockPacket.fBlockPacketDataLength);
   end;
  finally
   fOutgoingMTUProbeBlockPackets.Enqueue(OutgoingBlockPacket);
  end;
 end;

end;

procedure TRNLPeer.DispatchIncomingBlockPackets;
var IncomingBlockPacket,OutgoingBlockPacket:TRNLPeerBlockPacket;
    HostEvent:TRNLHostEvent;
begin

 while fIncomingBlockPackets.Dequeue(IncomingBlockPacket) do begin

  try

   case TRNLProtocolBlockPacketType(TRNLInt32(IncomingBlockPacket.fBlockPacket.Header.TypeAndSubtype and $f)) of

    RNL_PROTOCOL_BLOCK_PACKET_TYPE_NONE:begin
    end;

    RNL_PROTOCOL_BLOCK_PACKET_TYPE_PING:begin

     OutgoingBlockPacket:=TRNLPeerBlockPacket.Create(self);
     try
      OutgoingBlockPacket.fBlockPacket.Header.TypeAndSubtype:=TRNLInt32(TRNLProtocolBlockPacketType(RNL_PROTOCOL_BLOCK_PACKET_TYPE_PONG));
      OutgoingBlockPacket.fBlockPacket.Pong.SequenceNumber:=IncomingBlockPacket.fBlockPacket.Ping.SequenceNumber;
      OutgoingBlockPacket.fBlockPacket.Pong.SentTime:=TRNLEndianness.HostToLittleEndian16(TRNLUInt16(IncomingBlockPacket.fSentTime.fValue));
     finally
      fOutgoingBlockPackets.Enqueue(OutgoingBlockPacket);
     end;

{$if defined(RNL_DEBUG) and defined(RNL_DEBUG_PING)}
     fHost.fInstance.fDebugLock.Acquire;
     try
      writeln('Peer ',fLocalPeerID,': Incoming Ping => Outgoing Pong');
     finally
      fHost.fInstance.fDebugLock.Release;
     end;
{$ifend}

    end;

    RNL_PROTOCOL_BLOCK_PACKET_TYPE_PONG:begin

     fKeepAlivePongTimes[IncomingBlockPacket.fBlockPacket.Pong.SequenceNumber and RNL_PEER_KEEP_ALIVE_TIME_HISTORY_MASK]:=fHost.fTime;
     if (fKeepAlivePingTimes[IncomingBlockPacket.fBlockPacket.Pong.SequenceNumber and RNL_PEER_KEEP_ALIVE_TIME_HISTORY_MASK]<>0) and
        (TRNLUInt16(fKeepAlivePingTimes[IncomingBlockPacket.fBlockPacket.Pong.SequenceNumber and RNL_PEER_KEEP_ALIVE_TIME_HISTORY_MASK].fValue)=IncomingBlockPacket.fBlockPacket.Pong.SentTime) then begin
      UpdateRoundTripTime(TRNLTime.Difference(fKeepAlivePongTimes[IncomingBlockPacket.fBlockPacket.Pong.SequenceNumber and RNL_PEER_KEEP_ALIVE_TIME_HISTORY_MASK],
                                              fKeepAlivePingTimes[IncomingBlockPacket.fBlockPacket.Pong.SequenceNumber and RNL_PEER_KEEP_ALIVE_TIME_HISTORY_MASK]));
     end else begin
      inc(fCountPacketLoss);
     end;

     fKeepAlivePingTimes[IncomingBlockPacket.fBlockPacket.Pong.SequenceNumber and RNL_PEER_KEEP_ALIVE_TIME_HISTORY_MASK]:=0;
     fKeepAlivePongTimes[IncomingBlockPacket.fBlockPacket.Pong.SequenceNumber and RNL_PEER_KEEP_ALIVE_TIME_HISTORY_MASK]:=0;

{$if defined(RNL_DEBUG) and defined(RNL_DEBUG_PING)}
     fHost.fInstance.fDebugLock.Acquire;
     try
      writeln('Peer ',fLocalPeerID,': Incoming Pong');
     finally
      fHost.fInstance.fDebugLock.Release;
     end;
{$ifend}

    end;

    RNL_PROTOCOL_BLOCK_PACKET_TYPE_DISCONNECT:begin

     if fState<>RNL_PEER_STATE_DISCONNECTION_ACKNOWLEDGING then begin
      fState:=RNL_PEER_STATE_DISCONNECTION_ACKNOWLEDGING;
      fDisconnectData:=IncomingBlockPacket.fBlockPacket.Disconnect.Data;
      fDisconnectionSequenceNumber:=0;
     end;

     fNextPendingDisconnectionSendTimeout.fValue:=0;

    end;

    RNL_PROTOCOL_BLOCK_PACKET_TYPE_DISCONNECT_ACKNOWLEGDEMENT:begin

     fState:=RNL_PEER_STATE_DISCONNECTION_ACKNOWLEDGING;

     fDisconnectionSequenceNumber:=IncomingBlockPacket.fBlockPacket.DisconnectAcknowledgement.SequenceNumber;

     fNextPendingDisconnectionSendTimeout.fValue:=0;

    end;

    RNL_PROTOCOL_BLOCK_PACKET_TYPE_BANDWIDTH_LIMITS:begin

     OutgoingBlockPacket:=TRNLPeerBlockPacket.Create(self);
     try
      OutgoingBlockPacket.fBlockPacket.Header.TypeAndSubtype:=TRNLInt32(TRNLProtocolBlockPacketType(RNL_PROTOCOL_BLOCK_PACKET_TYPE_BANDWIDTH_LIMITS_ACKNOWLEGDEMENT));
      OutgoingBlockPacket.fBlockPacket.BandwidthLimitsAcknowledgement.SequenceNumber:=IncomingBlockPacket.fBlockPacket.BandwidthLimitsAcknowledgement.SequenceNumber;
     finally
      fOutgoingBlockPackets.Enqueue(OutgoingBlockPacket);
     end;

     if TRNLInt8(TRNLUInt8(IncomingBlockPacket.fBlockPacket.BandwidthLimitsAcknowledgement.SequenceNumber-fReceivedNewHostBandwidthLimitsSequenceNumber))>=0 then begin

      fReceivedNewHostBandwidthLimitsSequenceNumber:=IncomingBlockPacket.fBlockPacket.BandwidthLimitsAcknowledgement.SequenceNumber;

      fRemoteIncomingBandwidthLimit:=TRNLEndianness.HostToLittleEndian32(IncomingBlockPacket.fBlockPacket.BandwidthLimits.IncomingBandwidthLimit);
      fRemoteOutgoingBandwidthLimit:=TRNLEndianness.HostToLittleEndian32(IncomingBlockPacket.fBlockPacket.BandwidthLimits.OutgoingBandwidthLimit);

      UpdateOutgoingBandwidthRateLimiter;

      HostEvent.Type_:=RNL_HOST_EVENT_TYPE_BANDWIDTH_LIMITS;
      HostEvent.BandwidthLimits.Peer:=self;
      fHost.fEventQueue.Enqueue(HostEvent);

     end;

    end;

    RNL_PROTOCOL_BLOCK_PACKET_TYPE_BANDWIDTH_LIMITS_ACKNOWLEGDEMENT:begin

     if IncomingBlockPacket.fBlockPacket.BandwidthLimitsAcknowledgement.SequenceNumber=fSendNewHostBandwidthLimitsSequenceNumber then begin
      fSendNewHostBandwidthLimits:=false;
     end;

    end;

    RNL_PROTOCOL_BLOCK_PACKET_TYPE_MTU_PROBE:begin

     DispatchIncomingMTUProbeBlockPacket(IncomingBlockPacket);

    end;

    RNL_PROTOCOL_BLOCK_PACKET_TYPE_CHANNEL:begin

     if IncomingBlockPacket.fBlockPacket.Channel.ChannelNumber<fCountChannels then begin

      fChannels[IncomingBlockPacket.fBlockPacket.Channel.ChannelNumber].DispatchIncomingBlockPacket(IncomingBlockPacket);

     end;

    end;

   end;

  finally
   IncomingBlockPacket.DecRef;
  end;

 end;

end;

procedure TRNLPeer.DispatchPacketTimeOuts;
var Index:TRNLSizeInt;
    Interval:TRNLInt64;
begin

 Interval:=Min(Max(TRNLInt64(fRetransmissionTimeOut shr 32),
                   TRNLInt64(fHost.fPingInterval.fValue)),
               Min(TRNLInt64(fHost.fPingInterval.fValue*4),
                   Max(TRNLInt64(fHost.fPingInterval.fValue),
                       TRNLInt64(fHost.fConnectionTimeout.fValue shr 2))));

 if (fNextCheckTimeoutsTimeout.fValue=0) or
    (fHost.fTime>=fNextCheckTimeoutsTimeout) then begin

  for Index:=0 to RNL_PEER_KEEP_ALIVE_TIME_HISTORY_SIZE-1 do begin
   if (fKeepAlivePingTimes[Index]<>0) and
      (TRNLTIme.Difference(fHost.fTime,fKeepAlivePingTimes[Index])>=Interval) then begin
    inc(fCountPacketLoss);
    fKeepAlivePingTimes[Index]:=0;
    fKeepAlivePongTimes[Index]:=0;
   end;
  end;

  fNextCheckTimeoutsTimeout:=fHost.fTime+Interval;

 end;

 if (fNextCheckTimeoutsTimeout.Value<>0) and
    (fNextCheckTimeoutsTimeout>=fHost.fTime) then begin
  fHost.fNextPeerEventTime:=TRNLTime.Minimum(fHost.fNextPeerEventTime,fNextCheckTimeoutsTimeout);
 end;

end;

procedure TRNLPeer.DispatchStateActions;
var OutgoingBlockPacket:TRNLPeerBlockPacket;
    HostEvent:TRNLHostEvent;
begin

 case fState of

  RNL_PEER_STATE_CONNECTION_REQUESTING,
  RNL_PEER_STATE_CONNECTION_CHALLENGING,
  RNL_PEER_STATE_CONNECTION_AUTHENTICATING,
  RNL_PEER_STATE_CONNECTION_APPROVING:begin

   // Connection handshake state machine flow

   if fHost.fTime>=fNextPendingConnectionSendTimeout then begin

    fNextPendingConnectionSendTimeout:=fHost.fTime+fHost.fPendingConnectionSendTimeout;

    case fState of
     RNL_PEER_STATE_CONNECTION_REQUESTING:begin
      if assigned(fPendingConnectionHandshakeSendData) and
         (fPendingConnectionHandshakeSendData.fHandshakePacket.Header.PacketType=TRNLUInt32(TRNLProtocolHandshakePacketType(RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_REQUEST))) then begin
       fLocalSalt:=fHost.fRandomGenerator.GetUInt64;
       fConnectionSalt:=fLocalSalt;
       fChecksumPlaceHolder:=fConnectionSalt xor (fConnectionSalt shl 32);
       fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionRequest.OutgoingSalt:=TRNLEndianness.HostToLittleEndian64(fLocalSalt);
       fPendingConnectionHandshakeSendData.Send;
      end else begin
       fState:=RNL_PEER_STATE_DISCONNECTED;
      end;
     end;
     RNL_PEER_STATE_CONNECTION_CHALLENGING:begin
      if assigned(fPendingConnectionHandshakeSendData) and
         (fPendingConnectionHandshakeSendData.fHandshakePacket.Header.PacketType=TRNLUInt32(TRNLProtocolHandshakePacketType(RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_CHALLENGE_RESPONSE))) then begin
       TRNLX25519.GeneratePublicPrivateKeyPair(fHost.fRandomGenerator,
                                               fLocalShortTermPublicKey,
                                               fLocalShortTermPrivateKey);
       fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionChallengeResponse.ShortTermPublicKey:=fLocalShortTermPublicKey;
       fPendingConnectionHandshakeSendData.Send;
      end else begin
       fState:=RNL_PEER_STATE_DISCONNECTED;
      end;
     end;
     RNL_PEER_STATE_CONNECTION_AUTHENTICATING:begin
      if assigned(fPendingConnectionHandshakeSendData) and
         (fPendingConnectionHandshakeSendData.fHandshakePacket.Header.PacketType=TRNLUInt32(TRNLProtocolHandshakePacketType(RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_AUTHENTICATION_RESPONSE))) then begin
       fPendingConnectionHandshakeSendData.Send;
      end else begin
       fState:=RNL_PEER_STATE_DISCONNECTED;
      end;
     end;
     RNL_PEER_STATE_CONNECTION_APPROVING:begin
      if assigned(fPendingConnectionHandshakeSendData) and
         (fPendingConnectionHandshakeSendData.fHandshakePacket.Header.PacketType=TRNLUInt32(TRNLProtocolHandshakePacketType(RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_APPROVAL_RESPONSE))) then begin
       fPendingConnectionHandshakeSendData.Send;
      end else begin
       fState:=RNL_PEER_STATE_DISCONNECTED;
      end;
     end;
    end;

   end;

   if (fNextPendingConnectionSendTimeout.Value<>0) and
      (fNextPendingConnectionSendTimeout>=fHost.fTime) then begin
    fHost.fNextPeerEventTime:=TRNLTime.Minimum(fHost.fNextPeerEventTime,fNextPendingConnectionSendTimeout);
   end;

  end;

  RNL_PEER_STATE_CONNECTED:begin

   FreeAndNil(fPendingConnectionHandshakeSendData);

  end;

  RNL_PEER_STATE_DISCONNECT_LATER,
  RNL_PEER_STATE_DISCONNECTING,
  RNL_PEER_STATE_DISCONNECTION_ACKNOWLEDGING,
  RNL_PEER_STATE_DISCONNECTION_PENDING:begin

   // Disconnection state machine flow

   repeat
    case fState of
     RNL_PEER_STATE_DISCONNECT_LATER:begin
      if fOutgoingBlockPackets.IsEmpty and
         (fUnacknowlegmentedBlockPackets=0) then begin
       fState:=RNL_PEER_STATE_DISCONNECTING;
      end else begin
       break;
      end;
     end;
     RNL_PEER_STATE_DISCONNECTING:begin
      if (fDisconnectionTimeout.fValue<>0) and
         (fHost.fTime>=fDisconnectionTimeout) then begin
       fState:=RNL_PEER_STATE_DISCONNECTION_PENDING;
      end else if (fNextPendingDisconnectionSendTimeout.fValue=0) or
                  (fHost.fTime>=fNextPendingDisconnectionSendTimeout) then begin
       OutgoingBlockPacket:=TRNLPeerBlockPacket.Create(self);
       try
        OutgoingBlockPacket.fBlockPacket.Header.TypeAndSubtype:=TRNLInt32(TRNLProtocolBlockPacketType(RNL_PROTOCOL_BLOCK_PACKET_TYPE_DISCONNECT));
        OutgoingBlockPacket.fBlockPacket.Disconnect.Data:=fDisconnectData;
       finally
        fOutgoingBlockPackets.Enqueue(OutgoingBlockPacket);
       end;
       if fDisconnectionTimeout.fValue=0 then begin
        fDisconnectionTimeout:=fHost.fTime+fHost.fPendingDisconnectionTimeout;
       end;
       fNextPendingDisconnectionSendTimeout:=fHost.fTime+fHost.fPendingDisconnectionSendTimeout;
      end;
      break;
     end;
     RNL_PEER_STATE_DISCONNECTION_ACKNOWLEDGING:begin
      if (fDisconnectionTimeout.fValue<>0) and
         (fHost.fTime>=fDisconnectionTimeout) then begin
       fState:=RNL_PEER_STATE_DISCONNECTION_PENDING;
      end else begin
       if (fNextPendingDisconnectionSendTimeout.fValue=0) or
          (fHost.fTime>=fNextPendingDisconnectionSendTimeout) then begin
        OutgoingBlockPacket:=TRNLPeerBlockPacket.Create(self);
        try
         OutgoingBlockPacket.fBlockPacket.Header.TypeAndSubtype:=TRNLInt32(TRNLProtocolBlockPacketType(RNL_PROTOCOL_BLOCK_PACKET_TYPE_DISCONNECT_ACKNOWLEGDEMENT));
         OutgoingBlockPacket.fBlockPacket.DisconnectAcknowledgement.SequenceNumber:=fDisconnectionSequenceNumber+1;
        finally
         fOutgoingBlockPackets.Enqueue(OutgoingBlockPacket);
        end;
        case fDisconnectionSequenceNumber of
         0,1:begin
          // At this step, we can not be sure yet, that the counterside does know about the disconnection
         end;
         2,3:begin
          // At this step, we can be sure, that the counterside does know about the disconnection
          fDisconnectionSequenceNumber:=4;
         end;
         else begin
          fState:=RNL_PEER_STATE_DISCONNECTION_PENDING;
          continue;
         end;
        end;
        if fDisconnectionTimeout.fValue=0 then begin
         fDisconnectionTimeout:=fHost.fTime+fHost.fPendingDisconnectionTimeout;
        end;
        fNextPendingDisconnectionSendTimeout:=fHost.fTime+fHost.fPendingDisconnectionSendTimeout;
       end;
       break;
      end;
     end;
     RNL_PEER_STATE_DISCONNECTION_PENDING:begin
      HostEvent.Type_:=RNL_HOST_EVENT_TYPE_DISCONNECT;
      HostEvent.Disconnect.Peer:=self;
      HostEvent.Disconnect.Data:=fDisconnectData;
      fHost.fEventQueue.Enqueue(HostEvent);
      fState:=RNL_PEER_STATE_DISCONNECTED;
      break;
     end;
     else begin
      break;
     end;
    end;
   until false;

   if (fDisconnectionTimeout.Value<>0) and
      (fDisconnectionTimeout>=fHost.fTime) then begin
    fHost.fNextPeerEventTime:=TRNLTime.Minimum(fHost.fNextPeerEventTime,fDisconnectionTimeout);
   end;

   if (fNextPendingDisconnectionSendTimeout.Value<>0) and
      (fNextPendingDisconnectionSendTimeout>=fHost.fTime) then begin
    fHost.fNextPeerEventTime:=TRNLTime.Minimum(fHost.fNextPeerEventTime,fNextPendingDisconnectionSendTimeout);
   end;

  end;

 end;

end;

procedure TRNLPeer.DispatchIncomingChannelMessages;
var Channel:TRNLPeerChannel;
begin
 for Channel in fChannels do begin
  Channel.DispatchIncomingMessages;
 end;
end;

procedure TRNLPeer.DispatchOutgoingChannelPackets;
var Channel:TRNLPeerChannel;
begin
 for Channel in fChannels do begin
  Channel.DispatchOutgoingBlockPackets;
 end;
end;

function TRNLPeer.DispatchOutgoingMTUProbeBlockPackets(var aOutgoingPacketBuffer:TRNLOutgoingPacketBuffer):boolean;
var OutgoingBlockPacket:TRNLPeerBlockPacket;
begin

 result:=false;

 while fOutgoingMTUProbeBlockPackets.Peek(OutgoingBlockPacket) do begin

  if OutgoingBlockPacket.fBlockPacket.Header.TypeAndSubtype=TRNLInt32(TRNLProtocolBlockPacketType(RNL_PROTOCOL_BLOCK_PACKET_TYPE_MTU_PROBE)) then begin

   aOutgoingPacketBuffer.Reset(SizeOf(TRNLProtocolNormalPacketHeader),
                               TRNLEndianness.LittleEndianToHost16(OutgoingBlockPacket.fBlockPacket.MTUProbe.Size)-
                               (RNL_IP_HEADER_SIZE+
                                RNL_UDP_HEADER_SIZE));

   if aOutgoingPacketBuffer.HasSpaceFor(OutgoingBlockPacket.Size) and
      fOutgoingMTUProbeBlockPackets.Dequeue then begin

    OutgoingBlockPacket.AppendTo(aOutgoingPacketBuffer);
    inc(fCountSentPackets);

    result:=true;

    break;

   end;

  end else begin

   fOutgoingMTUProbeBlockPackets.Dequeue;

  end;

 end;

end;

function TRNLPeer.DispatchOutgoingBlockPackets(var aOutgoingPacketBuffer:TRNLOutgoingPacketBuffer):boolean;
var OutgoingBlockPacket:TRNLPeerBlockPacket;
begin

 result:=true;

 while fOutgoingBlockPackets.Peek(OutgoingBlockPacket) and
       aOutgoingPacketBuffer.HasSpaceFor(OutgoingBlockPacket.Size) and
       fOutgoingBlockPackets.Dequeue do begin

  try

   OutgoingBlockPacket.AppendTo(aOutgoingPacketBuffer);
   inc(fCountSentPackets);

  finally

   if assigned(OutgoingBlockPacket.fPendingResendOutgoingBlockPacketsList) then begin

    OutgoingBlockPacket.fSentTime:=fHost.fTime;

    inc(OutgoingBlockPacket.fCountSendAttempts);

    if OutgoingBlockPacket.fRoundTripTimeout=0 then begin
     OutgoingBlockPacket.fRoundTripTimeout:=Max(fRetransmissionTimeOut shr 32,1);
     OutgoingBlockPacket.fRoundTripTimeoutLimit:=Max(fRetransmissionTimeOut shr 30,1);
    end;

    if (fNextReliableBlockPacketTimeout.Value=0) or
       (fNextReliableBlockPacketTimeout>=fHost.fTime) then begin
     fNextReliableBlockPacketTimeout:=fHost.fTime+OutgoingBlockPacket.fRoundTripTimeout;
    end;

    OutgoingBlockPacket.fPendingResendOutgoingBlockPacketsList.Add(OutgoingBlockPacket);

    result:=false;

   end else begin

    OutgoingBlockPacket.DecRef;

   end;

  end;

 end;

 if (fNextReliableBlockPacketTimeout.Value<>0) and
    (fNextReliableBlockPacketTimeout>=fHost.fTime) then begin
  fHost.fNextPeerEventTime:=TRNLTime.Minimum(fHost.fNextPeerEventTime,fNextPendingDisconnectionSendTimeout);
 end;

end;

procedure TRNLPeer.DispatchNewHostBandwidthLimits;
var OutgoingBlockPacket:TRNLPeerBlockPacket;
begin

 if not fSendNewHostBandwidthLimits then begin
  exit;
 end;

 if (fSendNewHostBandwidthLimitsNextTimeout.Value<>0) and
    (fSendNewHostBandwidthLimitsNextTimeout<=fHost.fTime) then begin

  OutgoingBlockPacket:=TRNLPeerBlockPacket.Create(self);
  try
   OutgoingBlockPacket.fBlockPacket.Header.TypeAndSubtype:=TRNLInt32(TRNLProtocolBlockPacketType(RNL_PROTOCOL_BLOCK_PACKET_TYPE_BANDWIDTH_LIMITS));
   OutgoingBlockPacket.fBlockPacket.BandwidthLimits.SequenceNumber:=fSendNewHostBandwidthLimitsSequenceNumber;
   OutgoingBlockPacket.fBlockPacket.BandwidthLimits.IncomingBandwidthLimit:=TRNLEndianness.HostToLittleEndian32(fHost.IncomingBandwidthLimit);
   OutgoingBlockPacket.fBlockPacket.BandwidthLimits.OutgoingBandwidthLimit:=TRNLEndianness.HostToLittleEndian32(fHost.OutgoingBandwidthLimit);
  finally
   fOutgoingMTUProbeBlockPackets.Enqueue(OutgoingBlockPacket);
  end;

  fSendNewHostBandwidthLimitsNextTimeout:=fHost.fTime+fSendNewHostBandwidthLimitsInterval;

 end;

 if (fSendNewHostBandwidthLimitsNextTimeout.Value<>0) and
    (fSendNewHostBandwidthLimitsNextTimeout>=fHost.fTime) then begin
  fHost.fNextPeerEventTime:=TRNLTime.Minimum(fHost.fNextPeerEventTime,fSendNewHostBandwidthLimitsNextTimeout);
 end;

end;

procedure TRNLPeer.DispatchMTUProbe;
var OutgoingBlockPacket:TRNLPeerBlockPacket;
    HostEvent:TRNLHostEvent;
begin

 if fMTUProbeIndex<0 then begin
  fMTUProbeNextTimeout:=0;
  exit;
 end;

 if (fMTUProbeNextTimeout.Value<>0) and
    (fMTUProbeNextTimeout<=fHost.fTime) then begin

  if fMTUProbeRemainingTryIterations>0 then begin

   dec(fMTUProbeRemainingTryIterations);
   if fMTUProbeRemainingTryIterations=0 then begin

    dec(fMTUProbeIndex);
    if fMTUProbeIndex<0 then begin
     fMTUProbeNextTimeout:=0;
     HostEvent.Type_:=RNL_HOST_EVENT_TYPE_MTU;
     HostEvent.MTU.Peer:=self;
     HostEvent.MTU.MTU:=fMTU;
     fHost.fEventQueue.Enqueue(HostEvent);
     exit;
    end;

    inc(fMTUProbeSequenceNumber);

    fMTUProbeRemainingTryIterations:=fMTUProbeTryIterationsPerMTUProbeSize;

   end;

   OutgoingBlockPacket:=TRNLPeerBlockPacket.Create(self);
   try
    OutgoingBlockPacket.fBlockPacket.Header.TypeAndSubtype:=TRNLInt32(TRNLProtocolBlockPacketType(RNL_PROTOCOL_BLOCK_PACKET_TYPE_MTU_PROBE));
    OutgoingBlockPacket.fBlockPacket.MTUProbe.SequenceNumber:=TRNLEndianness.HostToLittleEndian16(fMTUProbeSequenceNumber.fValue);
    OutgoingBlockPacket.fBlockPacket.MTUProbe.Phase:=0;
    OutgoingBlockPacket.fBlockPacket.MTUProbe.Size:=TRNLEndianness.HostToLittleEndian16(RNLKnownCommonMTUSizes[fMTUProbeIndex]);
    OutgoingBlockPacket.fBlockPacketDataLength:=RNLKnownCommonMTUSizes[fMTUProbeIndex]-(RNL_IP_HEADER_SIZE+
                                                                                        RNL_UDP_HEADER_SIZE+
                                                                                        SizeOf(TRNLProtocolNormalPacketHeader)+
                                                                                        SizeOf(TRNLProtocolBlockPacketMTUProbe));
    SetLength(OutgoingBlockPacket.fBlockPacketData,OutgoingBlockPacket.fBlockPacketDataLength);
    OutgoingBlockPacket.fBlockPacket.MTUProbe.PayloadDataLength:=TRNLEndianness.LittleEndianToHost16(OutgoingBlockPacket.fBlockPacketDataLength);
    if OutgoingBlockPacket.fBlockPacketDataLength>0 then begin
     fHost.fRandomGenerator.GetRandomBytes(OutgoingBlockPacket.fBlockPacketData[0],OutgoingBlockPacket.fBlockPacketDataLength);
    end;
   finally
    fOutgoingMTUProbeBlockPackets.Enqueue(OutgoingBlockPacket);
   end;

  end;

  fMTUProbeNextTimeout:=fHost.fTime+fMTUProbeInterval;

 end;

 if (fMTUProbeNextTimeout.Value<>0) and
    (fMTUProbeNextTimeout>=fHost.fTime) then begin
  fHost.fNextPeerEventTime:=TRNLTime.Minimum(fHost.fNextPeerEventTime,fMTUProbeNextTimeout);
 end;

end;

procedure TRNLPeer.DispatchKeepAlive(var aOutgoingPacketBuffer:TRNLOutgoingPacketBuffer;const aCanDoPingIfNeeded:boolean);
var PingInterval:TRNLUInt64;
    PingBlockPacket:TRNLProtocolBlockPacketPing;
begin

 if aCanDoPingIfNeeded then begin

  PingInterval:=fHost.fPingInterval;

  if (fOutgoingBlockPackets.Count=0) and
     (fUnacknowlegmentedBlockPackets=0) and
     (fHost.fTime>=(fLastReceivedDataTime+PingInterval)) and
     (fHost.fTime>=(fLastPingSentTime+PingInterval)) and
     aOutgoingPacketBuffer.HasSpaceFor(SizeOf(TRNLProtocolBlockPacketPing)) then begin
   fLastPingSentTime:=fHost.fTime;
   fNextPingSendTime:=fHost.fTime+PingInterval;
   PingBlockPacket.Header.TypeAndSubtype:=TRNLInt32(TRNLProtocolBlockPacketType(RNL_PROTOCOL_BLOCK_PACKET_TYPE_PING));
   PingBlockPacket.SequenceNumber:=fOutgoingPingSequenceNumber;
   aOutgoingPacketBuffer.Write(PingBlockPacket,SizeOf(TRNLProtocolBlockPacketPing));
   fKeepAlivePingTimes[fOutgoingPingSequenceNumber and RNL_PEER_KEEP_ALIVE_TIME_HISTORY_MASK]:=fHost.fTime;
   fKeepAlivePongTimes[fOutgoingPingSequenceNumber and RNL_PEER_KEEP_ALIVE_TIME_HISTORY_MASK]:=0;
   inc(fOutgoingPingSequenceNumber);
   inc(fCountSentPackets);
{$if defined(RNL_DEBUG) and defined(RNL_DEBUG_PING)}
   fHost.fInstance.fDebugLock.Acquire;
   try
    writeln('Peer ',fLocalPeerID,': Outgoing Ping');
   finally
    fHost.fInstance.fDebugLock.Release;
   end;
{$ifend}
  end;

 end;

 if (fNextPingSendTime.Value<>0) and
    (fNextPingSendTime>=fHost.fTime) then begin
  fHost.fNextPeerEventTime:=TRNLTime.Minimum(fHost.fNextPeerEventTime,fNextPingSendTime);
 end;

end;

procedure TRNLPeer.DispatchIncomingPacket(const aPayloadData;const aPayloadDataLength:TRNLSizeUInt;const aSentTime:TRNLUInt64);
var PayloadDataPosition,BlockPacketSize:TRNLSizeUInt;
    BlockPacket:PRNLProtocolBlockPacket;
    BlockPacketType:TRNLProtocolBlockPacketType;
    BlockPacketPayload:TRNLPointer;
    PeerBlockPacket:TRNLPeerBlockPacket;
begin

 fLastReceivedDataTime:=fHost.fTime;

 PayloadDataPosition:=0;

 while (PayloadDataPosition+SizeOf(TRNLProtocolBlockPacketHeader))<=aPayloadDataLength do begin

  BlockPacket:=TRNLPointer(@PRNLUInt8Array(TRNLPointer(@aPayloadData))^[PayloadDataPosition]);

  BlockPacketType:=TRNLProtocolBlockPacketType(TRNLInt32(BlockPacket^.Header.TypeAndSubtype and $f));

  if not (BlockPacketType in [TRNLProtocolBlockPacketType(Low(TRNLProtocolBlockPacketType))..TRNLProtocolBlockPacketType(High(TRNLProtocolBlockPacketType))]) then begin
   break;
  end;

  BlockPacketSize:=RNLProtocolBlockPacketSizes[BlockPacketType];

  if (PayloadDataPosition+BlockPacketSize)>aPayloadDataLength then begin
   break;
  end;
  inc(PayloadDataPosition,BlockPacketSize);

  case BlockPacketType of

   RNL_PROTOCOL_BLOCK_PACKET_TYPE_PING:begin

    PeerBlockPacket:=TRNLPeerBlockPacket.Create(self);
    try
     PeerBlockPacket.fSentTime:=aSentTime;
     PeerBlockPacket.fReceivedTime:=fHost.fTime;
     PRNLProtocolBlockPacketPing(TRNLPointer(@PeerBlockPacket.fBlockPacket))^:=PRNLProtocolBlockPacketPing(TRNLPointer(BlockPacket))^;
    finally
     fIncomingBlockPackets.Enqueue(PeerBlockPacket);
    end;

   end;

   RNL_PROTOCOL_BLOCK_PACKET_TYPE_PONG:begin

    BlockPacket.Pong.SentTime:=TRNLEndianness.LittleEndianToHost16(BlockPacket.Pong.SentTime);

    PeerBlockPacket:=TRNLPeerBlockPacket.Create(self);
    try
     PeerBlockPacket.fSentTime:=aSentTime;
     PeerBlockPacket.fReceivedTime:=fHost.fTime;
     PRNLProtocolBlockPacketPong(TRNLPointer(@PeerBlockPacket.fBlockPacket))^:=PRNLProtocolBlockPacketPong(TRNLPointer(BlockPacket))^;
    finally
     fIncomingBlockPackets.Enqueue(PeerBlockPacket);
    end;

   end;

   RNL_PROTOCOL_BLOCK_PACKET_TYPE_DISCONNECT:begin

    PeerBlockPacket:=TRNLPeerBlockPacket.Create(self);
    try
     PeerBlockPacket.fSentTime:=aSentTime;
     PeerBlockPacket.fReceivedTime:=fHost.fTime;
     PRNLProtocolBlockPacketDisconnect(TRNLPointer(@PeerBlockPacket.fBlockPacket))^:=PRNLProtocolBlockPacketDisconnect(TRNLPointer(BlockPacket))^;
    finally
     fIncomingBlockPackets.Enqueue(PeerBlockPacket);
    end;

   end;

   RNL_PROTOCOL_BLOCK_PACKET_TYPE_DISCONNECT_ACKNOWLEGDEMENT:begin

    PeerBlockPacket:=TRNLPeerBlockPacket.Create(self);
    try
     PeerBlockPacket.fSentTime:=aSentTime;
     PeerBlockPacket.fReceivedTime:=fHost.fTime;
     PRNLProtocolBlockPacketDisconnectAcknowledgement(TRNLPointer(@PeerBlockPacket.fBlockPacket))^:=PRNLProtocolBlockPacketDisconnectAcknowledgement(TRNLPointer(BlockPacket))^;
    finally
     fIncomingBlockPackets.Enqueue(PeerBlockPacket);
    end;

   end;

   RNL_PROTOCOL_BLOCK_PACKET_TYPE_BANDWIDTH_LIMITS:begin

    PeerBlockPacket:=TRNLPeerBlockPacket.Create(self);
    try
     PeerBlockPacket.fSentTime:=aSentTime;
     PeerBlockPacket.fReceivedTime:=fHost.fTime;
     PRNLProtocolBlockPacketBandwidthLimits(TRNLPointer(@PeerBlockPacket.fBlockPacket))^:=PRNLProtocolBlockPacketBandwidthLimits(TRNLPointer(BlockPacket))^;
    finally
     fIncomingBlockPackets.Enqueue(PeerBlockPacket);
    end;

   end;

   RNL_PROTOCOL_BLOCK_PACKET_TYPE_BANDWIDTH_LIMITS_ACKNOWLEGDEMENT:begin

    PeerBlockPacket:=TRNLPeerBlockPacket.Create(self);
    try
     PeerBlockPacket.fSentTime:=aSentTime;
     PeerBlockPacket.fReceivedTime:=fHost.fTime;
     PRNLProtocolBlockPacketBandwidthLimitsAcknowledgement(TRNLPointer(@PeerBlockPacket.fBlockPacket))^:=PRNLProtocolBlockPacketBandwidthLimitsAcknowledgement(TRNLPointer(BlockPacket))^;
    finally
     fIncomingBlockPackets.Enqueue(PeerBlockPacket);
    end;

   end;

   RNL_PROTOCOL_BLOCK_PACKET_TYPE_MTU_PROBE:begin

    if (PayloadDataPosition+TRNLEndianness.LittleEndianToHost16(BlockPacket^.MTUProbe.PayloadDataLength))>aPayloadDataLength then begin
     break;
    end;

    BlockPacketPayload:=TRNLPointer(@PRNLUInt8Array(TRNLPointer(@aPayloadData))^[PayloadDataPosition]);
    inc(PayloadDataPosition,TRNLEndianness.LittleEndianToHost16(BlockPacket^.MTUProbe.PayloadDataLength));

    PeerBlockPacket:=TRNLPeerBlockPacket.Create(self);
    try
     PeerBlockPacket.fSentTime:=aSentTime;
     PeerBlockPacket.fReceivedTime:=fHost.fTime;
     PRNLProtocolBlockPacketMTUProbe(TRNLPointer(@PeerBlockPacket.fBlockPacket))^:=PRNLProtocolBlockPacketMTUProbe(TRNLPointer(BlockPacket))^;
     PeerBlockPacket.fBlockPacketDataLength:=TRNLEndianness.LittleEndianToHost16(BlockPacket^.MTUProbe.PayloadDataLength);
     if PeerBlockPacket.fBlockPacketDataLength>0 then begin
      SetLength(PeerBlockPacket.fBlockPacketData,PeerBlockPacket.fBlockPacketDataLength);
      Move(BlockPacketPayload^,PeerBlockPacket.fBlockPacketData[0],PeerBlockPacket.fBlockPacketDataLength);
     end;
    finally
     fIncomingBlockPackets.Enqueue(PeerBlockPacket);
    end;

   end;

   RNL_PROTOCOL_BLOCK_PACKET_TYPE_CHANNEL:begin

    BlockPacket^.Channel.PayloadDataLength:=TRNLEndianness.LittleEndianToHost16(BlockPacket^.Channel.PayloadDataLength);

    if (PayloadDataPosition+BlockPacket^.Channel.PayloadDataLength)>aPayloadDataLength then begin
     break;
    end;

    BlockPacketPayload:=TRNLPointer(@PRNLUInt8Array(TRNLPointer(@aPayloadData))^[PayloadDataPosition]);
    inc(PayloadDataPosition,BlockPacket^.Channel.PayloadDataLength);

    PeerBlockPacket:=TRNLPeerBlockPacket.Create(self);
    try
     PeerBlockPacket.fSentTime:=aSentTime;
     PeerBlockPacket.fReceivedTime:=fHost.fTime;
     PRNLProtocolBlockPacketChannel(TRNLPointer(@PeerBlockPacket.fBlockPacket))^:=PRNLProtocolBlockPacketChannel(TRNLPointer(BlockPacket))^;
     PeerBlockPacket.fBlockPacketDataLength:=BlockPacket^.Channel.PayloadDataLength;
     if PeerBlockPacket.fBlockPacketDataLength>0 then begin
      SetLength(PeerBlockPacket.fBlockPacketData,PeerBlockPacket.fBlockPacketDataLength);
      Move(BlockPacketPayload^,PeerBlockPacket.fBlockPacketData[0],PeerBlockPacket.fBlockPacketDataLength);
     end;
    finally
     fIncomingBlockPackets.Enqueue(PeerBlockPacket);
    end;

   end;

  end;

 end;

end;

procedure TRNLPeer.DispatchIncomingPackets;
var NormalPacketHeader:PRNLProtocolNormalPacketHeader;
    EncryptedPacketSequenceNumber:TRNLUInt64;
    Index:TRNLInt32;
    PacketDataLength,PayloadDataLength,
    OriginalDecompressedDataLength,DecompressedDataLength:TRNLSizeint;
    PayloadData:TRNLPointer;
    PayloadMAC:TRNLCipherMAC;
    CipherNonce:TRNLCipherNonce;
    PacketData:TBytes;
begin

 PacketData:=nil;

 try

  while fIncomingPacketQueue.Dequeue(PacketData) do begin

   try

    PacketDataLength:=length(PacketData);

    NormalPacketHeader:=@PacketData[0];

    if NormalPacketHeader^.Not255=$ff then begin
     // 255? Ups, there's probably something went wrong then :-)
     continue;
    end;

    fIncomingBandwidthRateTracker.AddUnits(PacketDataLength shl 3);

    if not (fState in RNLNormalPacketPeerStates) then begin
     continue;
    end;

    EncryptedPacketSequenceNumber:=TRNLEndianness.LittleEndianToHost64(NormalPacketHeader^.EncryptedPacketSequenceNumber);

{$if defined(RNL_DEBUG) and false}
    fInstance.fDebugLock.Acquire;
    try
     writeln(Peer.fIncomingEncryptedPacketSequenceNumber,' ',EncryptedPacketSequenceNumber);
    finally
     fInstance.fDebugLock.Release;
    end;
{$ifend}

    begin
     // Replay protection based on the encrypted packet sequence number
     //   To enable playback protection, RNL performs the following steps:
     //     1. Encrypted packets are sent with 64-bit sequence numbers that
     //        start at zero and increase with each packet sent.
     //     2. The sequence number is included in the packet header and
     //        can be read by the recipient of a packet before decryption.
     //     3. The sequence number is used as a part of the nonce for packet
     //        encryption, so that any change to the sequence number does not
     //        pass the encryption signature check.
     //   The replay protection algorithm is as follows:
     //     1. Any packet older than the sequence number received last, minus the
     //        size of the replay sequence number window size, is discarded on the
     //        receiver side.
     //     2. If a packet arrives with a sequence number that is newer than the
     //        last received sequence number, the most recent sequence number on
     //        the receiver side is updated and the packet is accepted.
     //     3. If a packet arrives that is within the replay sequence window size
     //        of the last sequence number, it is only accepted if its sequence
     //        number has not yet been received, otherwise it is ignored.
     // It is basically almost the same what yojimbo respectively netcode.io does also.
     if TRNLUInt32(length(fIncomingEncryptedPacketSequenceBuffer))<>fHost.fEncryptedPacketSequenceWindowSize then begin
      SetLength(fIncomingEncryptedPacketSequenceBuffer,fHost.fEncryptedPacketSequenceWindowSize);
      FillChar(fIncomingEncryptedPacketSequenceBuffer[0],
               fHost.fEncryptedPacketSequenceWindowSize*SizeOf(TRNLUInt64),
               #$ff);
     end;
     if ((EncryptedPacketSequenceNumber and TRNLUInt64($8000000000000000))<>0) or
        ((EncryptedPacketSequenceNumber+fHost.fEncryptedPacketSequenceWindowSize)<=fIncomingEncryptedPacketSequenceNumber) then begin
      continue;
     end else if fIncomingEncryptedPacketSequenceNumber<EncryptedPacketSequenceNumber then begin
      fIncomingEncryptedPacketSequenceNumber:=EncryptedPacketSequenceNumber;
     end;
     Index:=EncryptedPacketSequenceNumber and fHost.fEncryptedPacketSequenceWindowMask;
     if (fIncomingEncryptedPacketSequenceBuffer[Index]<>TRNLUInt64($ffffffffffffffff)) and
        (fIncomingEncryptedPacketSequenceBuffer[Index]>=EncryptedPacketSequenceNumber) then begin
      continue;
     end;
     fIncomingEncryptedPacketSequenceBuffer[Index]:=EncryptedPacketSequenceNumber;
    end;

    PayloadData:=TRNLPointer(@PRNLUInt8Array(TRNLPointer(@PacketData[0]))^[SizeOf(TRNLProtocolNormalPacketHeader)]);

    PayloadDataLength:=PacketDataLength-SizeOf(TRNLProtocolNormalPacketHeader);

    if PayloadDataLength=0 then begin
     continue;
    end;

    TRNLMemoryAccess.StoreLittleEndianUInt64(CipherNonce.ui64[0],EncryptedPacketSequenceNumber);
    TRNLMemoryAccess.StoreLittleEndianUInt64(CipherNonce.ui64[1],TRNLEndianness.LittleEndianToHost64(fConnectionNonce));
    TRNLMemoryAccess.StoreLittleEndianUInt64(CipherNonce.ui64[2],fConnectionSalt);

    PayloadMAC:=NormalPacketHeader^.PayloadMAC;

    FillChar(NormalPacketHeader^.PayloadMAC,SizeOf(TRNLCipherMAC),#$00);

    if not TRNLAuthenticatedEncryption.Decrypt(PayloadData^,
                                               fSharedSecretKey,
                                               CipherNonce,
                                               PayloadMAC,
                                               NormalPacketHeader^,
                                               SizeOf(TRNLProtocolNormalPacketHeader),
                                               PayloadData^,
                                               PayloadDataLength) then begin
{$if defined(RNL_DEBUG) and defined(RNL_DEBUG_SECURITY_EXTENDED)}
     fInstance.fDebugLock.Acquire;
     try
      if assigned(Peer) then begin
       writeln('DP: ',Peer.fSharedSecretKey.ui32[0],' ',Peer.fSharedSecretKey.ui32[1],' ',Peer.fSharedSecretKey.ui32[2],' ',Peer.fSharedSecretKey.ui32[3],' ',TRNLUInt32(fReceivedDataLength)-ReceivedDataOffset);
      end else begin
       writeln('DH: ',Peer.fSharedSecretKey.ui32[0],' ',Peer.fSharedSecretKey.ui32[1],' ',Peer.fSharedSecretKey.ui32[2],' ',Peer.fSharedSecretKey.ui32[3],' ',TRNLUInt32(fReceivedDataLength)-ReceivedDataOffset);
      end;
     finally
      fInstance.fDebugLock.Release;
     end;
{$ifend}
     continue;
    end;

    if (NormalPacketHeader^.Flags and RNL_PROTOCOL_PACKET_HEADER_FLAG_COMPRESSED)<>0 then begin

     if not assigned(fHost.fCompressor) then begin
      continue;
     end;

     OriginalDecompressedDataLength:=TRNLMemoryAccess.LoadLittleEndianUInt16(PayloadData^);
     if OriginalDecompressedDataLength=0 then begin
      continue;
     end;

     DecompressedDataLength:=fHost.fCompressor.Decompress(@PRNLUInt8Array(PayloadData)^[SizeOf(TRNLUInt16)],
                                                          PayloadDataLength-SizeOf(TRNLUInt16),
                                                          @fHost.fCompressionBuffer[0],
                                                          OriginalDecompressedDataLength);

     if (DecompressedDataLength=0) or
        (DecompressedDataLength<>OriginalDecompressedDataLength) then begin
      continue;
     end;

{$if defined(RNL_DEBUG) and defined(RNL_DEBUG_COMPRESS)}
     fHost.fInstance.fDebugLock.Acquire;
     try
      writeln('Peer ',fLocalPeerID,': ',
              'compressed ',PayloadDataLength-SizeOf(TRNLUInt16),' => uncompressed ',DecompressedDataLength,' ',
              '(',((PayloadDataLength-SizeOf(TRNLUInt16))*100.0)/DecompressedDataLength:1:1,'%)');
     finally
      fHost.fInstance.fDebugLock.Release;
     end;
{$ifend}

     PayloadData:=@fHost.fCompressionBuffer[0];
     PayloadDataLength:=DecompressedDataLength;

     PacketData:=nil;

    end;

    DispatchIncomingPacket(PayloadData^,
                           PayloadDataLength,
                           TRNLEndianness.LittleEndianToHost16(NormalPacketHeader^.SentTime));

   finally
    PacketData:=nil;
   end;

  end;

 finally

  PacketData:=nil;

 end;

end;

function TRNLPeer.DispatchOutgoingPackets:boolean;
var OutgoingPacketData:TRNLPointer;
    OutgoingPacketDataLength,CompressedDataLength:TRNLSizeInt;
    NormalPacketHeader:TRNLProtocolNormalPacketHeader;
    CipherNonce:TRNLCipherNonce;
    Buffers:array[0..1] of TRNLBuffer;
    OutgoingPacketBuffer:PRNLOutgoingPacketBuffer;
    IsMTUProbe:boolean;
begin

 result:=true;

 OutgoingPacketBuffer:=@fHost.fOutgoingPacketBuffer;

 if fState in [RNL_PEER_STATE_CONNECTED,
               RNL_PEER_STATE_DISCONNECT_LATER] then begin
  DispatchOutgoingChannelPackets;
 end;

 repeat

  IsMTUProbe:=DispatchOutgoingMTUProbeBlockPackets(OutgoingPacketBuffer^);

  if not IsMTUProbe then begin

   OutgoingPacketBuffer^.Reset(SizeOf(TRNLProtocolNormalPacketHeader),
                               fMTU-(RNL_IP_HEADER_SIZE+RNL_UDP_HEADER_SIZE));

   DispatchKeepAlive(OutgoingPacketBuffer^,
                     DispatchOutgoingBlockPackets(OutgoingPacketBuffer^));

  end;

  if OutgoingPacketBuffer^.fSize>0 then begin

   OutgoingPacketData:=@OutgoingPacketBuffer^.fData[0];
   OutgoingPacketDataLength:=OutgoingPacketBuffer^.fSize;

   NormalPacketHeader.PeerID:=fRemotePeerID;
   NormalPacketHeader.Flags:=0;
   NormalPacketHeader.Not255:=0;

   if assigned(fHost.fCompressor) and
      (OutgoingPacketDataLength>SizeOf(TRNLUInt16)) and
      (OutgoingPacketDataLength<65536) and
      not IsMTUProbe then begin

    CompressedDataLength:=fHost.fCompressor.Compress(OutgoingPacketData,
                                                     OutgoingPacketDataLength,
                                                     @fHost.fCompressionBuffer[SizeOf(TRNLUInt16)],
                                                     OutgoingPacketDataLength-SizeOf(TRNLUInt16));

    if (CompressedDataLength>0) and (CompressedDataLength<(OutgoingPacketDataLength-SizeOf(TRNLUInt16))) then begin
{$if defined(RNL_DEBUG) and defined(RNL_DEBUG_COMPRESS)}
     fHost.fInstance.fDebugLock.Acquire;
     try
      writeln('Peer ',fLocalPeerID,': ',
              'uncompressed ',OutgoingPacketDataLength,' => compressed ',CompressedDataLength,' ',
              '(',(CompressedDataLength*100.0)/OutgoingPacketDataLength:1:1,'%)');
     finally
      fHost.fInstance.fDebugLock.Release;
     end;
{$ifend}

     TRNLMemoryAccess.StoreLittleEndianUInt16(fHost.fCompressionBuffer[0],OutgoingPacketDataLength);

     OutgoingPacketData:=@fHost.fCompressionBuffer[0];
     OutgoingPacketDataLength:=SizeOf(TRNLUInt16)+CompressedDataLength;
     NormalPacketHeader.Flags:=NormalPacketHeader.Flags or RNL_PROTOCOL_PACKET_HEADER_FLAG_COMPRESSED;

    end;

   end;

   NormalPacketHeader.SentTime:=TRNLEndianness.HostToLittleEndian16(TRNLUInt16(fHost.fTime.fValue));

   NormalPacketHeader.EncryptedPacketSequenceNumber:=TRNLEndianness.HostToLittleEndian64(fOutgoingEncryptedPacketSequenceNumber);

   FillChar(NormalPacketHeader.PayloadMAC,SizeOf(TRNLCipherMAC),#0);

   TRNLMemoryAccess.StoreLittleEndianUInt64(CipherNonce.ui64[0],fOutgoingEncryptedPacketSequenceNumber);
   TRNLMemoryAccess.StoreLittleEndianUInt64(CipherNonce.ui64[1],fConnectionNonce);
   TRNLMemoryAccess.StoreLittleEndianUInt64(CipherNonce.ui64[2],fConnectionSalt);

   inc(fOutgoingEncryptedPacketSequenceNumber);

   if not TRNLAuthenticatedEncryption.Encrypt(OutgoingPacketData^,
                                              fSharedSecretKey,
                                              CipherNonce,
                                              NormalPacketHeader.PayloadMAC,
                                              NormalPacketHeader,
                                              SizeOf(TRNLProtocolNormalPacketHeader),
                                              OutgoingPacketData^,
                                              OutgoingPacketDataLength
                                             ) then begin
    continue;
   end;

   Buffers[0].Data:=@NormalPacketHeader;
   Buffers[0].DataLength:=SizeOf(TRNLProtocolNormalPacketHeader);

   Buffers[1].Data:=OutgoingPacketData;
   Buffers[1].DataLength:=OutgoingPacketDataLength;

   result:=SendBuffers(Buffers)<>RNL_NETWORK_SEND_RESULT_ERROR;

   if result then begin
    fLastSentDataTime:=fHost.fTime;
   end;

  end else begin

   break;

  end;

 until fOutgoingBlockPackets.IsEmpty;

end;

function TRNLPeer.DispatchPeer:boolean;
var HostEvent:TRNLHostEvent;
begin

 result:=true;

 if fState=RNL_PEER_STATE_DISCONNECTED then begin
  exit;
 end;

 if TRNLTime.Difference(fLastReceivedDataTime,Host.fTime)>=fHost.fConnectionTimeout then begin
  fState:=RNL_PEER_STATE_DISCONNECTED;
  HostEvent.Type_:=RNL_HOST_EVENT_TYPE_DISCONNECT;
  HostEvent.Disconnect.Peer:=self;
  HostEvent.Disconnect.Data:=0;
  fHost.fEventQueue.Enqueue(HostEvent);
  exit;
 end;

 fIncomingBandwidthRateTracker.SetTime(fHost.fTime);
 fIncomingBandwidthRateTracker.Update;

 fOutgoingBandwidthRateTracker.SetTime(fHost.fTime);
 fOutgoingBandwidthRateTracker.Update;

 DispatchNewHostBandwidthLimits;

 DispatchMTUProbe;

 DispatchIncomingPackets;

 DispatchIncomingBlockPackets;

 DispatchIncomingChannelMessages;

 UpdatePatchLossStatistics;

 DispatchPacketTimeOuts;

 DispatchStateActions;

 result:=DispatchOutgoingPackets;

end;

procedure TRNLPeer.SendNewHostBandwidthLimits;
begin
 if not fSendNewHostBandwidthLimits then begin
  fSendNewHostBandwidthLimits:=true;
  fSendNewHostBandwidthLimitsInterval:=fHost.fPendingSendNewBandwidthLimitsSendTimeout;
  fSendNewHostBandwidthLimitsNextTimeout:=fHost.fTime;
 end;
 inc(fSendNewHostBandwidthLimitsSequenceNumber);
end;

function TRNLPeer.SendPacket(const aData;const aDataLength:TRNLSizeUInt):TRNLNetworkSendResult;
var DataLength:TRNLSizeUInt;
begin
 DataLength:=aDataLength shl 3;
 if (DataLength=0) or
    fOutgoingBandwidthRateLimiter.CanProceed(DataLength,fHost.fTime) then begin
  result:=fHost.SendPacket(fAddress,aData,aDataLength);
  if result=RNL_NETWORK_SEND_RESULT_OK then begin
   fOutgoingBandwidthRateLimiter.AddAmount(DataLength,fHost.fTime);
   fOutgoingBandwidthRateTracker.AddUnits(DataLength);
  end;
 end else begin
  // Drop the whole outgoing UDP packet for to satisfy the outgoing bandwidth limit (=> intended artificial packet loss)
  result:=RNL_NETWORK_SEND_RESULT_BANDWIDTH_RATE_LIMITER_DROP;
 end;
end;

function TRNLPeer.SendBuffers(const aBuffers:array of TRNLBuffer):TRNLNetworkSendResult;
var Index:TRNLSizeInt;
    DataLength:TRNLSizeUInt;
begin
 DataLength:=0;
 for Index:=0 to length(aBuffers)-1 do begin
  inc(DataLength,aBuffers[Index].DataLength);
 end;
 DataLength:=DataLength shl 3;
 if (DataLength=0) or
    fOutgoingBandwidthRateLimiter.CanProceed(DataLength,fHost.fTime) then begin
  result:=fHost.SendBuffers(fAddress,aBuffers);
  if result=RNL_NETWORK_SEND_RESULT_OK then begin
   fOutgoingBandwidthRateLimiter.AddAmount(DataLength,fHost.fTime);
   fOutgoingBandwidthRateTracker.AddUnits(DataLength);
  end;
 end else begin
  // Drop the whole outgoing UDP packet for to satisfy the outgoing bandwidth limit (=> intended artificial packet loss)
  result:=RNL_NETWORK_SEND_RESULT_BANDWIDTH_RATE_LIMITER_DROP;
 end;
end;

procedure TRNLPeer.Disconnect(const aData:TRNLUInt64=0;const aDelayed:boolean=false);
begin
 if fState in [RNL_PEER_STATE_DISCONNECTED,
               RNL_PEER_STATE_DISCONNECT_LATER,
               RNL_PEER_STATE_DISCONNECTING,
               RNL_PEER_STATE_DISCONNECTION_ACKNOWLEDGING,
               RNL_PEER_STATE_DISCONNECTION_PENDING] then begin
  exit;
 end;
 if aDelayed then begin
  fState:=RNL_PEER_STATE_DISCONNECT_LATER;
 end else begin
  fState:=RNL_PEER_STATE_DISCONNECTING;
 end;
 fDisconnectData:=aData;
end;

procedure TRNLPeer.MTUProbe(const aTryIterationsPerMTUProbeSize:TRNLUInt32=5;const aMTUProbeInterval:TRNLUInt64=100);
begin

 fMTUProbeIndex:=High(RNLKnownCommonMTUSizes);

 inc(fMTUProbeSequenceNumber);

 fMTUProbeTryIterationsPerMTUProbeSize:=aTryIterationsPerMTUProbeSize;

 fMTUProbeRemainingTryIterations:=fMTUProbeTryIterationsPerMTUProbeSize;

 fMTUProbeInterval:=aMTUProbeInterval;

 fMTUProbeNextTimeout:=fHost.fTime;

end;

constructor TRNLHost.Create(const aInstance:TRNLInstance;const aNetwork:TRNLNetwork);
var Index:TRNLInt32;
begin

 inherited Create;

 fInstance:=aInstance;

 fNetwork:=aNetwork;

 fRandomGenerator:=TRNLRandomGenerator.Create;

 fPeerIDManager:=TRNLIDManager.Create;

 fPeerIDMap:=TRNLHostPeerIDMap.Create;

 fPeerList:=TRNLHostPeerList.Create(false);

 fCountPeers:=0;

 fTime:=0;

 fNextPeerEventTime.fValue:=TRNLUInt64(High(TRNLUInt64));

 fEventQueue:=TRNLHostEventQueue.Create;

 fAddress.Host:=RNL_HOST_ANY;
 fAddress.Port:=0;

 fPointerToAddress:=@fAddress;

 fAllowIncomingConnections:=true;

 for Index:=Low(TRNLPeerChannelTypes) to High(TRNLPeerChannelTypes) do begin
  case Index and 3 of
   0:begin
    fChannelTypes[Index]:=RNL_PEER_RELIABLE_ORDERED_CHANNEL;
   end;
   1:begin
    fChannelTypes[Index]:=RNL_PEER_RELIABLE_UNORDERED_CHANNEL;
   end;
   2:begin
    fChannelTypes[Index]:=RNL_PEER_UNRELIABLE_ORDERED_CHANNEL;
   end;
   else begin
    fChannelTypes[Index]:=RNL_PEER_UNRELIABLE_UNORDERED_CHANNEL;
   end;
  end;
 end;

 fMaximumCountPeers:=16;

 fMaximumCountChannels:=RNL_MAXIMUM_PEER_CHANNELS;

 fIncomingBandwidthLimit:=0;

 fOutgoingBandwidthLimit:=0;

 SetReliableChannelBlockPacketWindowSize(1024);

 fMaximumMessageSize:=16777216;

 fReceiveBufferSize:=262144;

 fSendBufferSize:=262144;

 SetMTU(1500);

 fMTUDoFragment:=true;

 SetConnectionTimeout(0);

 SetPingInterval(0);

 SetEncryptedPacketSequenceWindowSize(256);

 fProtocolID:=0;

 fSockets[0]:=RNL_SOCKET_NULL;
 fSockets[1]:=RNL_SOCKET_NULL;

 fSalt:=fRandomGenerator.GetUInt64;

 TRNLED25519.GeneratePublicPrivateKeyPair(fRandomGenerator,fLongTermPublicKey,fLongTermPrivateKey);

 fPendingConnectionTimeout:=10000;

 fPendingConnectionSendTimeout:=100;

 fPendingDisconnectionTimeout:=5000;

 fPendingDisconnectionSendTimeout:=50;

 fPendingSendNewBandwidthLimitsSendTimeout:=50;

 fRateLimiterHostAddressBurst:=20;

 fRateLimiterHostAddressPeriod:=1000;

 fOnCheckConnectionToken:=nil;

 fOnCheckAuthenticationToken:=nil;

 fTotalReceivedData:=0;

 fTotalReceivedPackets:=0;

 fConnectionCandidateHashTable:=nil;

 fConnectionKnownCandidateHostAddressHashTable:=nil;

 fIncomingBandwidthRateTracker.Reset;

 fOutgoingBandwidthRateTracker.Reset;

 Initialize(fOutgoingPacketBuffer);

end;

destructor TRNLHost.Destroy;
begin

 fEventQueue.Free;

 while fPeerList.Count>0 do begin
  fPeerList[fPeerList.Count-1].Free;
 end;

 fPeerList.Free;

 fRandomGenerator.Free;

 if assigned(fConnectionCandidateHashTable) then begin
  FreeMem(fConnectionCandidateHashTable);
  fConnectionCandidateHashTable:=nil;
 end;

 if assigned(fConnectionKnownCandidateHostAddressHashTable) then begin
  FreeMem(fConnectionKnownCandidateHostAddressHashTable);
  fConnectionKnownCandidateHostAddressHashTable:=nil;
 end;

 fPeerIDMap.Free;

 fPeerIDManager.Free;

 Finalize(fOutgoingPacketBuffer);

 FreeAndNil(fCompressor);

 inherited Destroy;
end;

procedure TRNLHost.SetReliableChannelBlockPacketWindowSize(const aReliableChannelBlockPacketWindowSize:TRNLUInt32);
begin
 fReliableChannelBlockPacketWindowSize:=Min(TRNLMath.RoundUpToPowerOfTwo32(aReliableChannelBlockPacketWindowSize),65536);
 fReliableChannelBlockPacketWindowMask:=fReliableChannelBlockPacketWindowSize-1;
end;

procedure TRNLHost.BroadcastNewBandwidthLimits;
var Peer:TRNLPeer;
begin
 for Peer in fPeerList do begin
  if Peer.fState in [RNL_PEER_STATE_CONNECTED,
                     RNL_PEER_STATE_DISCONNECT_LATER] then begin
   Peer.SendNewHostBandwidthLimits;
  end;
 end;
end;

procedure TRNLHost.SetIncomingBandwidthLimit(const aIncomingBandwidthLimit:TRNLUInt32);
begin
 if fIncomingBandwidthLimit<>aIncomingBandwidthLimit then begin
  fIncomingBandwidthLimit:=aIncomingBandwidthLimit;
  BroadcastNewBandwidthLimits;
 end;
end;

procedure TRNLHost.SetOutgoingBandwidthLimit(const aOutgoingBandwidthLimit:TRNLUInt32);
begin
 if OutgoingBandwidthLimit<>aOutgoingBandwidthLimit then begin
  fOutgoingBandwidthLimit:=aOutgoingBandwidthLimit;
  fOutgoingBandwidthRateLimiter.Setup(fOutgoingBandwidthLimit,1000);
  BroadcastNewBandwidthLimits;
 end;
end;

function TRNLHost.GetIncomingBandwidthRate:TRNLUInt32;
begin
 result:=fIncomingBandwidthRateTracker.UnitsPerSecond;
end;

function TRNLHost.GetOutgoingBandwidthRate:TRNLUInt32;
begin
 result:=fOutgoingBandwidthRateTracker.UnitsPerSecond;
end;

function TRNLHost.GetChannelType(const aIndex:TRNLUInt32):TRNLPeerChannelType;
begin
 result:=fChannelTypes[aIndex];
end;

procedure TRNLHost.SetChannelType(const aIndex:TRNLUInt32;const aChannelType:TRNLPeerChannelType);
begin
 fChannelTypes[aIndex]:=aChannelType;
end;

procedure TRNLHost.SetMaximumCountChannels(const aMaximumCountChannels:TRNLUInt32);
begin
 fMaximumCountChannels:=Min(Max(aMaximumCountChannels,1),RNL_MAXIMUM_PEER_CHANNELS);
end;

procedure TRNLHost.SetMTU(const aMTU:TRNLSizeUInt);
begin
 fMTU:=Min(Max(aMTU,RNL_MINIMUM_MTU),RNL_MAXIMUM_MTU);
end;

procedure TRNLHost.SetConnectionTimeout(const aConnectionTimeout:TRNLTime);
begin
 if aConnectionTimeout.fValue=0 then begin
  fConnectionTimeout:=10000;
 end else begin
  fConnectionTimeout:=aConnectionTimeout;
 end;
end;

procedure TRNLHost.SetPingInterval(const aPingInterval:TRNLTime);
begin
 if aPingInterval.fValue=0 then begin
  fPingInterval:=1000;
 end else begin
  fPingInterval:=aPingInterval;
 end;
end;

procedure TRNLHost.SetEncryptedPacketSequenceWindowSize(const aEncryptedPacketSequenceWindowSize:TRNLUInt32);
begin
 if (aEncryptedPacketSequenceWindowSize=0) or (aEncryptedPacketSequenceWindowSize>65536) then begin
  fEncryptedPacketSequenceWindowSize:=65536;
 end else if aEncryptedPacketSequenceWindowSize<16 then begin
  fEncryptedPacketSequenceWindowSize:=16;
 end else begin
  fEncryptedPacketSequenceWindowSize:=TRNLMath.RoundUpToPowerOfTwo32(aEncryptedPacketSequenceWindowSize);
 end;
 fEncryptedPacketSequenceWindowMask:=fEncryptedPacketSequenceWindowSize-1;
end;

function TRNLHost.SendPacket(const aAddress:TRNLAddress;const aData;const aDataLength:TRNLSizeUInt):TRNLNetworkSendResult;
var Family:TRNLInt64;
    Socket:TRNLSocket;
begin
 Family:=aAddress.GetAddressFamily;
 if Family=RNL_IPV4 then begin
  Socket:=fSockets[0];
 end else begin
  Socket:=fSockets[1];
 end;
 if Socket=RNL_SOCKET_NULL then begin
  result:=RNL_NETWORK_SEND_RESULT_ERROR;
 end else begin
  if fOutgoingBandwidthRateLimiter.CanProceed(aDataLength shl 3,fTime) then begin
   if fNetwork.Send(Socket,@aAddress,aData,aDataLength,Family)=TRNLSizeInt(aDataLength) then begin
    fOutgoingBandwidthRateLimiter.AddAmount(aDataLength shl 3,fTime);
    fOutgoingBandwidthRateTracker.AddUnits(aDataLength shl 3);
    result:=RNL_NETWORK_SEND_RESULT_OK;
   end else begin
    result:=RNL_NETWORK_SEND_RESULT_ERROR;
   end;
  end else begin
   // Drop the whole outgoing UDP packet for to satisfy the outgoing bandwidth limit (=> intended artificial packet loss)
   result:=RNL_NETWORK_SEND_RESULT_BANDWIDTH_RATE_LIMITER_DROP;
  end;
 end;
end;

function TRNLHost.SendBuffers(const aAddress:TRNLAddress;const aBuffers:array of TRNLBuffer):TRNLNetworkSendResult;
var Family:TRNLInt64;
    Socket:TRNLSocket;
    Index,DataLength:TRNLSizeInt;
begin
 Family:=aAddress.GetAddressFamily;
 if Family=RNL_IPV4 then begin
  Socket:=fSockets[0];
 end else begin
  Socket:=fSockets[1];
 end;
 if Socket=RNL_SOCKET_NULL then begin
  result:=RNL_NETWORK_SEND_RESULT_ERROR;
 end else begin
  DataLength:=0;
  for Index:=0 to length(aBuffers)-1 do begin
   inc(DataLength,aBuffers[Index].DataLength);
  end;
  if fOutgoingBandwidthRateLimiter.CanProceed(DataLength shl 3,fTime) then begin
   if fNetwork.SendBuffers(Socket,@aAddress,aBuffers[0],length(aBuffers),Family)=DataLength then begin
    fOutgoingBandwidthRateLimiter.AddAmount(DataLength shl 3,fTime);
    fOutgoingBandwidthRateTracker.AddUnits(DataLength shl 3);
    result:=RNL_NETWORK_SEND_RESULT_OK;
   end else begin
    result:=RNL_NETWORK_SEND_RESULT_ERROR;
   end;
  end else begin
   // Drop the whole outgoing UDP packet for to satisfy the outgoing bandwidth limit (=> intended artificial packet loss)
   result:=RNL_NETWORK_SEND_RESULT_BANDWIDTH_RATE_LIMITER_DROP;
  end;
 end;
end;

procedure TRNLHost.ResetConnectionAttemptHistory;
begin
 fConnectionAttemptDeltaTime:=0;
 fConnectionAttemptLastTime:=0;
 fConnectionAttemptHasLastTime:=false;
 FillChar(fConnectionAttemptHistoryDeltaTimes,SizeOf(fConnectionAttemptHistoryDeltaTimes),#0);
 FillChar(fConnectionAttemptHistoryTimePoints,SizeOf(fConnectionAttemptHistoryTimePoints),#0);
 fConnectionAttemptHistoryReadIndex:=0;
 fConnectionAttemptHistoryWriteIndex:=0;
 fConnectionAttemptsPerSecond:=0;
end;

procedure TRNLHost.UpdateConnectionAttemptHistory(const aTime:TRNLTime);
var Index,Count:TRNLUInt32;
    SumOfConnectionAttemptTimes:TRNLUInt64;
begin

 if fConnectionAttemptHasLastTime then begin
  fConnectionAttemptDeltaTime:=aTime-fConnectionAttemptLastTime;
 end else begin
  fConnectionAttemptDeltaTime:=0;
 end;
 fConnectionAttemptLastTime:=aTime;
 fConnectionAttemptHasLastTime:=true;

 if fConnectionAttemptDeltaTime>0 then begin

  fConnectionAttemptHistoryDeltaTimes[fConnectionAttemptHistoryWriteIndex]:=fConnectionAttemptDeltaTime;
  fConnectionAttemptHistoryTimePoints[fConnectionAttemptHistoryWriteIndex]:=aTime;
  inc(fConnectionAttemptHistoryWriteIndex);
  if fConnectionAttemptHistoryWriteIndex>=RNL_CONNECTION_ATTEMPT_SIZE then begin
   fConnectionAttemptHistoryWriteIndex:=0;
  end;

  while (fConnectionAttemptHistoryReadIndex<>fConnectionAttemptHistoryWriteIndex) and
        ((aTime-fConnectionAttemptHistoryTimePoints[fConnectionAttemptHistoryReadIndex])>=1000) do begin
   inc(fConnectionAttemptHistoryReadIndex);
   if fConnectionAttemptHistoryReadIndex>=RNL_CONNECTION_ATTEMPT_SIZE then begin
    fConnectionAttemptHistoryReadIndex:=0;
   end;
  end;

 end;

 SumOfConnectionAttemptTimes:=0;
 Count:=0;
 Index:=fConnectionAttemptHistoryReadIndex;
 while Index<>fConnectionAttemptHistoryWriteIndex do begin
  SumOfConnectionAttemptTimes:=SumOfConnectionAttemptTimes+fConnectionAttemptHistoryDeltaTimes[Index];
  inc(Count);
  inc(Index);
  if Index>RNL_CONNECTION_ATTEMPT_SIZE then begin
   Index:=0;
  end;
 end;
 if (Count>0) and (SumOfConnectionAttemptTimes>0) then begin
  fConnectionAttemptsPerSecond:=(Count*1000) div SumOfConnectionAttemptTimes;
 end else if fConnectionAttemptDeltaTime>0 then begin
  fConnectionAttemptsPerSecond:=1000 div fConnectionAttemptDeltaTime;
 end else begin
  fConnectionAttemptsPerSecond:=0;
 end;

end;

procedure TRNLHost.Start;
var Index,Families,Family:TRNLInt32;
    TemporaryAddress:TRNLAddress;
    Socket:TRNLSocket;
begin

 if fAddress.Host.Equals(RNL_HOST_ANY) then begin
  Families:=RNL_IPV4 or RNL_IPV6;
 end else begin
  Families:=fAddress.GetAddressFamily;
 end;

 for Index:=Low(TRNLHostSockets) to High(TRNLHostSockets) do begin
  Family:=HostSocketFamilies[Index];
  if (Families and Family)<>0 then begin
   Socket:=fNetwork.SocketCreate(RNL_SOCKET_TYPE_DATAGRAM,Family);
   if Socket<>RNL_SOCKET_NULL then begin
    case Family of
     RNL_IPV4:begin
      fNetwork.SocketSetOption(Socket,RNL_SOCKET_OPTION_DONTFRAGMENT,ord(not fMTUDoFragment) and 1);
     end;
     RNL_IPV6:begin
      fNetwork.SocketSetOption(Socket,RNL_SOCKET_OPTION_IPV6_V6ONLY,1);
     end;
    end;
    if fNetwork.SocketBind(Socket,@fAddress,Family) then begin
     fNetwork.SocketSetOption(Socket,RNL_SOCKET_OPTION_NONBLOCK,1);
     fNetwork.SocketSetOption(Socket,RNL_SOCKET_OPTION_BROADCAST,1);
     fNetwork.SocketSetOption(Socket,RNL_SOCKET_OPTION_REUSEADDR,1);
     fNetwork.SocketSetOption(Socket,RNL_SOCKET_OPTION_RCVBUF,fReceiveBufferSize);
     fNetwork.SocketSetOption(Socket,RNL_SOCKET_OPTION_SNDBUF,fSendBufferSize);
     if Family=RNL_IPV4 then begin
      fNetwork.SocketSetOption(Socket,RNL_SOCKET_OPTION_DONTFRAGMENT,ord(not fMTUDoFragment) and 1);
     end;
    end else begin
     fNetwork.SocketDestroy(Socket);
     Socket:=RNL_SOCKET_NULL;
    end;
   end;
   fSockets[Index]:=Socket;
  end else begin
   fSockets[Index]:=RNL_SOCKET_NULL;
  end;
 end;

 if (fSockets[0]=RNL_SOCKET_NULL) and (fSockets[0]=RNL_SOCKET_NULL) then begin
  raise ERNLHost.Create('Empty Socket');
 end;

 if fAddress.Host.Equals(RNL_HOST_ANY) then begin
  for Index:=Low(TRNLHostSockets) to High(TRNLHostSockets) do begin
   if (fSockets[Index]<>RNL_SOCKET_NULL) and
      fNetwork.SocketGetAddress(fSockets[Index],TemporaryAddress,HostSocketFamilies[Index]) then begin
    fAddress:=TemporaryAddress;
    break;
   end;
  end;
 end;

 if fAllowIncomingConnections then begin

  if assigned(fConnectionCandidateHashTable) then begin
   FreeMem(fConnectionCandidateHashTable);
   fConnectionCandidateHashTable:=nil;
  end;

  if assigned(fConnectionKnownCandidateHostAddressHashTable) then begin
   FreeMem(fConnectionKnownCandidateHostAddressHashTable);
   fConnectionKnownCandidateHostAddressHashTable:=nil;
  end;

  GetMem(fConnectionCandidateHashTable,SizeOf(TRNLConnectionCandidateHashTable));
  fConnectionCandidateHashTable^.Clear;

  GetMem(fConnectionKnownCandidateHostAddressHashTable,SizeOf(TRNLConnectionKnownCandidateHostAddressHashTable));
  fConnectionKnownCandidateHostAddressHashTable^.Clear;

  ResetConnectionAttemptHistory;

 end;

 fTime:=fInstance.Time;

 fIncomingBandwidthRateTracker.Reset;

 fOutgoingBandwidthRateTracker.Reset;

 fIncomingBandwidthRateTracker.SetTime(fTime);

 fOutgoingBandwidthRateTracker.SetTime(fTime);

 fIncomingBandwidthRateTracker.Update;

 fOutgoingBandwidthRateTracker.Update;

 fOutgoingBandwidthRateLimiter.Setup(fOutgoingBandwidthLimit,1000);

 fOutgoingBandwidthRateLimiter.Reset(fTime);

end;

function TRNLHost.Connect(const aAddress:TRNLAddress;
                          const aCountChannels:TRNLUInt32=1;
                          const aData:TRNLUInt64=0;
                          const aConnectionToken:PRNLConnectionToken=nil;
                          const aAuthenticationToken:PRNLAuthenticationToken=nil):TRNLPeer;
var Index:TRNLInt32;
//    Channel:TRNLChannel;
begin
 fTime:=fInstance.Time;
 if fCountPeers>=fMaximumCountPeers then begin
  raise ERNLHost.Create('No free peer available');
 end;
 result:=TRNLPeer.Create(self);
/// CurrentPeer.fConnectData:=aData;

 result.fState:=RNL_PEER_STATE_CONNECTION_REQUESTING;

 result.fNextPendingConnectionSendTimeout:=fTime+fPendingConnectionSendTimeout;

 result.fAddress:=aAddress;

 result.fOutgoingEncryptedPacketSequenceNumber:=0;
 result.fIncomingEncryptedPacketSequenceNumber:=0;
 result.fIncomingEncryptedPacketSequenceBuffer:=nil;

 result.fLocalSalt:=fRandomGenerator.GetUInt64;

 result.fRemoteSalt:=0;

 result.SetCountChannels(aCountChannels);

 result.fDisconnectData:=aData;

 result.fConnectionData:=aData;

 result.fConnectionSalt:=result.fLocalSalt;

 result.fConnectionNonce:=0;

 result.fChecksumPlaceHolder:=result.fConnectionSalt xor (result.fConnectionSalt shl 32);

 TRNLX25519.GeneratePublicPrivateKeyPair(fRandomGenerator,
                                         result.fLocalShortTermPublicKey,
                                         result.fLocalShortTermPrivateKey);

 if assigned(result.fConnectionToken) then begin
  FreeMem(result.fConnectionToken);
  result.fConnectionToken:=nil;
 end;

 GetMem(result.fConnectionToken,SizeOf(TRNLConnectionToken));

 if assigned(aConnectionToken) then begin
  result.fConnectionToken^:=aConnectionToken^;
 end else begin
  for Index:=0 to SizeOf(TRNLConnectionToken)-1 do begin
   result.fConnectionToken^[Index]:=fRandomGenerator.GetUInt32;
  end;
 end;

 if assigned(result.fAuthenticationToken) then begin
  FreeMem(result.fAuthenticationToken);
  result.fAuthenticationToken:=nil;
 end;

 GetMem(result.fAuthenticationToken,SizeOf(TRNLAuthenticationToken));

 if assigned(aAuthenticationToken) then begin
  result.fAuthenticationToken^:=aAuthenticationToken^;
 end else begin
  for Index:=0 to SizeOf(TRNLAuthenticationToken)-1 do begin
   result.fAuthenticationToken^[Index]:=fRandomGenerator.GetUInt32;
  end;
 end;

 FreeAndNil(result.fPendingConnectionHandshakeSendData);

 result.fPendingConnectionHandshakeSendData:=TRNLPeerPendingConnectionHandshakeSendData.Create(result);
 result.fPendingConnectionHandshakeSendData.fHandshakePacket.Header.Signature:=RNLProtocolHandshakePacketHeaderSignature;
 result.fPendingConnectionHandshakeSendData.fHandshakePacket.Header.ProtocolVersion:=TRNLEndianness.HostToLittleEndian64(RNL_PROTOCOL_VERSION);
 result.fPendingConnectionHandshakeSendData.fHandshakePacket.Header.ProtocolID:=TRNLEndianness.HostToLittleEndian64(fProtocolID);
 result.fPendingConnectionHandshakeSendData.fHandshakePacket.Header.PacketType:=TRNLInt32(TRNLProtocolHandshakePacketType(RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_REQUEST));
 result.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionRequest.PeerID:=TRNLEndianness.HostToLittleEndian16(result.fLocalPeerID);
 result.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionRequest.OutgoingSalt:=TRNLEndianness.HostToLittleEndian64(result.fLocalSalt);
 result.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionRequest.IncomingBandwidthLimit:=TRNLEndianness.HostToLittleEndian32(fIncomingBandwidthLimit);
 result.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionRequest.OutgoingBandwidthLimit:=TRNLEndianness.HostToLittleEndian32(fOutgoingBandwidthLimit);
 result.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionRequest.ConnectionToken:=result.fConnectionToken^;
 result.fPendingConnectionHandshakeSendData.Send;

 result.fNextPendingConnectionSendTimeout:=fTime+fPendingConnectionSendTimeout;

end;

procedure TRNLHost.AddHandshakePacketChecksum(var aHandshakePacket);
var PacketSize:TRNLSizeInt;
begin
 PacketSize:=RNLProtocolHandshakePacketSizes[TRNLProtocolHandshakePacketType(TRNLInt32(PRNLProtocolHandshakePacket(TRNLPointer(@aHandshakePacket))^.Header.PacketType))];
 PRNLProtocolHandshakePacket(TRNLPointer(@aHandshakePacket))^.Header.Checksum:=TRNLEndianness.HostToLittleEndian32(0);
 PRNLProtocolHandshakePacket(TRNLPointer(@aHandshakePacket))^.Header.Checksum:=DirectChecksumCRC32C(aHandshakePacket,PacketSize);
end;

function TRNLHost.VerifyHandshakePacketChecksum(var aHandshakePacket):boolean;
var PacketSize:TRNLSizeInt;
    DesiredChecksum:TRNLUInt32;
begin
 PacketSize:=RNLProtocolHandshakePacketSizes[TRNLProtocolHandshakePacketType(TRNLInt32(PRNLProtocolHandshakePacket(TRNLPointer(@aHandshakePacket))^.Header.PacketType))];
 DesiredChecksum:=TRNLEndianness.LittleEndianToHost32(PRNLProtocolHandshakePacket(TRNLPointer(@aHandshakePacket))^.Header.Checksum);
 PRNLProtocolHandshakePacket(TRNLPointer(@aHandshakePacket))^.Header.Checksum:=TRNLEndianness.HostToLittleEndian32(0);
 PRNLProtocolHandshakePacket(TRNLPointer(@aHandshakePacket))^.Header.Checksum:=TRNLEndianness.HostToLittleEndian32(DirectChecksumCRC32C(aHandshakePacket,PacketSize));
 result:=DesiredChecksum=TRNLEndianness.LittleEndianToHost32(PRNLProtocolHandshakePacket(TRNLPointer(@aHandshakePacket))^.Header.Checksum);
end;

procedure TRNLHost.DispatchReceivedHandshakePacketConnectionRequest(const aIncomingPacket:PRNLProtocolHandshakePacketConnectionRequest);
var Index:TRNLInt32;
    ConnectionKnownCandidateHostAddress:PRNLConnectionKnownCandidateHostAddress;
    ConnectionCandidate:PRNLConnectionCandidate;
    OutgoingPacket:TRNLProtocolHandshakePacketConnectionChallengeRequest;
begin

{$if defined(RNL_DEBUG) and defined(RNL_DEBUG_SECURITY)}
 fInstance.fDebugLock.Acquire;
 try
  writeln('DispatchReceivedHandshakePacketConnectionRequest');
 finally
  fInstance.fDebugLock.Release;
 end;
{$ifend}

 if not (assigned(fConnectionCandidateHashTable) and
         assigned(fConnectionKnownCandidateHostAddressHashTable)) then begin
  exit;
 end;

 UpdateConnectionAttemptHistory(fInstance.Time);

 fConnectionChallengeDifficultyLevel:=Min(Max((fConnectionAttemptsPerSecond*
                                               fConnectionAttemptsPerSecondChallengeDifficultyFactor) shr 12,
                                              0),
                                          65535);

 ConnectionKnownCandidateHostAddress:=fConnectionKnownCandidateHostAddressHashTable^.Find(fReceivedAddress.Host,
                                                                                          fInstance.Time,
                                                                                          true);
 if assigned(ConnectionKnownCandidateHostAddress) then begin
  if ConnectionKnownCandidateHostAddress^.RateLimiter.RateLimit(fInstance.Time,
                                                                 fRateLimiterHostAddressBurst,
                                                                 fRateLimiterHostAddressPeriod) then begin
   exit;
  end;
 end else begin
  exit;
 end;

 if assigned(fOnCheckConnectionToken) and not
    fOnCheckConnectionToken(self,fReceivedAddress,aIncomingPacket^.ConnectionToken) then begin
  exit;
 end;

 ConnectionCandidate:=fConnectionCandidateHashTable^.Find(fRandomGenerator,
                                                          fReceivedAddress,
                                                          TRNLEndianness.LittleEndianToHost64(aIncomingPacket^.OutgoingSalt),
                                                          fSalt,
                                                          fInstance.Time,
                                                          fPendingConnectionTimeout,
                                                          true);
 if assigned(ConnectionCandidate) then begin

  if not (ConnectionCandidate^.State in [RNL_CONNECTION_STATE_REQUESTING,
                                         RNL_CONNECTION_STATE_CHALLENGING]) then begin
   exit;
  end;

  ConnectionCandidate^.OutgoingPeerID:=TRNLEndianness.LittleEndianToHost16(aIncomingPacket^.PeerID);

  ConnectionCandidate^.IncomingBandwidthLimit:=TRNLEndianness.LittleEndianToHost32(aIncomingPacket^.IncomingBandwidthLimit);
  ConnectionCandidate^.OutgoingBandwidthLimit:=TRNLEndianness.LittleEndianToHost32(aIncomingPacket^.OutgoingBandwidthLimit);

  ConnectionCandidate^.CountChallengeRepetitions:=Max(1,fConnectionChallengeDifficultyLevel);

  for Index:=0 to (SizeOf(TRNLConnectionChallenge) shr 3)-1 do begin
   PRNLUInt64Array(TRNLPointer(@ConnectionCandidate^.Challenge))^[Index]:=fRandomGenerator.GetUInt64;
  end;

  OutgoingPacket.Header.Signature:=RNLProtocolHandshakePacketHeaderSignature;
  OutgoingPacket.Header.ProtocolVersion:=TRNLEndianness.HostToLittleEndian64(RNL_PROTOCOL_VERSION);
  OutgoingPacket.Header.ProtocolID:=TRNLEndianness.HostToLittleEndian64(fProtocolID);
  OutgoingPacket.Header.PacketType:=TRNLUInt32(TRNLProtocolHandshakePacketType(RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_CHALLENGE_REQUEST));
  OutgoingPacket.PeerID:=TRNLEndianness.HostToLittleEndian16(ConnectionCandidate^.OutgoingPeerID);
  OutgoingPacket.OutgoingSalt:=TRNLEndianness.HostToLittleEndian64(ConnectionCandidate^.RemoteSalt);
  OutgoingPacket.IncomingSalt:=TRNLEndianness.HostToLittleEndian64(ConnectionCandidate^.LocalSalt);
  OutgoingPacket.IncomingBandwidthLimit:=TRNLEndianness.HostToLittleEndian32(fIncomingBandwidthLimit);
  OutgoingPacket.OutgoingBandwidthLimit:=TRNLEndianness.HostToLittleEndian32(fOutgoingBandwidthLimit);
  OutgoingPacket.CountChallengeRepetitions:=TRNLEndianness.HostToLittleEndian16(ConnectionCandidate^.CountChallengeRepetitions);
  OutgoingPacket.Challenge:=ConnectionCandidate^.Challenge;

  AddHandshakePacketChecksum(OutgoingPacket);

  SendPacket(fReceivedAddress,
             OutgoingPacket,
             SizeOf(TRNLProtocolHandshakePacketConnectionChallengeRequest));

  ConnectionCandidate^.State:=RNL_CONNECTION_STATE_CHALLENGING;

 end;

end;

procedure TRNLHost.DispatchReceivedHandshakePacketConnectionChallengeRequest(const aIncomingPacket:PRNLProtocolHandshakePacketConnectionChallengeRequest);
var Index:TRNLInt32;
    PeerID:TRNLID;
    Peer:TRNLPeer;
    LocalSalt,RemoteSalt:TRNLUInt64;
begin

{$if defined(RNL_DEBUG) and defined(RNL_DEBUG_SECURITY)}
 fInstance.fDebugLock.Acquire;
 try
  writeln('DispatchReceivedHandshakePacketConnectionChallengeRequest');
 finally
  fInstance.fDebugLock.Release;
 end;
{$ifend}

 PeerID:=TRNLEndianness.LittleEndianToHost16(aIncomingPacket^.PeerID);

 Peer:=fPeerIDMap[PeerID];
 if not assigned(Peer) then begin
  exit;
 end;

 RemoteSalt:=TRNLEndianness.LittleEndianToHost64(aIncomingPacket^.IncomingSalt);
 LocalSalt:=TRNLEndianness.LittleEndianToHost64(aIncomingPacket^.OutgoingSalt);

 if Peer.fLocalSalt<>LocalSalt then begin
  exit;
 end;

 if Peer.fState<>RNL_PEER_STATE_CONNECTION_REQUESTING then begin
  exit;
 end;

 Peer.fRemoteSalt:=RemoteSalt;

 Peer.fConnectionSalt:=Peer.fLocalSalt xor Peer.fRemoteSalt;

 Peer.fRemoteIncomingBandwidthLimit:=TRNLEndianness.LittleEndianToHost32(aIncomingPacket^.IncomingBandwidthLimit);

 Peer.fRemoteOutgoingBandwidthLimit:=TRNLEndianness.LittleEndianToHost32(aIncomingPacket^.OutgoingBandwidthLimit);

 Peer.fChecksumPlaceHolder:=Peer.fConnectionSalt xor (Peer.fConnectionSalt shl 32);

 if assigned(Peer.fConnectionChallengeResponse) then begin
  FreeMem(Peer.fConnectionChallengeResponse);
 end;

 GetMem(Peer.fConnectionChallengeResponse,SizeOf(TRNLConnectionChallenge));

 Peer.fConnectionChallengeResponse^:=aIncomingPacket^.Challenge;

 for Index:=1 to TRNLEndianness.LittleEndianToHost16(aIncomingPacket^.CountChallengeRepetitions) do begin
  TRNLSHA512.Process(Peer.fConnectionChallengeResponse^,
                     Peer.fConnectionChallengeResponse^,
                     SizeOf(TRNLConnectionChallenge));
 end;

 Peer.fConnectionNonce:=PRNLUInt64(TRNLPointer(Peer.fConnectionChallengeResponse))^;

 FreeAndNil(Peer.fPendingConnectionHandshakeSendData);

 Peer.fPendingConnectionHandshakeSendData:=TRNLPeerPendingConnectionHandshakeSendData.Create(Peer);
 Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.Header.Signature:=RNLProtocolHandshakePacketHeaderSignature;
 Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.Header.ProtocolVersion:=TRNLEndianness.HostToLittleEndian64(RNL_PROTOCOL_VERSION);
 Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.Header.ProtocolID:=TRNLEndianness.HostToLittleEndian64(fProtocolID);
 Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.Header.PacketType:=TRNLInt32(TRNLProtocolHandshakePacketType(RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_CHALLENGE_RESPONSE));
 Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionChallengeResponse.ConnectionSalt:=TRNLEndianness.HostToLittleEndian64(Peer.fConnectionSalt);
 Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionChallengeResponse.ShortTermPublicKey:=Peer.fLocalShortTermPublicKey;
 Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionChallengeResponse.ChallengeResponse:=Peer.fConnectionChallengeResponse^;
 Peer.fPendingConnectionHandshakeSendData.Send;

 Peer.fNextPendingConnectionSendTimeout:=fTime+fPendingConnectionSendTimeout;

 Peer.fState:=RNL_PEER_STATE_CONNECTION_CHALLENGING;

end;

procedure TRNLHost.DispatchReceivedHandshakePacketConnectionChallengeResponse(const aIncomingPacket:PRNLProtocolHandshakePacketConnectionChallengeResponse);
var Index:TRNLInt32;
    ConnectionCandidate:PRNLConnectionCandidate;
    ConnectionSalt,ChallengeResult:TRNLUInt64;
    OutgoingPacket:TRNLProtocolHandshakePacket;
    Nonce:TRNLCipherNonce;
    TwoKeys:TRNLTwoKeys;
begin

{$if defined(RNL_DEBUG) and defined(RNL_DEBUG_SECURITY)}
 fInstance.fDebugLock.Acquire;
 try
  writeln('DispatchReceivedHandshakePacketConnectionChallengeResponse');
 finally
  fInstance.fDebugLock.Release;
 end;
{$ifend}

 if not (assigned(fConnectionCandidateHashTable) and
         assigned(fConnectionKnownCandidateHostAddressHashTable)) then begin
  exit;
 end;

 ConnectionCandidate:=fConnectionCandidateHashTable^.Find(fRandomGenerator,
                                                          fReceivedAddress,
                                                          TRNLEndianness.LittleEndianToHost64(aIncomingPacket^.ConnectionSalt) xor fSalt,
                                                          fSalt,
                                                          fInstance.Time,
                                                          fPendingConnectionTimeout,
                                                          false);

 if assigned(ConnectionCandidate) then begin

  if not (ConnectionCandidate^.State in [RNL_CONNECTION_STATE_CHALLENGING,
                                         RNL_CONNECTION_STATE_AUTHENTICATING]) then begin
   exit;
  end;

  ConnectionSalt:=ConnectionCandidate^.LocalSalt xor ConnectionCandidate^.RemoteSalt;
  if ConnectionSalt<>TRNLEndianness.LittleEndianToHost64(aIncomingPacket^.ConnectionSalt) then begin
   exit;
  end;

  ConnectionCandidate^.SolvedChallenge:=ConnectionCandidate^.Challenge;

  for Index:=1 to ConnectionCandidate^.CountChallengeRepetitions do begin
   TRNLSHA512.Process(ConnectionCandidate^.SolvedChallenge,
                      ConnectionCandidate^.SolvedChallenge,
                      SizeOf(TRNLConnectionChallenge));
  end;

  ChallengeResult:=0;
  for Index:=0 to (SizeOf(TRNLConnectionChallenge) shr 3)-1 do begin
   ChallengeResult:=ChallengeResult or
                    (PRNLUInt64Array(TRNLPointer(@ConnectionCandidate^.SolvedChallenge))^[Index] xor
                     PRNLUInt64Array(TRNLPointer(@aIncomingPacket^.ChallengeResponse))^[Index]);
  end;

  if ChallengeResult<>0 then begin
   exit;
  end;

  TRNLX25519.GeneratePublicPrivateKeyPair(fRandomGenerator,
                                          ConnectionCandidate^.LocalShortTermPublicKey,
                                          ConnectionCandidate^.LocalShortTermPrivateKey);

  ConnectionCandidate^.RemoteShortTermPublicKey:=aIncomingPacket^.ShortTermPublicKey;

  TRNLX25519.GenerateSharedSecretKey(ConnectionCandidate^.SharedSecretKey,
                                     ConnectionCandidate^.RemoteShortTermPublicKey,
                                     ConnectionCandidate^.LocalShortTermPrivateKey);
 {$if defined(RNL_DEBUG) and defined(RNL_DEBUG_SECURITY_EXTENDED)}
  fInstance.fDebugLock.Acquire;
  try
   writeln('HandleConnectionRequest SharedSecretKey: ',ConnectionCandidate^.SharedSecretKey.ui32[0],' ',ConnectionCandidate^.SharedSecretKey.ui32[1],' ',ConnectionCandidate^.SharedSecretKey.ui32[2],' ',ConnectionCandidate^.SharedSecretKey.ui32[3]);
  finally
   fInstance.fDebugLock.Release;
  end;
 {$ifend}

  ConnectionCandidate^.Nonce:=fRandomGenerator.GetUInt64;

  OutgoingPacket.Header.Signature:=RNLProtocolHandshakePacketHeaderSignature;
  OutgoingPacket.Header.ProtocolVersion:=TRNLEndianness.HostToLittleEndian64(RNL_PROTOCOL_VERSION);
  OutgoingPacket.Header.ProtocolID:=TRNLEndianness.HostToLittleEndian64(fProtocolID);

  OutgoingPacket.Header.PacketType:=TRNLUInt32(TRNLProtocolHandshakePacketType(RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_AUTHENTICATION_REQUEST));

  OutgoingPacket.ConnectionAuthenticationRequest.PeerID:=TRNLEndianness.HostToLittleEndian16(ConnectionCandidate^.OutgoingPeerID);
  OutgoingPacket.ConnectionAuthenticationRequest.ConnectionSalt:=TRNLEndianness.HostToLittleEndian64(ConnectionSalt);
  OutgoingPacket.ConnectionAuthenticationRequest.ShortTermPublicKey:=ConnectionCandidate^.LocalShortTermPublicKey;
  OutgoingPacket.ConnectionAuthenticationRequest.Nonce:=TRNLEndianness.HostToLittleEndian64(ConnectionCandidate^.Nonce);

  OutgoingPacket.ConnectionAuthenticationRequest.Payload.LongTermPublicKey:=fLongTermPublicKey;

  OutgoingPacket.ConnectionAuthenticationRequest.Payload.MTU:=TRNLEndianness.HostToLittleEndian16(fMTU);

  TwoKeys[0]:=ConnectionCandidate^.LocalShortTermPublicKey;
  TwoKeys[1]:=ConnectionCandidate^.RemoteShortTermPublicKey;

  TRNLED25519.Sign(OutgoingPacket.ConnectionAuthenticationRequest.Payload.Signature,
                   fLongTermPrivateKey,
                   fLongTermPublicKey,
                   TwoKeys,
                   SizeOf(TRNLTwoKeys));

  PRNLUInt64Array(TRNLPointer(@Nonce))^[0]:=TRNLEndianness.HostToLittleEndian64(ConnectionCandidate^.Nonce);
  PRNLUInt64Array(TRNLPointer(@Nonce))^[1]:=TRNLEndianness.HostToLittleEndian64(ConnectionCandidate^.RemoteSalt);
  PRNLUInt64Array(TRNLPointer(@Nonce))^[2]:=TRNLEndianness.HostToLittleEndian64(ConnectionCandidate^.LocalSalt);

  if not TRNLAuthenticatedEncryption.Encrypt(OutgoingPacket.ConnectionAuthenticationRequest.Payload,
                                             ConnectionCandidate^.SharedSecretKey,
                                             Nonce,
                                             OutgoingPacket.ConnectionAuthenticationRequest.PayloadMAC,
                                             ConnectionCandidate^.SolvedChallenge,
                                             SizeOf(TRNLConnectionChallenge),
                                             OutgoingPacket.ConnectionAuthenticationRequest.Payload,
                                             SizeOf(TTRNLProtocolHandshakePacketConnectionAuthenticationRequestPayload)) then begin
   exit;
  end;

  AddHandshakePacketChecksum(OutgoingPacket);

  SendPacket(fReceivedAddress,
             OutgoingPacket,
             SizeOf(TRNLProtocolHandshakePacketConnectionAuthenticationRequest));

  ConnectionCandidate^.State:=RNL_CONNECTION_STATE_AUTHENTICATING;

 end;

end;

procedure TRNLHost.DispatchReceivedHandshakePacketConnectionAuthenticationRequest(const aIncomingPacket:PRNLProtocolHandshakePacketConnectionAuthenticationRequest);
var Index:TRNLInt32;
    PeerID:TRNLID;
    Peer:TRNLPeer;
    Nonce:TRNLCipherNonce;
    TwoKeys:TRNLTwoKeys;
begin

{$if defined(RNL_DEBUG) and defined(RNL_DEBUG_SECURITY)}
 fInstance.fDebugLock.Acquire;
 try
  writeln('DispatchReceivedHandshakePacketConnectionAuthenticationRequest');
 finally
  fInstance.fDebugLock.Release;
 end;
{$ifend}

 PeerID:=TRNLEndianness.LittleEndianToHost16(aIncomingPacket^.PeerID);

 Peer:=fPeerIDMap[PeerID];
 if not assigned(Peer) then begin
  exit;
 end;

 if Peer.fConnectionSalt<>TRNLEndianness.LittleEndianToHost64(aIncomingPacket^.ConnectionSalt) then begin
  exit;
 end;

 if Peer.fState<>RNL_PEER_STATE_CONNECTION_CHALLENGING then begin
  exit;
 end;

 TRNLX25519.GenerateSharedSecretKey(Peer.fSharedSecretKey,
                                    aIncomingPacket^.ShortTermPublicKey,
                                    Peer.fLocalShortTermPrivateKey);

{$if defined(RNL_DEBUG) and defined(RNL_DEBUG_SECURITY_EXTENDED)}
 fInstance.fDebugLock.Acquire;
 try
  writeln('HandleConnectionAuthenticationRequest SharedSecretKey: ',Peer.fSharedSecretKey.ui32[0],' ',
                                                                    Peer.fSharedSecretKey.ui32[1],' ',
                                                                    Peer.fSharedSecretKey.ui32[2],' ',
                                                                    Peer.fSharedSecretKey.ui32[3]);
 finally
  fInstance.fDebugLock.Release;
 end;
{$ifend}

 PRNLUInt64Array(TRNLPointer(@Nonce))^[0]:=aIncomingPacket^.Nonce;
 PRNLUInt64Array(TRNLPointer(@Nonce))^[1]:=TRNLEndianness.HostToLittleEndian64(Peer.fLocalSalt);
 PRNLUInt64Array(TRNLPointer(@Nonce))^[2]:=TRNLEndianness.HostToLittleEndian64(Peer.fRemoteSalt);

 if not TRNLAuthenticatedEncryption.Decrypt(aIncomingPacket^.Payload,
                                            Peer.fSharedSecretKey,
                                            Nonce,
                                            aIncomingPacket^.PayloadMAC,
                                            Peer.fConnectionChallengeResponse^,
                                            SizeOf(TRNLConnectionChallenge),
                                            aIncomingPacket^.Payload,
                                            SizeOf(TTRNLProtocolHandshakePacketConnectionAuthenticationRequestPayload)) then begin
  exit;
 end;

 TwoKeys[0]:=aIncomingPacket^.ShortTermPublicKey;
 TwoKeys[1]:=Peer.fLocalShortTermPublicKey;

 if not TRNLED25519.Verify(aIncomingPacket^.Payload.Signature,
                           aIncomingPacket^.Payload.LongTermPublicKey,
                           TwoKeys,
                           SizeOf(TRNLTwoKeys)) then begin
  exit;
 end;

 Peer.fRemoteMTU:=TRNLEndianness.LittleEndianToHost16(aIncomingPacket^.Payload.MTU);

 Peer.fMTU:=Min(Max(Min(fMTU,Peer.fRemoteMTU),RNL_MINIMUM_MTU),RNL_MAXIMUM_MTU);

 FreeAndNil(Peer.fPendingConnectionHandshakeSendData);

 Peer.fPendingConnectionHandshakeSendData:=TRNLPeerPendingConnectionHandshakeSendData.Create(Peer);
 Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.Header.Signature:=RNLProtocolHandshakePacketHeaderSignature;
 Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.Header.ProtocolVersion:=TRNLEndianness.HostToLittleEndian64(RNL_PROTOCOL_VERSION);
 Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.Header.ProtocolID:=TRNLEndianness.HostToLittleEndian64(fProtocolID);
 Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.Header.PacketType:=TRNLInt32(TRNLProtocolHandshakePacketType(RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_AUTHENTICATION_RESPONSE));
 Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionAuthenticationResponse.ConnectionSalt:=TRNLEndianness.HostToLittleEndian64(Peer.fConnectionSalt);
 Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionAuthenticationResponse.Nonce:=TRNLEndianness.HostToLittleEndian64(fRandomGenerator.GetUInt64);

 PRNLUInt64Array(TRNLPointer(@Nonce))^[0]:=aIncomingPacket^.Nonce;
 PRNLUInt64Array(TRNLPointer(@Nonce))^[1]:=Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionAuthenticationResponse.Nonce;
 PRNLUInt64Array(TRNLPointer(@Nonce))^[2]:=Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionAuthenticationResponse.ConnectionSalt;

 if assigned(Peer.fAuthenticationToken) then begin
  Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionAuthenticationResponse.Payload.AuthenticationToken:=Peer.fAuthenticationToken^;
 end else begin
  FillChar(Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionAuthenticationResponse.Payload.AuthenticationToken,SizeOf(TRNLAuthenticationToken),#0);
 end;

//Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionAuthenticationResponse.Payload.Data:=TRNLEndianness.HostToLittleEndian32(fConnectData);

 Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionAuthenticationResponse.Payload.LongTermPublicKey:=fLongTermPublicKey;

 TwoKeys[0]:=Peer.fLocalShortTermPublicKey;
 TwoKeys[1]:=aIncomingPacket^.ShortTermPublicKey;

 TRNLED25519.Sign(Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionAuthenticationResponse.Payload.Signature,
                  fLongTermPrivateKey,
                  fLongTermPublicKey,
                  TwoKeys,
                  SizeOf(TRNLTwoKeys));

 Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionAuthenticationResponse.Payload.MTU:=TRNLEndianness.HostToLittleEndian16(fMTU);

 Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionAuthenticationResponse.Payload.CountChannels:=TRNLEndianness.HostToLittleEndian16(Peer.fCountChannels);

 for Index:=Low(TRNLPeerChannelTypes) to High(TRNLPeerChannelTypes) do begin
  Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionAuthenticationResponse.Payload.ChannelTypes[Index]:=TRNLInt32(TRNLPeerChannelType(fChannelTypes[Index]));
 end;

 Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionAuthenticationResponse.Payload.Data:=TRNLEndianness.HostToLittleEndian64(Peer.fConnectionData);

 if not TRNLAuthenticatedEncryption.Encrypt(Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionAuthenticationResponse.Payload,
                                            Peer.fSharedSecretKey,
                                            Nonce,
                                            Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionAuthenticationResponse.PayloadMAC,
                                            Peer.fConnectionChallengeResponse^,
                                            SizeOf(TRNLConnectionChallenge),
                                            Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionAuthenticationResponse.Payload,
                                            SizeOf(TRNLProtocolHandshakePacketConnectionAuthenticationResponsePayload)
                                           ) then begin
  exit;
 end;

 Peer.fPendingConnectionHandshakeSendData.Send;

 Peer.fNextPendingConnectionSendTimeout:=fTime+fPendingConnectionSendTimeout;

 Peer.fState:=RNL_PEER_STATE_CONNECTION_AUTHENTICATING;

end;

procedure TRNLHost.DispatchReceivedHandshakePacketConnectionAuthenticationResponse(const aIncomingPacket:PRNLProtocolHandshakePacketConnectionAuthenticationResponse);
var Index:TRNLInt32;
    RemoteCountChannels:TRNLUInt32;
    ConnectionCandidate:PRNLConnectionCandidate;
    ConnectionSalt:TRNLUInt64;
    OutgoingPacket:TRNLProtocolHandshakePacket;
    Nonce:TRNLCipherNonce;
    TwoKeys:TRNLTwoKeys;
    Peer:TRNLPeer;
    Authorized:boolean;
    RemoteChannelTypes:TRNLPeerChannelTypes;
begin

{$if defined(RNL_DEBUG) and defined(RNL_DEBUG_SECURITY)}
 fInstance.fDebugLock.Acquire;
 try
  writeln('DispatchReceivedHandshakePacketConnectionAuthenticationResponse');
 finally
  fInstance.fDebugLock.Release;
 end;
{$ifend}

 if not (assigned(fConnectionCandidateHashTable) and
         assigned(fConnectionKnownCandidateHostAddressHashTable)) then begin
  exit;
 end;

 ConnectionCandidate:=fConnectionCandidateHashTable^.Find(fRandomGenerator,
                                                          fReceivedAddress,
                                                          TRNLEndianness.LittleEndianToHost64(aIncomingPacket^.ConnectionSalt) xor fSalt,
                                                          fSalt,
                                                          fInstance.Time,
                                                          fPendingConnectionTimeout,
                                                          false);

 if assigned(ConnectionCandidate) then begin

  if not (ConnectionCandidate^.State in [RNL_CONNECTION_STATE_AUTHENTICATING,
                                         RNL_CONNECTION_STATE_APPROVING]) then begin
   exit;
  end;

  ConnectionSalt:=ConnectionCandidate^.LocalSalt xor ConnectionCandidate^.RemoteSalt;
  if ConnectionSalt<>TRNLEndianness.LittleEndianToHost64(aIncomingPacket^.ConnectionSalt) then begin
   exit;
  end;

  Authorized:=true;

  PRNLUInt64Array(TRNLPointer(@Nonce))^[0]:=TRNLEndianness.HostToLittleEndian64(ConnectionCandidate^.Nonce);
  PRNLUInt64Array(TRNLPointer(@Nonce))^[1]:=aIncomingPacket^.Nonce;
  PRNLUInt64Array(TRNLPointer(@Nonce))^[2]:=TRNLEndianness.HostToLittleEndian64(ConnectionSalt);

  if not TRNLAuthenticatedEncryption.Decrypt(aIncomingPacket^.Payload,
                                             ConnectionCandidate^.SharedSecretKey,
                                             Nonce,
                                             aIncomingPacket^.PayloadMAC,
                                             ConnectionCandidate^.SolvedChallenge,
                                             SizeOf(TRNLConnectionChallenge),
                                             aIncomingPacket^.Payload,
                                             SizeOf(TRNLProtocolHandshakePacketConnectionAuthenticationResponsePayload)) then begin
   Authorized:=false;
  end;

  if Authorized then begin

   TwoKeys[0]:=ConnectionCandidate^.RemoteShortTermPublicKey;
   TwoKeys[1]:=ConnectionCandidate^.LocalShortTermPublicKey;

   if not TRNLED25519.Verify(aIncomingPacket^.Payload.Signature,
                             aIncomingPacket^.Payload.LongTermPublicKey,
                             TwoKeys,
                             SizeOf(TRNLTwoKeys)) then begin
    Authorized:=false;
   end;

  end;

  OutgoingPacket.Header.Signature:=RNLProtocolHandshakePacketHeaderSignature;
  OutgoingPacket.Header.ProtocolVersion:=TRNLEndianness.HostToLittleEndian64(RNL_PROTOCOL_VERSION);
  OutgoingPacket.Header.ProtocolID:=TRNLEndianness.HostToLittleEndian64(fProtocolID);

  RemoteCountChannels:=TRNLEndianness.LittleEndianToHost16(aIncomingPacket^.Payload.CountChannels);

  for Index:=Low(TRNLPeerChannelTypes) to High(TRNLPeerChannelTypes) do begin
   RemoteChannelTypes[Index]:=TRNLPeerChannelType(TRNLInt32(aIncomingPacket^.Payload.ChannelTypes[Index]));
  end;

  if Authorized and
     ((fCountPeers+1)<fMaximumCountPeers) and
     ((RemoteCountChannels>0) and (RemoteCountChannels<=fMaximumCountChannels)) and
     TRNLMemory.SecureIsEqual(RemoteChannelTypes,fChannelTypes,SizeOf(TRNLPeerChannelType)*RemoteCountChannels) then begin

   if assigned(ConnectionCandidate^.Peer) then begin

    Peer:=ConnectionCandidate^.Peer;

   end else begin

    Peer:=TRNLPeer.Create(self);

    ConnectionCandidate^.Peer:=Peer;

    Peer.fAddress:=fReceivedAddress;

    Peer.fRemoteMTU:=TRNLEndianness.LittleEndianToHost16(aIncomingPacket^.Payload.MTU);

    Peer.fMTU:=Min(Max(Min(fMTU,Peer.fRemoteMTU),RNL_MINIMUM_MTU),RNL_MAXIMUM_MTU);

    Peer.fRemotePeerID:=ConnectionCandidate^.OutgoingPeerID;

    Peer.fRemoteSalt:=ConnectionCandidate^.RemoteSalt;

    Peer.fLocalSalt:=ConnectionCandidate^.LocalSalt;

    Peer.SetCountChannels(RemoteCountChannels);

    Peer.fConnectionSalt:=ConnectionSalt;

    Peer.fConnectionNonce:=PRNLUInt64(TRNLPointer(@ConnectionCandidate^.SolvedChallenge))^;

    Peer.fChecksumPlaceHolder:=Peer.fConnectionSalt xor (Peer.fConnectionSalt shl 32);

    Peer.fSharedSecretKey:=ConnectionCandidate^.SharedSecretKey;

   end;

   Peer.fRemoteIncomingBandwidthLimit:=ConnectionCandidate^.IncomingBandwidthLimit;

   Peer.fRemoteOutgoingBandwidthLimit:=ConnectionCandidate^.OutgoingBandwidthLimit;

   Peer.fLastReceivedDataTime:=fTime;

   FreeAndNil(Peer.fPendingConnectionHandshakeSendData);

   Peer.fPendingConnectionHandshakeSendData:=TRNLPeerPendingConnectionHandshakeSendData.Create(Peer);
   Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.Header.Signature:=RNLProtocolHandshakePacketHeaderSignature;
   Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.Header.ProtocolVersion:=TRNLEndianness.HostToLittleEndian64(RNL_PROTOCOL_VERSION);
   Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.Header.ProtocolID:=TRNLEndianness.HostToLittleEndian64(fProtocolID);
   Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.Header.PacketType:=TRNLInt32(TRNLProtocolHandshakePacketType(RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_APPROVAL_RESPONSE));

   Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionApprovalResponse.PeerID:=TRNLEndianness.HostToLittleEndian16(ConnectionCandidate^.OutgoingPeerID);
   Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionApprovalResponse.ConnectionSalt:=TRNLEndianness.HostToLittleEndian64(ConnectionSalt);
   Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionApprovalResponse.Nonce:=TRNLEndianness.HostToLittleEndian64(ConnectionCandidate^.Nonce);

   Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionApprovalResponse.Payload.PeerID:=TRNLEndianness.HostToLittleEndian16(Peer.fLocalPeerID);

   PRNLUInt64Array(TRNLPointer(@Nonce))^[0]:=TRNLEndianness.HostToLittleEndian64(ConnectionCandidate^.Nonce);
   PRNLUInt64Array(TRNLPointer(@Nonce))^[1]:=TRNLEndianness.HostToLittleEndian64(ConnectionCandidate^.RemoteSalt);
   PRNLUInt64Array(TRNLPointer(@Nonce))^[2]:=TRNLEndianness.HostToLittleEndian64(ConnectionCandidate^.LocalSalt);

   if not TRNLAuthenticatedEncryption.Encrypt(Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionApprovalResponse.Payload,
                                              ConnectionCandidate^.SharedSecretKey,
                                              Nonce,
                                              Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionApprovalResponse.PayloadMAC,
                                              ConnectionCandidate^.SolvedChallenge,
                                              SizeOf(TRNLConnectionChallenge),
                                              Peer.fPendingConnectionHandshakeSendData.fHandshakePacket.ConnectionApprovalResponse.Payload,
                                              SizeOf(TRNLProtocolHandshakePacketConnectionApprovalResponsePayload)) then begin
    exit;
   end;

   Peer.fPendingConnectionHandshakeSendData.Send;

   Peer.fState:=RNL_PEER_STATE_CONNECTION_APPROVING;

   Peer.fNextPendingConnectionSendTimeout:=fTime+fPendingConnectionSendTimeout;

   Peer.UpdateOutgoingBandwidthRateLimiter;

   ConnectionCandidate^.State:=RNL_CONNECTION_STATE_APPROVING;

  end else begin

   OutgoingPacket.Header.PacketType:=TRNLUInt32(TRNLProtocolHandshakePacketType(RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_DENIAL_RESPONSE));

   OutgoingPacket.ConnectionDenialResponse.PeerID:=TRNLEndianness.HostToLittleEndian16(ConnectionCandidate^.OutgoingPeerID);
   OutgoingPacket.ConnectionDenialResponse.ConnectionSalt:=TRNLEndianness.HostToLittleEndian64(ConnectionSalt);
   OutgoingPacket.ConnectionDenialResponse.Nonce:=TRNLEndianness.HostToLittleEndian64(ConnectionCandidate^.Nonce);

   if not Authorized then begin
    OutgoingPacket.ConnectionDenialResponse.Payload.Reason:=TRNLInt32(TRNLConnectionDenialReason(RNL_CONNECTION_DENIAL_REASON_UNAUTHORIZED));
   end else if (fCountPeers+1)>=fMaximumCountPeers then begin
    OutgoingPacket.ConnectionDenialResponse.Payload.Reason:=TRNLInt32(TRNLConnectionDenialReason(RNL_CONNECTION_DENIAL_REASON_FULL));
   end else if RemoteCountChannels=0 then begin
    OutgoingPacket.ConnectionDenialResponse.Payload.Reason:=TRNLInt32(TRNLConnectionDenialReason(RNL_CONNECTION_DENIAL_REASON_TOO_LESS_CHANNELS));
   end else if RemoteCountChannels>fMaximumCountChannels then begin
    OutgoingPacket.ConnectionDenialResponse.Payload.Reason:=TRNLInt32(TRNLConnectionDenialReason(RNL_CONNECTION_DENIAL_REASON_TOO_MANY_CHANNELS));
   end else if TRNLMemory.SecureIsNonEqual(RemoteChannelTypes,fChannelTypes,SizeOf(TRNLPeerChannelType)*RemoteCountChannels) then begin
    OutgoingPacket.ConnectionDenialResponse.Payload.Reason:=TRNLInt32(TRNLConnectionDenialReason(RNL_CONNECTION_DENIAL_REASON_WRONG_CHANNEL_TYPES));
   end else begin
    OutgoingPacket.ConnectionDenialResponse.Payload.Reason:=TRNLInt32(TRNLConnectionDenialReason(RNL_CONNECTION_DENIAL_REASON_UNKNOWN));
   end;

   PRNLUInt64Array(TRNLPointer(@Nonce))^[0]:=TRNLEndianness.HostToLittleEndian64(ConnectionCandidate^.Nonce);
   PRNLUInt64Array(TRNLPointer(@Nonce))^[1]:=TRNLEndianness.HostToLittleEndian64(ConnectionCandidate^.RemoteSalt);
   PRNLUInt64Array(TRNLPointer(@Nonce))^[2]:=TRNLEndianness.HostToLittleEndian64(ConnectionCandidate^.LocalSalt);

   if not TRNLAuthenticatedEncryption.Encrypt(OutgoingPacket.ConnectionDenialResponse.Payload,
                                              ConnectionCandidate^.SharedSecretKey,
                                              Nonce,
                                              OutgoingPacket.ConnectionDenialResponse.PayloadMAC,
                                              ConnectionCandidate^.SolvedChallenge,
                                              SizeOf(TRNLConnectionChallenge),
                                              OutgoingPacket.ConnectionDenialResponse.Payload,
                                              SizeOf(TRNLProtocolHandshakePacketConnectionDenialResponsePayload)) then begin
    exit;
   end;

   AddHandshakePacketChecksum(OutgoingPacket);

   SendPacket(fReceivedAddress,
              OutgoingPacket,
              SizeOf(TRNLProtocolHandshakePacketConnectionDenialResponse));

   ConnectionCandidate^.State:=RNL_CONNECTION_STATE_INVALID;

  end;

 end;

end;

procedure TRNLHost.DispatchReceivedHandshakePacketConnectionApprovalResponse(const aIncomingPacket:PRNLProtocolHandshakePacketConnectionApprovalResponse);
var PeerID:TRNLID;
    Peer:TRNLPeer;
    HostEvent:TRNLHostEvent;
    Nonce:TRNLCipherNonce;
    OutgoingPacket:TRNLProtocolHandshakePacket;
begin

{$if defined(RNL_DEBUG) and defined(RNL_DEBUG_SECURITY)}
 fInstance.fDebugLock.Acquire;
 try
  writeln('DispatchReceivedHandshakePacketConnectionApprovalResponse');
 finally
  fInstance.fDebugLock.Release;
 end;
{$ifend}

 PeerID:=TRNLEndianness.LittleEndianToHost16(aIncomingPacket^.PeerID);

 Peer:=fPeerIDMap[PeerID];
 if not assigned(Peer) then begin
  exit;
 end;

 if Peer.fConnectionSalt<>TRNLEndianness.LittleEndianToHost64(aIncomingPacket^.ConnectionSalt) then begin
  exit;
 end;

 PRNLUInt64Array(TRNLPointer(@Nonce))^[0]:=aIncomingPacket^.Nonce;
 PRNLUInt64Array(TRNLPointer(@Nonce))^[1]:=TRNLEndianness.HostToLittleEndian64(Peer.fLocalSalt);
 PRNLUInt64Array(TRNLPointer(@Nonce))^[2]:=TRNLEndianness.HostToLittleEndian64(Peer.fRemoteSalt);

 if not TRNLAuthenticatedEncryption.Decrypt(aIncomingPacket^.Payload,
                                            Peer.fSharedSecretKey,
                                            Nonce,
                                            aIncomingPacket^.PayloadMAC,
                                            Peer.fConnectionChallengeResponse^,
                                            SizeOf(TRNLConnectionChallenge),
                                            aIncomingPacket^.Payload,
                                            SizeOf(TRNLProtocolHandshakePacketConnectionApprovalResponsePayload)) then begin
  exit;
 end;

 Peer.fState:=RNL_PEER_STATE_CONNECTED;

 Peer.fRemotePeerID:=TRNLEndianness.LittleEndianToHost16(aIncomingPacket^.Payload.PeerID);

 HostEvent.Type_:=RNL_HOST_EVENT_TYPE_APPROVAL;
 HostEvent.Approval.Peer:=Peer;
 fEventQueue.Enqueue(HostEvent);

 OutgoingPacket.Header.Signature:=RNLProtocolHandshakePacketHeaderSignature;
 OutgoingPacket.Header.ProtocolVersion:=TRNLEndianness.HostToLittleEndian64(RNL_PROTOCOL_VERSION);
 OutgoingPacket.Header.ProtocolID:=TRNLEndianness.HostToLittleEndian64(fProtocolID);
 OutgoingPacket.Header.PacketType:=TRNLUInt32(TRNLProtocolHandshakePacketType(RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_APPROVAL_ACKNOWLEDGE));
 OutgoingPacket.Header.Checksum:=0;

 OutgoingPacket.ConnectionApprovalAcknowledge.PeerID:=TRNLEndianness.HostToLittleEndian16(Peer.fRemotePeerID);
 OutgoingPacket.ConnectionApprovalAcknowledge.ConnectionSalt:=TRNLEndianness.HostToLittleEndian64(Peer.fConnectionSalt);
 OutgoingPacket.ConnectionApprovalAcknowledge.Nonce:=fRandomGenerator.GetUInt64;

 FillChar(OutgoingPacket.ConnectionApprovalAcknowledge.WholePacketMAC,SizeOf(TRNLCipherMAC),#0);

 TRNLPoly1305.OneTimeAuthentication(OutgoingPacket.ConnectionApprovalAcknowledge.WholePacketMAC,
                                    OutgoingPacket,
                                    SizeOf(TRNLProtocolHandshakePacketConnectionApprovalAcknowledge),
                                    Peer.fSharedSecretKey);

 AddHandshakePacketChecksum(OutgoingPacket);

 SendPacket(Peer.fAddress,
            OutgoingPacket,
            SizeOf(TRNLProtocolHandshakePacketConnectionApprovalAcknowledge));

end;

procedure TRNLHost.DispatchReceivedHandshakePacketConnectionDenialResponse(const aIncomingPacket:PRNLProtocolHandshakePacketConnectionDenialResponse);
var PeerID:TRNLID;
    Peer:TRNLPeer;
    HostEvent:TRNLHostEvent;
    Nonce:TRNLCipherNonce;
begin

{$if defined(RNL_DEBUG) and defined(RNL_DEBUG_SECURITY)}
 fInstance.fDebugLock.Acquire;
 try
  writeln('DispatchReceivedHandshakePacketConnectionDenialResponse');
 finally
  fInstance.fDebugLock.Release;
 end;
{$ifend}

 PeerID:=TRNLEndianness.LittleEndianToHost16(aIncomingPacket^.PeerID);

 Peer:=fPeerIDMap[PeerID];
 if not assigned(Peer) then begin
  exit;
 end;

 if Peer.fConnectionSalt<>TRNLEndianness.LittleEndianToHost64(aIncomingPacket^.ConnectionSalt) then begin
  exit;
 end;

 PRNLUInt64Array(TRNLPointer(@Nonce))^[0]:=aIncomingPacket^.Nonce;
 PRNLUInt64Array(TRNLPointer(@Nonce))^[1]:=TRNLEndianness.HostToLittleEndian64(Peer.fLocalSalt);
 PRNLUInt64Array(TRNLPointer(@Nonce))^[2]:=TRNLEndianness.HostToLittleEndian64(Peer.fRemoteSalt);

 if not TRNLAuthenticatedEncryption.Decrypt(aIncomingPacket^.Payload,
                                            Peer.fSharedSecretKey,
                                            Nonce,
                                            aIncomingPacket^.PayloadMAC,
                                            Peer.fConnectionChallengeResponse^,
                                            SizeOf(TRNLConnectionChallenge),
                                            aIncomingPacket^.Payload,
                                            SizeOf(TRNLProtocolHandshakePacketConnectionDenialResponsePayload)) then begin
  exit;
 end;

 Peer.fState:=RNL_PEER_STATE_DISCONNECTED;

 HostEvent.Type_:=RNL_HOST_EVENT_TYPE_DENIAL;
 HostEvent.Denial.Peer:=Peer;
 HostEvent.Denial.Reason:=TRNLConnectionDenialReason(TRNLInt32(aIncomingPacket^.Payload.Reason));
 fEventQueue.Enqueue(HostEvent);

end;

procedure TRNLHost.DispatchReceivedHandshakePacketConnectionApprovalAcknowledge(const aIncomingPacket:PRNLProtocolHandshakePacketConnectionApprovalAcknowledge);
var PeerID:TRNLID;
    Peer:TRNLPeer;
    MAC:TRNLCipherMAC;
    HostEvent:TRNLHostEvent;
    ConnectionCandidate:PRNLConnectionCandidate;
begin

{$if defined(RNL_DEBUG) and defined(RNL_DEBUG_SECURITY)}
 fInstance.fDebugLock.Acquire;
 try
  writeln('DispatchReceivedHandshakePacketConnectionApprovalAcknowledge');
 finally
  fInstance.fDebugLock.Release;
 end;
{$ifend}

 PeerID:=TRNLEndianness.LittleEndianToHost16(aIncomingPacket^.PeerID);

 Peer:=fPeerIDMap[PeerID];
 if not assigned(Peer) then begin
  exit;
 end;

 if Peer.fConnectionSalt<>TRNLEndianness.LittleEndianToHost64(aIncomingPacket^.ConnectionSalt) then begin
  exit;
 end;

 aIncomingPacket^.Header.Checksum:=0;

 MAC:=aIncomingPacket^.WholePacketMAC;

 FillChar(aIncomingPacket^.WholePacketMAC,SizeOf(TRNLCipherMAC),#0);

 if not TRNLPoly1305.OneTimeAuthenticationVerify(MAC,
                                                 aIncomingPacket^,
                                                 SizeOf(TRNLProtocolHandshakePacketConnectionApprovalAcknowledge),
                                                 Peer.fSharedSecretKey) then begin
  exit;
 end;

 FreeAndNil(Peer.fPendingConnectionHandshakeSendData);

 if not (Peer.fState in RNLNormalPacketPeerStates) then begin

  Peer.fState:=RNL_PEER_STATE_CONNECTED;

  Peer.UpdateOutgoingBandwidthRateLimiter;

  HostEvent.Type_:=RNL_HOST_EVENT_TYPE_CONNECT;
  HostEvent.Approval.Peer:=Peer;
  fEventQueue.Enqueue(HostEvent);

  ConnectionCandidate:=fConnectionCandidateHashTable^.Find(fRandomGenerator,
                                                           fReceivedAddress,
                                                           TRNLEndianness.LittleEndianToHost64(aIncomingPacket^.ConnectionSalt) xor fSalt,
                                                           fSalt,
                                                           fInstance.Time,
                                                           fPendingConnectionTimeout,
                                                           false);
  if assigned(ConnectionCandidate) then begin

   ConnectionCandidate^.State:=RNL_CONNECTION_STATE_INVALID;

  end;

 end;

end;

procedure TRNLHost.DispatchReceivedHandshakePacketData(var aPacketData;const aPacketDataLength:TRNLSizeUInt);
var ProtocolHandshakePacket:PRNLProtocolHandshakePacket;
begin

 if aPacketDataLength<SizeOf(TRNLProtocolHandshakePacketHeader) then begin
  exit;
 end;

 ProtocolHandshakePacket:=@aPacketData;

 // Protocol version check, but ignore the patch number part of the whole version number
 if ((TRNLEndianness.LittleEndianToHost64(ProtocolHandshakePacket^.Header.ProtocolVersion) xor RNL_PROTOCOL_VERSION) and TRNLUInt64($ffffffffffff0000))<>0 then begin
  exit;
 end;

 // Protocol ID check
 if TRNLEndianness.LittleEndianToHost64(ProtocolHandshakePacket^.Header.ProtocolID)<>fProtocolID then begin
  exit;
 end;

 if not VerifyHandshakePacketChecksum(ProtocolHandshakePacket^) then begin
  exit;
 end;

 case TRNLProtocolHandshakePacketType(TRNLInt32(ProtocolHandshakePacket^.Header.PacketType)) of
  RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_REQUEST:begin
   if aPacketDataLength=SizeOf(TRNLProtocolHandshakePacketConnectionRequest) then begin
    DispatchReceivedHandshakePacketConnectionRequest(@aPacketData);
   end;
  end;
  RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_CHALLENGE_REQUEST:begin
   if aPacketDataLength=SizeOf(TRNLProtocolHandshakePacketConnectionChallengeRequest) then begin
    DispatchReceivedHandshakePacketConnectionChallengeRequest(@aPacketData);
   end;
  end;
  RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_CHALLENGE_RESPONSE:begin
   if aPacketDataLength=SizeOf(TRNLProtocolHandshakePacketConnectionChallengeResponse) then begin
    DispatchReceivedHandshakePacketConnectionChallengeResponse(@aPacketData);
   end;
  end;
  RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_AUTHENTICATION_REQUEST:begin
   if aPacketDataLength=SizeOf(TRNLProtocolHandshakePacketConnectionAuthenticationRequest) then begin
    DispatchReceivedHandshakePacketConnectionAuthenticationRequest(@aPacketData);
   end;
  end;
  RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_AUTHENTICATION_RESPONSE:begin
   if aPacketDataLength=SizeOf(TRNLProtocolHandshakePacketConnectionAuthenticationResponse) then begin
    DispatchReceivedHandshakePacketConnectionAuthenticationResponse(@aPacketData);
   end;
  end;
  RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_APPROVAL_RESPONSE:begin
   if aPacketDataLength=SizeOf(TRNLProtocolHandshakePacketConnectionApprovalResponse) then begin
    DispatchReceivedHandshakePacketConnectionApprovalResponse(@aPacketData);
   end;
  end;
  RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_DENIAL_RESPONSE:begin
   if aPacketDataLength=SizeOf(TRNLProtocolHandshakePacketConnectionDenialResponse) then begin
    DispatchReceivedHandshakePacketConnectionDenialResponse(@aPacketData);
   end;
  end;
  RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_APPROVAL_ACKNOWLEDGE:begin
   if aPacketDataLength=SizeOf(TRNLProtocolHandshakePacketConnectionApprovalAcknowledge) then begin
    DispatchReceivedHandshakePacketConnectionApprovalAcknowledge(@aPacketData);
   end;
  end;
  else begin
   exit;
  end;
 end;

end;

procedure TRNLHost.DispatchReceivedNormalPacketData(var aPacketData;const aPacketDataLength:TRNLSizeUInt);
var NormalPacketHeader:PRNLProtocolNormalPacketHeader;
    LocalPeerID:TRNLID;
    Peer:TRNLPeer;
    PacketData:TBytes;
begin

 NormalPacketHeader:=@aPacketData;

 if NormalPacketHeader^.Not255=$ff then begin
  // 255? Ups, there's probably something went wrong then :-)
  exit;
 end;

 LocalPeerID:=TRNLEndianness.LittleEndianToHost16(NormalPacketHeader^.PeerID);

 Peer:=fPeerIDMap[LocalPeerID];
 if not assigned(Peer) then begin
  exit;
 end;

 SetLength(PacketData,aPacketDataLength);
 Move(aPacketData,PacketData[0],aPacketDataLength);

 Peer.fIncomingPacketQueue.Enqueue(PacketData);

end;

procedure TRNLHost.DispatchReceivedPacketData(var aPacketData;const aPacketDataLength:TRNLSizeUInt);
begin

 if (aPacketDataLength>=SizeOf(TRNLProtocolHandshakePacketHeaderSignature)) and
    (TRNLUInt32(aPacketData)=PRNLUInt32(TRNLPointer(@RNLProtocolHandshakePacketHeaderSignature))^) then begin

  DispatchReceivedHandshakePacketData(aPacketData,aPacketDataLength);

 end else if aPacketDataLength>=SizeOf(TRNLProtocolNormalPacketHeader) then begin

  DispatchReceivedNormalPacketData(aPacketData,aPacketDataLength);

 end else begin

  // Otherwise just discard it :-)

 end;

end;

function TRNLHost.DispatchPeers(var aNextTimeout:TRNLTime):boolean;
var Peer:TRNLPeer;
begin

 fNextPeerEventTime.fValue:=TRNLUInt64(High(TRNLUInt64));

 for Peer in fPeerList do begin
  if not Peer.DispatchPeer then begin
   result:=false;
   exit;
  end;
 end;

 if (fNextPeerEventTime<>TRNLUInt64(High(TRNLUInt64))) and
    (fNextPeerEventTime>fTime) and
    (fNextPeerEventTime<aNextTimeout) then begin
  aNextTimeout:=fNextPeerEventTime;
 end;

 result:=true;

end;

function TRNLHost.ReceivePackets(const aTimeout:TRNLTime):boolean;
var Index,Family,Packets:TRNLInt32;
    Socket:TRNLSocket;
    HadReceived:boolean;
begin

 Packets:=0;
 repeat

  HadReceived:=false;

  for Index:=Low(TRNLHostSockets) to High(TRNLHostSockets) do begin

   Socket:=fSockets[Index];

   if Socket<>RNL_SOCKET_NULL then begin

    Family:=HostSocketFamilies[Index];

    fReceivedBufferLength:=fNetwork.Receive(Socket,
                                            @fReceivedAddress,
                                            fReceiveBuffer,
                                            SizeOf(fReceiveBuffer),
                                            Family);

    if fReceivedBufferLength>0 then begin
     fIncomingBandwidthRateTracker.AddUnits(fReceivedBufferLength shl 3);
    end;

    if (fReceivedBufferLength<0){or
       ((fReceivedBufferLength>0) and (fReceivedAddress.GetAddressFamily<>Family))} then begin

     result:=false;
     exit;

    end else if fReceivedBufferLength>0 then begin

     HadReceived:=true;

     DispatchReceivedPacketData(fReceiveBuffer,fReceivedBufferLength);

     inc(fTotalReceivedData,fReceivedBufferLength);
     inc(fTotalReceivedPackets);

    end;

   end;

  end;

  inc(Packets);

 until (not HadReceived) or
       (((Packets and 1023)=0) and
        (fInstance.Time>=aTimeout));

 result:=true;

end;

procedure TRNLHost.BroadcastMessage(const aChannel:TRNLUInt8;const aMessage:TRNLMessage);
var Peer:TRNLPeer;
begin
 for Peer in fPeerList do begin
  if Peer.fState in [RNL_PEER_STATE_CONNECTED,
                     RNL_PEER_STATE_DISCONNECT_LATER] then begin
   Peer.Channels[aChannel].SendMessage(aMessage);
  end;
 end;
end;

procedure TRNLHost.BroadcastMessageData(const aChannel:TRNLUInt8;const aData:TRNLPointer;const aDataLength:TRNLUInt32;const aFlags:TRNLMessageFlags=[]);
var Message:TRNLMessage;
begin
 Message:=TRNLMessage.CreateFromMemory(aData,aDataLength,aFlags);
 try
  BroadcastMessage(aChannel,Message);
 finally
  Message.DecRef;
 end;
end;

procedure TRNLHost.BroadcastMessageString(const aChannel:TRNLUInt8;const aString:TRNLRawByteString;const aFlags:TRNLMessageFlags=[]);
var Message:TRNLMessage;
begin
 Message:=TRNLMessage.CreateFromString(aString,aFlags);
 try
  BroadcastMessage(aChannel,Message);
 finally
  Message.DecRef;
 end;
end;

procedure TRNLHost.BroadcastMessageStream(const aChannel:TRNLUInt8;const aStream:TStream;const aFlags:TRNLMessageFlags=[]);
var Message:TRNLMessage;
begin
 Message:=TRNLMessage.CreateFromStream(aStream,aFlags);
 try
  BroadcastMessage(aChannel,Message);
 finally
  Message.DecRef;
 end;
end;

procedure TRNLHost.FreeEvent(var aEvent:TRNLHostEvent);
begin
 case aEvent.Type_ of
  RNL_HOST_EVENT_TYPE_NONE:begin
  end;
  RNL_HOST_EVENT_TYPE_CONNECT:begin
  end;
  RNL_HOST_EVENT_TYPE_DISCONNECT:begin
   FreeAndNil(aEvent.Disconnect.Peer);
  end;
  RNL_HOST_EVENT_TYPE_DENIAL:begin
   FreeAndNil(aEvent.Denial.Peer);
  end;
  RNL_HOST_EVENT_TYPE_RECEIVE:begin
   if assigned(aEvent.Receive.Message) then begin
    aEvent.Receive.Message.DecRef;
    aEvent.Receive.Message:=nil;
   end;
  end;
 end;
 aEvent.Type_:=RNL_HOST_EVENT_TYPE_NONE;
end;

function TRNLHost.Service(const aEvent:PRNLHostEvent=nil;
                          const aTimeout:TRNLInt64=1000):TRNLHostServiceStatus;
var Timeout,NextTimeout:TRNLTime;
    WaitConditions:TRNLSocketWaitConditions;
begin

 result:=RNL_HOST_SERVICE_STATUS_TIMEOUT;

 if assigned(aEvent) then begin
  FreeEvent(aEvent^);
 end;

 Timeout:=fInstance.Time+Max(0,aTimeout);

 repeat

{$if defined(RNL_DEBUG) and defined(RNL_DEBUG_EXTENDED)}
  fInstance.fDebugLock.Acquire;
  try
   writeln('Blup');
  finally
   fInstance.fDebugLock.Release;
  end;
{$ifend}

  repeat

   if assigned(aEvent) and fEventQueue.Dequeue(aEvent^) then begin
    result:=RNL_HOST_SERVICE_STATUS_EVENT;
    exit;
   end;

   // When aTimeout is negative (for example -1), then we do check only the event queue (for TRNLHost.CheckEvents)
   if aTimeout<0 then begin
    result:=RNL_HOST_SERVICE_STATUS_TIMEOUT;
    exit;
   end;

   fTime:=fInstance.Time;

   fIncomingBandwidthRateTracker.SetTime(fTime);
   fIncomingBandwidthRateTracker.Update;

   fOutgoingBandwidthRateTracker.SetTime(fTime);
   fOutgoingBandwidthRateTracker.Update;

   NextTimeout:=Timeout;

   if not DispatchPeers(NextTimeout) then begin
    result:=RNL_HOST_SERVICE_STATUS_ERROR;
    exit;
   end;

   if not ReceivePackets(NextTimeout) then begin
    result:=RNL_HOST_SERVICE_STATUS_ERROR;
    exit;
   end;

   NextTimeout:=Timeout;

   if not DispatchPeers(NextTimeout) then begin
    result:=RNL_HOST_SERVICE_STATUS_ERROR;
    exit;
   end;

  until fEventQueue.IsEmpty or
        (fTime>=NextTimeout);

  // When aTimeout is zero, then we doing only one iteration without waiting (as fake-flushing for TRNLHost.Flush)
  if aTimeout=0 then begin
   result:=RNL_HOST_SERVICE_STATUS_TIMEOUT;
   exit;
  end;

  repeat

   fTime:=fInstance.Time;

   if fTime>=Timeout then begin
    result:=RNL_HOST_SERVICE_STATUS_TIMEOUT;
    exit;
   end;

   WaitConditions:=[RNL_SOCKET_WAIT_CONDITION_RECEIVE,
                    RNL_SOCKET_WAIT_CONDITION_INTERRUPT];

  if not fNetwork.SocketWait(fSockets,
                              WaitConditions,
                              TRNLTime.Difference(NextTimeout,fTime)) then begin
    result:=RNL_HOST_SERVICE_STATUS_ERROR;
    exit;
   end;

  until not (RNL_SOCKET_WAIT_CONDITION_INTERRUPT in WaitConditions);

 until (not (RNL_SOCKET_WAIT_CONDITION_RECEIVE in WaitConditions)) and
       (fInstance.Time>=Timeout);

end;

function TRNLHost.CheckEvents(var aEvent:TRNLHostEvent):boolean;
begin
 result:=Service(@aEvent,-1)=RNL_HOST_SERVICE_STATUS_EVENT;
end;

function TRNLHost.Flush:boolean;
begin
 result:=Service(nil,0)<>RNL_HOST_SERVICE_STATUS_ERROR;
end;

initialization
 InitializeCRC32C;
finalization
end.
