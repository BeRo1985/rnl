(*******************************************************************************
 *                         RNL TEST DTLS SERVER                                *
 *******************************************************************************
 *                        Version 2026-08-03-00-00-0000                        *
 *******************************************************************************
 *                                                                             *
 * A DTLS 1.2 server just complete enough to carry TRNLDTLS12Client through a  *
 * handshake, so that the state machine can be driven against something which  *
 * is not the network and not the one relay which happens to be reachable.     *
 *                                                                             *
 * It owns no socket and no thread, unlike the STUN and TURN stubs next to it. *
 * Both sides here are fed datagrams by the test itself and asked for the ones *
 * they want to send, which is what makes losing a flight, holding the clock   *
 * still and watching a retransmission happen at the millisecond it was due    *
 * possible at all. Against a real socket none of those can be arranged.       *
 *                                                                             *
 * The interesting part is not the correct handshake but the wrong ones. Every *
 * variant of TRNLTestDTLSServerBehaviour below is a server which is broken or *
 * hostile in exactly one way, and each of them exists because there is a      *
 * check in the client which it, and nothing else in the suite, makes fail.    *
 *                                                                             *
 * Two things here are not anchors and should not be read as any:              *
 *                                                                             *
 *  * the key schedule, the record protection and the transcript run on RNL's  *
 *    own code, so a handshake completing proves the two sides agree and       *
 *    nothing about whether they agree with anybody else. What settles that is *
 *    the captured vectors of RNL.pas, which came from a handshake a real      *
 *    coturn accepted.                                                         *
 *                                                                             *
 *  * the ECDSA signing below is built on RNL's own field arithmetic, which    *
 *    RNL itself never signs with - a client has no certificate to present. It *
 *    is held to the RFC 6979 vector, so it is at least not free to be wrong   *
 *    in the same direction as the verifier.                                   *
 *                                                                             *
 ******************************************************************************)
unit RNLTestDTLSServer;
{$ifdef fpc}
 {$mode delphi}
{$endif}
{$h+}

interface

uses SysUtils,
     Classes,
     SyncObjs,
     RNL,
     RNLTestCertificates;

type // ECDSA over P-256 the other way round from RNL, which only ever verifies. It exists because a
     // server has to sign its ServerKeyExchange over two randoms it cannot know in advance, so no
     // precomputed signature would do and no capture could stand in for one.
     //
     // Written on TRNLEC rather than as a second implementation of the arithmetic. That makes it
     // scaffolding, not an anchor: it says nothing about whether that arithmetic is right. What says
     // so is the NIST and RFC 6979 vectors the verifier is pinned against - and the same RFC 6979
     // vector applied to this routine, which is what keeps a signer that is wrong in the same
     // direction as the verifier from going unnoticed.
     TRNLTestECDSA=record
      public
       const ElementSize=TRNLP256.ElementSize;
             // A SEQUENCE of two INTEGERs of at most thirty three bytes each
             MaximumSignatureSize=2+(2*(2+(ElementSize+1)));
      public
       // aK is the per signature secret. Supplied rather than drawn here, so that a fixed one can be
       // handed in and the result compared against a published pair.
       class function Sign(out aR,aS_;
                           const aPrivateKey;const aK;
                           const aHash;const aHashSize:TRNLSizeInt):boolean; static;
       class function EncodeInteger(out aData;const aValue;
                                    const aValueSize:TRNLSizeInt):TRNLSizeInt; static;
       // The ECDSA-Sig-Value which both a certificate and a ServerKeyExchange carry
       class function EncodeSignature(out aData;out aDataSize:TRNLSizeInt;
                                      const aMaximumDataSize:TRNLSizeInt;
                                      const aR,aS_):boolean; static;
     end;

     TRNLTestDTLSServerBehaviour=
      (
       // A correct handshake, and the one every other case is measured against
       RNL_TEST_DTLS_SERVER_CORRECT,
       // Answers the very first ClientHello with its whole flight, asking for no cookie. Which of
       // the two happens is the server's choice and not the client's, so both have to work.
       RNL_TEST_DTLS_SERVER_WITHOUT_COOKIE_EXCHANGE,
       // Correct, except that its flight is cut into small fragments and sent last one first
       RNL_TEST_DTLS_SERVER_REVERSED_FRAGMENTS,
       // Correct, except that every message is sent twice and cut at different boundaries the
       // second time, so the two copies overlap without agreeing where anything begins
       RNL_TEST_DTLS_SERVER_OVERLAPPING_FRAGMENTS,
       // Throws its first real flight away and sends it only when the client asks a second time
       RNL_TEST_DTLS_SERVER_LOSES_ITS_FIRST_FLIGHT,
       // The same for its last flight, which is the interesting one: what the client has to send
       // again there is already protected, and a repeated record number lands in the replay window
       RNL_TEST_DTLS_SERVER_LOSES_ITS_LAST_FLIGHT,
       // Answers nothing at all, ever
       RNL_TEST_DTLS_SERVER_SILENT,
       // Asks for a cookie a second time, after the client has already answered with one
       RNL_TEST_DTLS_SERVER_SECOND_HELLO_VERIFY_REQUEST,
       // Picks a cipher suite which was never offered
       RNL_TEST_DTLS_SERVER_UNOFFERED_CIPHER_SUITE,
       // Names a curve nobody offered, and which this client cannot do
       RNL_TEST_DTLS_SERVER_UNOFFERED_CURVE,
       // Signs something other than the parameters it sends
       RNL_TEST_DTLS_SERVER_BAD_KEY_EXCHANGE_SIGNATURE,
       // A leaf signed by a key which is not the intermediate's
       RNL_TEST_DTLS_SERVER_UNTRUSTED_CERTIFICATE,
       // A leaf whose validity ended before the clock the client is given
       RNL_TEST_DTLS_SERVER_EXPIRED_CERTIFICATE,
       // Its Finished carries verify data which is one byte different
       RNL_TEST_DTLS_SERVER_WRONG_VERIFY_DATA,
       // Its Finished arrives in the clear, with no ChangeCipherSpec in front of it
       RNL_TEST_DTLS_SERVER_FINISHED_WITHOUT_CHANGE_CIPHER_SPEC,
       // A fatal alert where the flight should have been
       RNL_TEST_DTLS_SERVER_FATAL_ALERT
      );

     TRNLTestDTLSServer=class
      public
       const MaximumDatagramSize=1200;
             MaximumQueuedDatagrams=32;
             MaximumFlightSize=4096;
             MaximumFlightEntries=8;
             CookieSize=16;
             // Small enough that the certificate chain really does travel in pieces, and that the
             // two cuttings of the overlapping case land on different bytes
             FirstFragmentSize=100;
             SecondFragmentSize=64;
      private
       type TRNLTestDTLSServerDatagram=record
             Data:array[0..MaximumDatagramSize-1] of TRNLUInt8;
             Size:TRNLSizeInt;
            end;
            TRNLTestDTLSServerEntry=record
             MessageType:TRNLUInt8;
             MessageSequence:TRNLUInt16;
             ContentType:TRNLUInt8;
             Epoch:TRNLUInt16;
             Offset:TRNLSizeInt;
             Size:TRNLSizeInt;
            end;
      private

       fBehaviour:TRNLTestDTLSServerBehaviour;
       fEchoExtendedMasterSecret:boolean;

       fRandomGenerator:TRNLRandomGenerator;

       fServerRandom:array[0..TRNLDTLS12ClientHello.RandomSize-1] of TRNLUInt8;
       fClientRandom:array[0..TRNLDTLS12ClientHello.RandomSize-1] of TRNLUInt8;
       fCookie:array[0..CookieSize-1] of TRNLUInt8;

       fPrivateKey:array[0..TRNLP256.ElementSize-1] of TRNLUInt8;
       fPublicKey:array[0..TRNLP256.PointSize-1] of TRNLUInt8;

       fTranscript:TRNLDTLS12Transcript;
       fKeySchedule:TRNLDTLS12KeySchedule;
       fClientKeys:TRNLDTLS12TrafficKeys;
       fServerKeys:TRNLDTLS12TrafficKeys;
       fUseExtendedMasterSecret:boolean;

       fSendEpoch:TRNLUInt16;
       fSendSequenceNumbers:array[0..1] of TRNLUInt64;
       fReceiveEpoch:TRNLUInt16;
       fReplayWindow:TRNLDTLSReplayWindow;
       fNextSendMessageSequence:TRNLUInt16;

       fSentHelloVerifyRequest:boolean;
       fBuiltServerFlight:boolean;
       fBuiltServerFinishedFlight:boolean;
       fSeenClientKeyExchange:boolean;
       fSeenClientFinished:boolean;
       fLostTheFirstFlight:boolean;
       fLostTheLastFlight:boolean;
       fFragmentThisFlight:boolean;

       fFlight:array[0..MaximumFlightSize-1] of TRNLUInt8;
       fFlightSize:TRNLSizeInt;
       fEntries:array[0..MaximumFlightEntries-1] of TRNLTestDTLSServerEntry;
       fCountEntries:TRNLSizeInt;

       fPacking:TRNLTestDTLSServerDatagram;
       fOutgoing:array[0..MaximumQueuedDatagrams-1] of TRNLTestDTLSServerDatagram;
       fOutgoingHead:TRNLSizeInt;
       fCountOutgoing:TRNLSizeInt;

       fRecordBuffer:array[0..TRNLDTLS12Record.MaximumContentSize-1] of TRNLUInt8;

       fCountClientHellos:TRNLSizeInt;
       fCountFlightsSent:TRNLSizeInt;
       fCountAlertsReceived:TRNLSizeInt;
       fLastAlertDescription:TRNLUInt8;
       fClientFinishedVerified:boolean;
       fCountApplicationDataRecords:TRNLSizeInt;
       fLastApplicationData:TRNLTestDTLSServerDatagram;
       // Every application datagram, not only the last: a terminator in front of a relay
       // has to pass each one on, and dropping all but the newest would lose exactly the
       // request whose answer the test is waiting for.
       fIncoming:array[0..7] of TRNLTestDTLSServerDatagram;
       fIncomingHead:TRNLSizeInt;
       fCountIncoming:TRNLSizeInt;

       procedure QueuePacking;
       procedure EmitRecord(const aContentType:TRNLUInt8;const aEpoch:TRNLUInt16;
                            const aContent;const aContentSize:TRNLSizeInt);
       procedure EmitEntry(const aIndex,aChunkSize:TRNLSizeInt;const aReversed:boolean);
       procedure EmitFlight;

       procedure BeginFlight;
       function AppendMessage(const aMessageType:TRNLUInt8;
                              const aBody;const aBodySize:TRNLSizeInt;
                              const aEpoch:TRNLUInt16;
                              const aInTranscript:boolean):boolean;
       function AppendChangeCipherSpec:boolean;

       procedure BuildHelloVerifyRequest;
       function BuildServerFlight:boolean;
       function BuildServerFinishedFlight:boolean;

       procedure HandleClientHello(const aBody;const aBodySize:TRNLSizeInt);
       procedure HandleClientKeyExchange(const aBody;const aBodySize:TRNLSizeInt);
       procedure HandleClientFinished(const aBody;const aBodySize:TRNLSizeInt);
       procedure HandleHandshakeFragments(const aContent;const aContentSize:TRNLSizeInt);
       procedure HandleRecord(const aContentType:TRNLUInt8;
                              const aContent;const aContentSize:TRNLSizeInt);

      public

       constructor Create(const aBehaviour:TRNLTestDTLSServerBehaviour;
                          const aEchoExtendedMasterSecret:boolean=false); reintroduce;
       destructor Destroy; override;

       procedure ProcessDatagram(const aData;const aDataSize:TRNLSizeInt);
       function PopOutgoingDatagram(out aData;out aDataSize:TRNLSizeInt;
                                    const aMaximumDataSize:TRNLSizeInt):boolean;
       function Send(const aData;const aDataSize:TRNLSizeInt):boolean;
       // Whether the last application data record to arrive said exactly this. A comparison rather
       // than a window into the buffer, so that nothing outside can hold on to it.
       function LastApplicationDataMatches(const aData;const aDataSize:TRNLSizeInt):boolean;
       function TakeApplicationData(out aData;out aSize:TRNLSizeInt;
                                    const aMaximumSize:TRNLSizeInt):boolean;

       property CountClientHellos:TRNLSizeInt read fCountClientHellos;
       property CountFlightsSent:TRNLSizeInt read fCountFlightsSent;
       property CountAlertsReceived:TRNLSizeInt read fCountAlertsReceived;
       property LastAlertDescription:TRNLUInt8 read fLastAlertDescription;
       property ClientFinishedVerified:boolean read fClientFinishedVerified;
       property CountApplicationDataRecords:TRNLSizeInt read fCountApplicationDataRecords;
       property UseExtendedMasterSecret:boolean read fUseExtendedMasterSecret;

     end;

     TRNLTestDTLS13ServerBehaviour=
      (
       // A correct handshake over x25519, and the one every other case is measured against
       RNL_TEST_DTLS13_SERVER_CORRECT,
       // The same over secp256r1, which is the share the measured relays would pick
       RNL_TEST_DTLS13_SERVER_SECP256R1,
       // Its flight arrives cut into small fragments, last one first
       RNL_TEST_DTLS13_SERVER_REVERSED_FRAGMENTS,
       // Throws its flight away once and sends it only when asked again
       RNL_TEST_DTLS13_SERVER_LOSES_ITS_FLIGHT,
       // Answers nothing at all
       RNL_TEST_DTLS13_SERVER_SILENT,
       // A HelloRetryRequest, which this client can only refuse: it already sent both shares
       RNL_TEST_DTLS13_SERVER_HELLO_RETRY_REQUEST,
       // Picks a cipher suite which was never offered
       RNL_TEST_DTLS13_SERVER_UNOFFERED_CIPHER_SUITE,
       // Leaves supported_versions out, which makes it not a 1.3 ServerHello at all
       RNL_TEST_DTLS13_SERVER_WITHOUT_SUPPORTED_VERSIONS,
       // Names a group nobody offered
       RNL_TEST_DTLS13_SERVER_UNOFFERED_GROUP,
       // A CertificateVerify signed over a transcript which is not the one that happened
       RNL_TEST_DTLS13_SERVER_BAD_CERTIFICATE_VERIFY,
       // A leaf signed by a key which is not the intermediate's
       RNL_TEST_DTLS13_SERVER_UNTRUSTED_CERTIFICATE,
       // Its Finished carries verify data which is one byte different
       RNL_TEST_DTLS13_SERVER_WRONG_VERIFY_DATA,
       // The messages of its flight in the wrong order, Certificate before EncryptedExtensions
       RNL_TEST_DTLS13_SERVER_MESSAGES_OUT_OF_ORDER,
       // A fatal alert where the flight should have been
       RNL_TEST_DTLS13_SERVER_FATAL_ALERT
      );

     // The DTLS 1.3 counterpart of TRNLTestDTLSServer above, and the same idea: no socket, no
     // thread, fed by hand. What it has to do that the 1.2 one did not is encrypt most of its own
     // handshake - everything from EncryptedExtensions onwards travels under keys which are
     // derived halfway through the exchange, so a stub which could not do the key schedule could
     // not answer at all.
     TRNLTestDTLS13Server=class
      public
       const MaximumDatagramSize=1200;
             MaximumQueuedDatagrams=32;
             MaximumFlightSize=4096;
             MaximumFlightEntries=8;
             FragmentSize=64;
             EpochInitial=0;
             EpochHandshake=2;
             EpochApplication=3;
      private
       type TRNLTestDTLS13ServerDatagram=record
             Data:array[0..MaximumDatagramSize-1] of TRNLUInt8;
             Size:TRNLSizeInt;
            end;
            TRNLTestDTLS13ServerEntry=record
             MessageType:TRNLUInt8;
             MessageSequence:TRNLUInt16;
             Epoch:TRNLUInt64;
             Offset:TRNLSizeInt;
             Size:TRNLSizeInt;
            end;
      private

       fBehaviour:TRNLTestDTLS13ServerBehaviour;
       fRandomGenerator:TRNLRandomGenerator;

       fServerRandom:array[0..TRNLDTLS13ClientHello.RandomSize-1] of TRNLUInt8;

       fGroup:TRNLUInt16;
       fX25519PublicKey:TRNLKey;
       fX25519PrivateKey:TRNLKey;
       fSecp256r1PrivateKey:array[0..TRNLP256.ElementSize-1] of TRNLUInt8;
       fSecp256r1PublicKey:array[0..TRNLP256.PointSize-1] of TRNLUInt8;

       fTranscript:TRNLDTLS13Transcript;
       fKeySchedule:TRNLDTLS13KeySchedule;
       fClientHandshakeKeys:TRNLDTLSTrafficKeys;
       fServerHandshakeKeys:TRNLDTLSTrafficKeys;
       fClientApplicationKeys:TRNLDTLSTrafficKeys;
       fServerApplicationKeys:TRNLDTLSTrafficKeys;

       fSendEpoch:TRNLUInt64;
       fSendSequenceNumbers:array[0..3] of TRNLUInt64;
       fReceiveEpoch:TRNLUInt64;
       fReplayWindows:array[0..3] of TRNLDTLSReplayWindow;
       fNextSendMessageSequence:TRNLUInt16;

       fBuiltFlight:boolean;
       fLostAFlight:boolean;
       fSeenClientFinished:boolean;

       fFlight:array[0..MaximumFlightSize-1] of TRNLUInt8;
       fFlightSize:TRNLSizeInt;
       fEntries:array[0..MaximumFlightEntries-1] of TRNLTestDTLS13ServerEntry;
       fCountEntries:TRNLSizeInt;

       fPacking:TRNLTestDTLS13ServerDatagram;
       fOutgoing:array[0..MaximumQueuedDatagrams-1] of TRNLTestDTLS13ServerDatagram;
       fOutgoingHead:TRNLSizeInt;
       fCountOutgoing:TRNLSizeInt;

       fRecordBuffer:array[0..TRNLDTLSRecord.MaximumContentSize-1] of TRNLUInt8;

       fCountClientHellos:TRNLSizeInt;
       fCountFlightsSent:TRNLSizeInt;
       fCountAlertsReceived:TRNLSizeInt;
       fLastAlertDescription:TRNLUInt8;
       fClientFinishedVerified:boolean;
       fCountApplicationDataRecords:TRNLSizeInt;
       fLastApplicationData:TRNLTestDTLS13ServerDatagram;
       // Every application datagram, not only the last: a terminator in front of a relay
       // has to pass each one on, and dropping all but the newest would lose exactly the
       // request whose answer the test is waiting for.
       fIncoming:array[0..7] of TRNLTestDTLS13ServerDatagram;
       fIncomingHead:TRNLSizeInt;
       fCountIncoming:TRNLSizeInt;

       procedure QueuePacking;
       procedure EmitRecord(const aContentType:TRNLUInt8;const aEpoch:TRNLUInt64;
                            const aContent;const aContentSize:TRNLSizeInt);
       procedure EmitEntry(const aIndex,aChunkSize:TRNLSizeInt;const aReversed:boolean);
       procedure EmitFlight;
       procedure BeginFlight;
       function AppendMessage(const aMessageType:TRNLUInt8;
                              const aBody;const aBodySize:TRNLSizeInt;
                              const aEpoch:TRNLUInt64;
                              const aInTranscript:boolean):boolean;
       function BuildServerHello(const aClientShare;const aClientShareSize:TRNLSizeInt):boolean;
       function BuildRestOfFlight:boolean;
       procedure HandleClientHello(const aBody;const aBodySize:TRNLSizeInt);
       procedure HandleClientFinished(const aBody;const aBodySize:TRNLSizeInt);
       procedure HandleHandshakeFragments(const aContent;const aContentSize:TRNLSizeInt);
       procedure HandleRecord(const aContentType:TRNLUInt8;
                              const aContent;const aContentSize:TRNLSizeInt);

      public

       constructor Create(const aBehaviour:TRNLTestDTLS13ServerBehaviour); reintroduce;
       destructor Destroy; override;

       procedure ProcessDatagram(const aData;const aDataSize:TRNLSizeInt);
       function PopOutgoingDatagram(out aData;out aDataSize:TRNLSizeInt;
                                    const aMaximumDataSize:TRNLSizeInt):boolean;
       function Send(const aData;const aDataSize:TRNLSizeInt):boolean;
       function LastApplicationDataMatches(const aData;const aDataSize:TRNLSizeInt):boolean;
       function TakeApplicationData(out aData;out aSize:TRNLSizeInt;
                                    const aMaximumSize:TRNLSizeInt):boolean;

       property CountClientHellos:TRNLSizeInt read fCountClientHellos;
       property CountFlightsSent:TRNLSizeInt read fCountFlightsSent;
       property CountAlertsReceived:TRNLSizeInt read fCountAlertsReceived;
       property LastAlertDescription:TRNLUInt8 read fLastAlertDescription;
       property ClientFinishedVerified:boolean read fClientFinishedVerified;
       property CountApplicationDataRecords:TRNLSizeInt read fCountApplicationDataRecords;

     end;

type // A DTLS terminator in front of a relay, which is how a real deployment is built: the relay
     // itself speaks plain STUN and something in front of it does the record layer. Composing the
     // two stubs that way costs nothing - TRNLTestTURNServer is not touched at all, and both DTLS
     // stubs are already driven exactly like this, by datagrams in and out.
     //
     // One client at a time, because a test has one. A second one arriving would have to start its
     // own handshake, and the address of the first is simply replaced - which is wrong for a real
     // terminator and irrelevant here.
     TRNLTestDTLSRelay=class(TThread)
      private

       fInstance:TRNLInstance;
       fNetwork:TRNLNetwork;
       fFamily:TRNLAddressFamily;

       // What the client talks to, and what the relay behind this talks to
       fListenSocket:TRNLSocket;
       fForwardSocket:TRNLSocket;
       fTargetAddress:TRNLAddress;

       fClientAddress:TRNLAddress;
       fHasClient:boolean;

       fVersion:TRNLTURNDTLSVersion;
       fServer12:TRNLTestDTLSServer;
       fServer13:TRNLTestDTLS13Server;

       fLock:TCriticalSection;
       fCountClientDatagrams:TRNLSizeInt;
       fCountForwarded:TRNLSizeInt;
       fCountReturned:TRNLSizeInt;

       function GetCountForwarded:TRNLSizeInt;
       procedure Flush;

      protected

       procedure Execute; override;

      public

       constructor Create(const aInstance:TRNLInstance;
                          const aNetwork:TRNLNetwork;
                          const aListenHost:TRNLRawByteString;
                          const aListenPort:TRNLUInt16;
                          const aTargetAddress:TRNLAddress;
                          const aFamily:TRNLAddressFamily;
                          const aVersion:TRNLTURNDTLSVersion); reintroduce;
       destructor Destroy; override;

       // How many datagrams came out of the record layer and went on to the relay. Zero means the
       // handshake never finished, which is a different failure from a relay which said no.
       property CountForwarded:TRNLSizeInt read GetCountForwarded;

     end;

const // The leaf of RNLTestCertificates, whose key makechainvectors.c derives from this very
      // number. Every leaf in that unit shares it, which is what lets the expired and the
      // wrongly signed ones sign a ServerKeyExchange perfectly well - the client is meant to stop
      // at the certificate and never get as far as the signature.
      RNL_TEST_LEAF_PRIVATE_KEY:array[0..31] of TRNLUInt8=
       (
        $00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,
        $00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,
        $00,$00,$00,$00,$44,$44,$44,$44
       );

implementation

class function TRNLTestECDSA.Sign(out aR,aS_;
                                  const aPrivateKey;const aK;
                                  const aHash;const aHashSize:TRNLSizeInt):boolean;
var Curve:TRNLECCurve;
    K,D,E,R_,S,T,One,X,Y:TRNLECFieldElement;
    Base,Point:TRNLECPoint;
    Buffer:array[0..ElementSize-1] of TRNLUInt8;
    Taken:TRNLSizeInt;
begin

 result:=false;
 Curve:=TRNLP256.Curve;

 TRNLEC.FromBigEndian(K,aK,Curve.Limbs);
 TRNLEC.FromBigEndian(D,aPrivateKey,Curve.Limbs);
 if not (TRNLEC.Below(K,Curve.OrderModulus) and (TRNLEC.IsZeroMask(K)=0) and
         TRNLEC.Below(D,Curve.OrderModulus) and (TRNLEC.IsZeroMask(D)=0)) then begin
  exit;
 end;

 // The same rule the verifier uses, FIPS 186-4 section 6.4: as many of the leftmost bits of the
 // hash as the order is wide, then one conditional subtraction because the result is below 2n
 Taken:=aHashSize;
 if Taken>Curve.ElementSize then begin
  Taken:=Curve.ElementSize;
 end;
 FillChar(Buffer,SizeOf(Buffer),#0);
 if Taken>0 then begin
  Move(aHash,Buffer[Curve.ElementSize-Taken],Taken);
 end;
 TRNLEC.FromBigEndian(E,Buffer,Curve.Limbs);
 TRNLEC.Subtract(E,E,Curve.OrderModulus,Curve.OrderModulus,Curve.Limbs);

 // r is the x coordinate of kG, taken modulo n
 TRNLEC.BasePoint(Base,Curve);
 TRNLEC.PointMultiply(Point,K,Base,Curve);
 if not TRNLEC.PointToAffine(X,Y,Point,Curve) then begin
  exit;
 end;
 TRNLEC.Subtract(R_,X,Curve.OrderModulus,Curve.OrderModulus,Curve.Limbs);
 if TRNLEC.IsZeroMask(R_)<>0 then begin
  exit;
 end;

 // s = k^-1 (e + r d) mod n, in Montgomery form the whole way, which is how the verifier does its
 // own arithmetic modulo n as well
 TRNLEC.MontgomeryMultiply(K,K,Curve.OrderMontgomeryRSquared,Curve.OrderModulus,
                           Curve.OrderNegativeInverse,Curve.Limbs);
 TRNLEC.MontgomeryInvert(K,K,Curve.OrderModulus,Curve.OrderNegativeInverse,
                         Curve.OrderMontgomeryOne,Curve.Limbs);
 TRNLEC.MontgomeryMultiply(D,D,Curve.OrderMontgomeryRSquared,Curve.OrderModulus,
                           Curve.OrderNegativeInverse,Curve.Limbs);
 TRNLEC.MontgomeryMultiply(T,R_,Curve.OrderMontgomeryRSquared,Curve.OrderModulus,
                           Curve.OrderNegativeInverse,Curve.Limbs);
 TRNLEC.MontgomeryMultiply(T,T,D,Curve.OrderModulus,Curve.OrderNegativeInverse,Curve.Limbs);
 TRNLEC.MontgomeryMultiply(E,E,Curve.OrderMontgomeryRSquared,Curve.OrderModulus,
                           Curve.OrderNegativeInverse,Curve.Limbs);
 TRNLEC.Add(T,T,E,Curve.OrderModulus,Curve.Limbs);
 TRNLEC.MontgomeryMultiply(S,K,T,Curve.OrderModulus,Curve.OrderNegativeInverse,Curve.Limbs);
 TRNLEC.Zero(One);
 One[0]:=1;
 TRNLEC.MontgomeryMultiply(S,S,One,Curve.OrderModulus,Curve.OrderNegativeInverse,Curve.Limbs);
 if TRNLEC.IsZeroMask(S)<>0 then begin
  exit;
 end;

 TRNLEC.ToBigEndian(aR,R_,Curve.Limbs);
 TRNLEC.ToBigEndian(aS_,S,Curve.Limbs);
 result:=true;

end;

class function TRNLTestECDSA.EncodeInteger(out aData;const aValue;
                                           const aValueSize:TRNLSizeInt):TRNLSizeInt;
var Data,Value:PRNLUInt8Array;
    Start,Size:TRNLSizeInt;
begin

 Data:=PRNLUInt8Array(TRNLPointer(@aData));
 Value:=PRNLUInt8Array(TRNLPointer(@aValue));

 // Minimal, which is DER's rule: no leading zero byte unless one is needed
 Start:=0;
 while (Start<(aValueSize-1)) and (Value^[Start]=0) do begin
  inc(Start);
 end;
 Size:=aValueSize-Start;

 Data^[0]:=$02;
 if (Value^[Start] and $80)<>0 then begin
  // And one is needed exactly when the top bit is set, because a DER INTEGER is signed and this
  // one is not meant to be negative
  Data^[1]:=TRNLUInt8(Size+1);
  Data^[2]:=0;
  Move(Value^[Start],Data^[3],Size);
  result:=3+Size;
 end else begin
  Data^[1]:=TRNLUInt8(Size);
  Move(Value^[Start],Data^[2],Size);
  result:=2+Size;
 end;

end;

class function TRNLTestECDSA.EncodeSignature(out aData;out aDataSize:TRNLSizeInt;
                                             const aMaximumDataSize:TRNLSizeInt;
                                             const aR,aS_):boolean;
var Data:PRNLUInt8Array;
    Size:TRNLSizeInt;
begin

 result:=false;
 aDataSize:=0;

 if aMaximumDataSize<MaximumSignatureSize then begin
  exit;
 end;

 Data:=PRNLUInt8Array(TRNLPointer(@aData));
 Size:=EncodeInteger(Data^[2],aR,ElementSize);
 inc(Size,EncodeInteger(Data^[2+Size],aS_,ElementSize));

 // Only the short form of the length, which is all two P-256 integers can ever need
 Data^[0]:=$30;
 Data^[1]:=TRNLUInt8(Size);
 aDataSize:=2+Size;
 result:=true;

end;

constructor TRNLTestDTLSServer.Create(const aBehaviour:TRNLTestDTLSServerBehaviour;
                                      const aEchoExtendedMasterSecret:boolean);
var Index:TRNLSizeInt;
begin

 inherited Create;

 fBehaviour:=aBehaviour;
 fEchoExtendedMasterSecret:=aEchoExtendedMasterSecret;

 fRandomGenerator:=TRNLRandomGenerator.Create;
 fRandomGenerator.GetRandomBytes(fServerRandom,SizeOf(fServerRandom));

 // A cookie which does not depend on anything, because nothing here is under load and the point of
 // the exchange is that the client sends back what it was given
 for Index:=0 to CookieSize-1 do begin
  fCookie[Index]:=TRNLUInt8($a0+Index);
 end;

 TRNLP256.GenerateKeyPair(fRandomGenerator,fPrivateKey,fPublicKey);

 FillChar(fClientRandom,SizeOf(fClientRandom),#0);
 fTranscript.Initialize;
 fKeySchedule.Clear;
 fClientKeys.Clear;
 fServerKeys.Clear;
 fUseExtendedMasterSecret:=false;

 fSendEpoch:=0;
 fSendSequenceNumbers[0]:=0;
 fSendSequenceNumbers[1]:=0;
 fReceiveEpoch:=0;
 fReplayWindow.Initialize;
 fNextSendMessageSequence:=0;

 fSentHelloVerifyRequest:=false;
 fBuiltServerFlight:=false;
 fBuiltServerFinishedFlight:=false;
 fSeenClientKeyExchange:=false;
 fSeenClientFinished:=false;
 fLostTheFirstFlight:=false;
 fLostTheLastFlight:=false;
 fFragmentThisFlight:=false;

 fFlightSize:=0;
 fCountEntries:=0;
 fPacking.Size:=0;
 fOutgoingHead:=0;
 fCountOutgoing:=0;

 fCountClientHellos:=0;
 fCountFlightsSent:=0;
 fCountAlertsReceived:=0;
 fLastAlertDescription:=0;
 fClientFinishedVerified:=false;
 fCountApplicationDataRecords:=0;
 fLastApplicationData.Size:=0;
 fIncomingHead:=0;
 fCountIncoming:=0;

end;

destructor TRNLTestDTLSServer.Destroy;
begin
 fKeySchedule.Clear;
 fClientKeys.Clear;
 fServerKeys.Clear;
 FillChar(fPrivateKey,SizeOf(fPrivateKey),#0);
 FreeAndNil(fRandomGenerator);
 inherited Destroy;
end;

procedure TRNLTestDTLSServer.QueuePacking;
var Index:TRNLSizeInt;
begin
 if (fPacking.Size>0) and (fCountOutgoing<MaximumQueuedDatagrams) then begin
  Index:=(fOutgoingHead+fCountOutgoing) mod MaximumQueuedDatagrams;
  Move(fPacking.Data[0],fOutgoing[Index].Data[0],fPacking.Size);
  fOutgoing[Index].Size:=fPacking.Size;
  inc(fCountOutgoing);
 end;
 fPacking.Size:=0;
end;

procedure TRNLTestDTLSServer.EmitRecord(const aContentType:TRNLUInt8;const aEpoch:TRNLUInt16;
                                        const aContent;const aContentSize:TRNLSizeInt);
var RecordSize:TRNLSizeInt;
    Written:TRNLSizeUInt;
    Ok:boolean;
begin

 RecordSize:=TRNLDTLS12Record.HeaderSize+aContentSize;
 if aEpoch<>0 then begin
  inc(RecordSize,TRNLDTLS12Record.TagSize);
 end;
 if (fPacking.Size+RecordSize)>MaximumDatagramSize then begin
  QueuePacking;
 end;

 if aEpoch=0 then begin
  Ok:=TRNLDTLS12Record.WritePlain(fPacking.Data[fPacking.Size],Written,
                                  TRNLSizeUInt(MaximumDatagramSize-fPacking.Size),
                                  0,fSendSequenceNumbers[0],aContentType,aContent,aContentSize);
  if Ok then begin
   inc(fSendSequenceNumbers[0]);
  end;
 end else begin
  Ok:=TRNLDTLS12Record.Protect(fPacking.Data[fPacking.Size],Written,
                               TRNLSizeUInt(MaximumDatagramSize-fPacking.Size),
                               fServerKeys,1,fSendSequenceNumbers[1],
                               aContentType,aContent,aContentSize);
  if Ok then begin
   inc(fSendSequenceNumbers[1]);
  end;
 end;
 if Ok then begin
  inc(fPacking.Size,TRNLSizeInt(Written));
 end;

end;

procedure TRNLTestDTLSServer.EmitEntry(const aIndex,aChunkSize:TRNLSizeInt;
                                       const aReversed:boolean);
var Fragment:array[0..(TRNLDTLS12Handshake.HeaderSize+MaximumDatagramSize)-1] of TRNLUInt8;
    Offset,Length_,Count,Step,Piece:TRNLSizeInt;
begin

 if fEntries[aIndex].ContentType<>TRNLDTLS12Record.CONTENT_TYPE_HANDSHAKE then begin
  // A ChangeCipherSpec is not a handshake message and has nothing to fragment
  EmitRecord(fEntries[aIndex].ContentType,fEntries[aIndex].Epoch,
             fFlight[fEntries[aIndex].Offset],fEntries[aIndex].Size);
  exit;
 end;

 Length_:=fEntries[aIndex].Size;
 if aChunkSize>=Length_ then begin
  Count:=1;
 end else begin
  Count:=(Length_+(aChunkSize-1)) div aChunkSize;
 end;
 if Count<1 then begin
  Count:=1;
 end;

 for Step:=0 to Count-1 do begin
  if aReversed then begin
   Offset:=((Count-1)-Step)*aChunkSize;
  end else begin
   Offset:=Step*aChunkSize;
  end;
  Piece:=Length_-Offset;
  if Piece>aChunkSize then begin
   Piece:=aChunkSize;
  end;
  if Piece<0 then begin
   Piece:=0;
  end;
  TRNLDTLS12Handshake.WriteHeader(Fragment[0],fEntries[aIndex].MessageType,Length_,
                                  fEntries[aIndex].MessageSequence,Offset,Piece);
  if Piece>0 then begin
   Move(fFlight[fEntries[aIndex].Offset+Offset],
        Fragment[TRNLDTLS12Handshake.HeaderSize],Piece);
  end;
  EmitRecord(TRNLDTLS12Record.CONTENT_TYPE_HANDSHAKE,fEntries[aIndex].Epoch,
             Fragment[0],TRNLDTLS12Handshake.HeaderSize+Piece);
 end;

end;

procedure TRNLTestDTLSServer.EmitFlight;
var Index:TRNLSizeInt;
begin

 if fBehaviour=RNL_TEST_DTLS_SERVER_SILENT then begin
  exit;
 end;

 if fFragmentThisFlight and (fBehaviour=RNL_TEST_DTLS_SERVER_REVERSED_FRAGMENTS) then begin
  for Index:=fCountEntries-1 downto 0 do begin
   EmitEntry(Index,SecondFragmentSize,true);
  end;
 end else if fFragmentThisFlight and (fBehaviour=RNL_TEST_DTLS_SERVER_OVERLAPPING_FRAGMENTS) then begin
  for Index:=0 to fCountEntries-1 do begin
   EmitEntry(Index,FirstFragmentSize,false);
   EmitEntry(Index,SecondFragmentSize,false);
  end;
 end else begin
  for Index:=0 to fCountEntries-1 do begin
   EmitEntry(Index,MaximumDatagramSize,false);
  end;
 end;

 QueuePacking;
 inc(fCountFlightsSent);

end;

procedure TRNLTestDTLSServer.BeginFlight;
begin
 fFlightSize:=0;
 fCountEntries:=0;
end;

function TRNLTestDTLSServer.AppendMessage(const aMessageType:TRNLUInt8;
                                          const aBody;const aBodySize:TRNLSizeInt;
                                          const aEpoch:TRNLUInt16;
                                          const aInTranscript:boolean):boolean;
begin

 result:=false;
 if (fCountEntries>=MaximumFlightEntries) or ((fFlightSize+aBodySize)>MaximumFlightSize) then begin
  exit;
 end;

 if aBodySize>0 then begin
  Move(aBody,fFlight[fFlightSize],aBodySize);
 end;
 if aInTranscript then begin
  fTranscript.AddMessage(aMessageType,fNextSendMessageSequence,aBody,aBodySize);
 end;

 fEntries[fCountEntries].MessageType:=aMessageType;
 fEntries[fCountEntries].MessageSequence:=fNextSendMessageSequence;
 fEntries[fCountEntries].ContentType:=TRNLDTLS12Record.CONTENT_TYPE_HANDSHAKE;
 fEntries[fCountEntries].Epoch:=aEpoch;
 fEntries[fCountEntries].Offset:=fFlightSize;
 fEntries[fCountEntries].Size:=aBodySize;
 inc(fCountEntries);
 inc(fFlightSize,aBodySize);
 inc(fNextSendMessageSequence);

 result:=true;

end;

function TRNLTestDTLSServer.AppendChangeCipherSpec:boolean;
begin
 result:=false;
 if (fCountEntries>=MaximumFlightEntries) or ((fFlightSize+1)>MaximumFlightSize) then begin
  exit;
 end;
 fFlight[fFlightSize]:=1;
 fEntries[fCountEntries].MessageType:=0;
 fEntries[fCountEntries].MessageSequence:=0;
 fEntries[fCountEntries].ContentType:=TRNLDTLS12Record.CONTENT_TYPE_CHANGE_CIPHER_SPEC;
 fEntries[fCountEntries].Epoch:=0;
 fEntries[fCountEntries].Offset:=fFlightSize;
 fEntries[fCountEntries].Size:=1;
 inc(fCountEntries);
 inc(fFlightSize);
 result:=true;
end;

procedure TRNLTestDTLSServer.BuildHelloVerifyRequest;
var Body:array[0..(2+1+CookieSize)-1] of TRNLUInt8;
begin
 // DTLS 1.0 in the version field whatever is about to be spoken, which is what RFC 6347 section
 // 4.2.1 asks for and what makes the field useless to check
 Body[0]:=254;
 Body[1]:=255;
 Body[2]:=CookieSize;
 Move(fCookie[0],Body[3],CookieSize);
 BeginFlight;
 fFragmentThisFlight:=false;
 // Outside the transcript, together with the ClientHello which provoked it
 AppendMessage(TRNLDTLS12Handshake.TYPE_HELLO_VERIFY_REQUEST,Body[0],SizeOf(Body),0,false);
 EmitFlight;
end;

function TRNLTestDTLSServer.BuildServerFlight:boolean;
var Body:array[0..1023] of TRNLUInt8;
    Chain:array[0..2047] of TRNLUInt8;
    Signed:array[0..255] of TRNLUInt8;
    Signature:array[0..TRNLTestECDSA.MaximumSignatureSize-1] of TRNLUInt8;
    R_,S:array[0..TRNLTestECDSA.ElementSize-1] of TRNLUInt8;
    K:array[0..TRNLTestECDSA.ElementSize-1] of TRNLUInt8;
    Digest:TRNLSHA256Hash;
    Context:TRNLSHA256Context;
    Size,ParametersSize,SignatureSize,LeafSize,ChainSize:TRNLSizeInt;
    Leaf:PRNLUInt8Array;
    NamedCurve:TRNLUInt16;
begin

 result:=false;

 BeginFlight;
 fFragmentThisFlight:=true;

 // ServerHello
 Body[0]:=TRNLDTLS12Record.VersionMajor;
 Body[1]:=TRNLDTLS12Record.VersionMinor;
 Move(fServerRandom[0],Body[2],SizeOf(fServerRandom));
 Size:=2+SizeOf(fServerRandom);
 Body[Size]:=0;
 inc(Size);
 if fBehaviour=RNL_TEST_DTLS_SERVER_UNOFFERED_CIPHER_SUITE then begin
  // TLS_RSA_WITH_AES_128_CBC_SHA, which this client neither offers nor could do
  Body[Size]:=$00;
  Body[Size+1]:=$2f;
 end else begin
  Body[Size]:=$cc;
  Body[Size+1]:=$a9;
 end;
 inc(Size,2);
 Body[Size]:=0;
 inc(Size);
 if fUseExtendedMasterSecret then begin
  Body[Size]:=0;
  Body[Size+1]:=4;
  Body[Size+2]:=0;
  Body[Size+3]:=TRNLUInt8(TRNLDTLS12ClientHello.EXTENSION_EXTENDED_MASTER_SECRET);
  Body[Size+4]:=0;
  Body[Size+5]:=0;
  inc(Size,6);
 end else begin
  Body[Size]:=0;
  Body[Size+1]:=0;
  inc(Size,2);
 end;
 if not AppendMessage(TRNLDTLS12Handshake.TYPE_SERVER_HELLO,Body[0],Size,0,true) then begin
  exit;
 end;

 // Certificate, leaf first and the intermediate above it. The root is what the client is given as
 // its anchor and is deliberately not sent, which is what a real chain looks like.
 if fBehaviour=RNL_TEST_DTLS_SERVER_UNTRUSTED_CERTIFICATE then begin
  Leaf:=PRNLUInt8Array(TRNLPointer(@TRNLTestCertificates.LeafSignedByAStranger[0]));
  LeafSize:=SizeOf(TRNLTestCertificates.LeafSignedByAStranger);
 end else if fBehaviour=RNL_TEST_DTLS_SERVER_EXPIRED_CERTIFICATE then begin
  Leaf:=PRNLUInt8Array(TRNLPointer(@TRNLTestCertificates.LeafExpired[0]));
  LeafSize:=SizeOf(TRNLTestCertificates.LeafExpired);
 end else begin
  Leaf:=PRNLUInt8Array(TRNLPointer(@TRNLTestCertificates.Leaf[0]));
  LeafSize:=SizeOf(TRNLTestCertificates.Leaf);
 end;
 ChainSize:=3;
 Chain[ChainSize]:=0;
 Chain[ChainSize+1]:=TRNLUInt8((LeafSize shr 8) and $ff);
 Chain[ChainSize+2]:=TRNLUInt8(LeafSize and $ff);
 Move(Leaf^[0],Chain[ChainSize+3],LeafSize);
 inc(ChainSize,3+LeafSize);
 Size:=SizeOf(TRNLTestCertificates.Intermediate);
 Chain[ChainSize]:=0;
 Chain[ChainSize+1]:=TRNLUInt8((Size shr 8) and $ff);
 Chain[ChainSize+2]:=TRNLUInt8(Size and $ff);
 Move(TRNLTestCertificates.Intermediate[0],Chain[ChainSize+3],Size);
 inc(ChainSize,3+Size);
 Size:=ChainSize-3;
 Chain[0]:=0;
 Chain[1]:=TRNLUInt8((Size shr 8) and $ff);
 Chain[2]:=TRNLUInt8(Size and $ff);
 if not AppendMessage(TRNLDTLS12Handshake.TYPE_CERTIFICATE,Chain[0],ChainSize,0,true) then begin
  exit;
 end;

 // ServerKeyExchange
 if fBehaviour=RNL_TEST_DTLS_SERVER_UNOFFERED_CURVE then begin
  // secp521r1, which is a real curve and one this client does not carry
  NamedCurve:=25;
 end else begin
  NamedCurve:=TRNLDTLS12ClientHello.NAMED_CURVE_SECP256R1;
 end;
 Body[0]:=3;
 Body[1]:=TRNLUInt8((NamedCurve shr 8) and $ff);
 Body[2]:=TRNLUInt8(NamedCurve and $ff);
 Body[3]:=TRNLP256.PointSize;
 Move(fPublicKey[0],Body[4],TRNLP256.PointSize);
 ParametersSize:=4+TRNLP256.PointSize;

 Move(fClientRandom[0],Signed[0],SizeOf(fClientRandom));
 Move(fServerRandom[0],Signed[SizeOf(fClientRandom)],SizeOf(fServerRandom));
 Size:=SizeOf(fClientRandom)+SizeOf(fServerRandom);
 Move(Body[0],Signed[Size],ParametersSize);
 inc(Size,ParametersSize);
 if fBehaviour=RNL_TEST_DTLS_SERVER_BAD_KEY_EXCHANGE_SIGNATURE then begin
  // Signed over parameters other than the ones which go out. The signature is a perfectly good one
  // over something else, which is exactly the shape of the attack the check is there for.
  Signed[Size-1]:=Signed[Size-1] xor 1;
 end;
 Context.Initialize;
 Context.Update(Signed[0],Size);
 Context.Finalize(Digest);

 repeat
  fRandomGenerator.GetRandomBytes(K,SizeOf(K));
 until TRNLTestECDSA.Sign(R_,S,RNL_TEST_LEAF_PRIVATE_KEY,K,Digest,SizeOf(Digest));
 if not TRNLTestECDSA.EncodeSignature(Signature,SignatureSize,SizeOf(Signature),R_,S) then begin
  exit;
 end;

 Size:=ParametersSize;
 Body[Size]:=4;
 Body[Size+1]:=3;
 Body[Size+2]:=TRNLUInt8((SignatureSize shr 8) and $ff);
 Body[Size+3]:=TRNLUInt8(SignatureSize and $ff);
 Move(Signature[0],Body[Size+4],SignatureSize);
 inc(Size,4+SignatureSize);
 if not AppendMessage(TRNLDTLS12Handshake.TYPE_SERVER_KEY_EXCHANGE,Body[0],Size,0,true) then begin
  exit;
 end;

 if not AppendMessage(TRNLDTLS12Handshake.TYPE_SERVER_HELLO_DONE,Body[0],0,0,true) then begin
  exit;
 end;

 result:=true;

end;

function TRNLTestDTLSServer.BuildServerFinishedFlight:boolean;
var VerifyData:array[0..TRNLDTLS12KeySchedule.VerifyDataSize-1] of TRNLUInt8;
    TranscriptHash:TRNLSHA256Hash;
begin

 result:=true;

 // A repeated flight is the one already built, sent again. Building a second one would hash the
 // client's Finished into the transcript twice over and produce verify data for a handshake which
 // never happened.
 if fBuiltServerFinishedFlight then begin
  EmitFlight;
  exit;
 end;

 result:=false;

 fTranscript.Snapshot(TranscriptHash);
 if not fKeySchedule.DeriveVerifyData(VerifyData,false,TranscriptHash,SizeOf(TranscriptHash)) then begin
  exit;
 end;
 if fBehaviour=RNL_TEST_DTLS_SERVER_WRONG_VERIFY_DATA then begin
  VerifyData[0]:=VerifyData[0] xor 1;
 end;

 BeginFlight;
 fFragmentThisFlight:=false;

 if fBehaviour=RNL_TEST_DTLS_SERVER_FINISHED_WITHOUT_CHANGE_CIPHER_SPEC then begin
  // In the clear and with no key change in front of it, which is a server proposing that the whole
  // exchange be taken on trust
  if not AppendMessage(TRNLDTLS12Handshake.TYPE_FINISHED,VerifyData[0],SizeOf(VerifyData),
                       0,true) then begin
   exit;
  end;
 end else begin
  if not AppendChangeCipherSpec then begin
   exit;
  end;
  fSendEpoch:=1;
  if not AppendMessage(TRNLDTLS12Handshake.TYPE_FINISHED,VerifyData[0],SizeOf(VerifyData),
                       1,true) then begin
   exit;
  end;
 end;

 fBuiltServerFinishedFlight:=true;
 result:=true;

 if (fBehaviour=RNL_TEST_DTLS_SERVER_LOSES_ITS_LAST_FLIGHT) and not fLostTheLastFlight then begin
  fLostTheLastFlight:=true;
  exit;
 end;

 EmitFlight;

end;

procedure TRNLTestDTLSServer.HandleClientHello(const aBody;const aBodySize:TRNLSizeInt);
var Reader,Extensions:TRNLTLSReader;
    Data:PRNLUInt8Array;
    Size:TRNLSizeInt;
    Major,Minor:TRNLUInt8;
    ExtensionType:TRNLUInt16;
    HasCookie:boolean;
begin

 inc(fCountClientHellos);

 Reader.Initialize(aBody,aBodySize);
 if not (Reader.ReadUInt8(Major) and Reader.ReadUInt8(Minor)) then begin
  exit;
 end;
 if not Reader.ReadBytes(Data,TRNLDTLS12ClientHello.RandomSize) then begin
  exit;
 end;
 Move(Data^[0],fClientRandom[0],TRNLDTLS12ClientHello.RandomSize);
 if not Reader.ReadVector8(Data,Size) then begin
  exit;
 end;
 if not Reader.ReadVector8(Data,Size) then begin
  exit;
 end;
 HasCookie:=Size>0;
 if not Reader.ReadVector16(Data,Size) then begin
  exit;
 end;
 if not Reader.ReadVector8(Data,Size) then begin
  exit;
 end;
 if not Reader.AtEnd then begin
  if not Reader.ReadVector16(Data,Size) then begin
   exit;
  end;
  Extensions.Initialize(Data^[0],Size);
  while not Extensions.AtEnd do begin
   if not (Extensions.ReadUInt16(ExtensionType) and Extensions.ReadVector16(Data,Size)) then begin
    break;
   end;
   if (ExtensionType=TRNLDTLS12ClientHello.EXTENSION_EXTENDED_MASTER_SECRET) and
      fEchoExtendedMasterSecret then begin
    fUseExtendedMasterSecret:=true;
   end;
  end;
 end;

 if (not HasCookie) and (fBehaviour<>RNL_TEST_DTLS_SERVER_WITHOUT_COOKIE_EXCHANGE) then begin
  BuildHelloVerifyRequest;
  fSentHelloVerifyRequest:=true;
  exit;
 end;

 if fSentHelloVerifyRequest and
    (fBehaviour=RNL_TEST_DTLS_SERVER_SECOND_HELLO_VERIFY_REQUEST) then begin
  BuildHelloVerifyRequest;
  exit;
 end;

 if fBehaviour=RNL_TEST_DTLS_SERVER_FATAL_ALERT then begin
  // handshake_failure, which is what a server says when nothing it can do overlaps with what was
  // offered. Not a flight and not a handshake message: an alert is a content type of its own.
  BeginFlight;
  fFlight[0]:=2;
  fFlight[1]:=40;
  EmitRecord(TRNLDTLS12Record.CONTENT_TYPE_ALERT,0,fFlight[0],2);
  QueuePacking;
  inc(fCountFlightsSent);
  exit;
 end;

 if not fBuiltServerFlight then begin
  // The transcript begins here, at the ClientHello which was answered rather than at the one which
  // asked for a cookie. RFC 6347 section 4.2.6.
  fTranscript.Initialize;
  fTranscript.AddMessage(TRNLDTLS12Handshake.TYPE_CLIENT_HELLO,
                         TRNLUInt16(fCountClientHellos-1),aBody,aBodySize);
  if not BuildServerFlight then begin
   exit;
  end;
  fBuiltServerFlight:=true;
 end;

 // A repeated ClientHello gets the flight which was already built, message sequence numbers and
 // all. Building a second one with fresh numbers is what a naive stub does, and the client would
 // wait for the missing ones for ever.
 if (fBehaviour=RNL_TEST_DTLS_SERVER_LOSES_ITS_FIRST_FLIGHT) and not fLostTheFirstFlight then begin
  fLostTheFirstFlight:=true;
  exit;
 end;

 EmitFlight;

end;

procedure TRNLTestDTLSServer.HandleClientKeyExchange(const aBody;const aBodySize:TRNLSizeInt);
var Reader:TRNLTLSReader;
    Data:PRNLUInt8Array;
    Size:TRNLSizeInt;
    PreMasterSecret:array[0..TRNLP256.ElementSize-1] of TRNLUInt8;
    KeyBlock:array[0..TRNLDTLS12TrafficKeys.KeyBlockSize-1] of TRNLUInt8;
    SessionHash:TRNLSHA256Hash;
    Derived:boolean;
begin

 Reader.Initialize(aBody,aBodySize);
 if not Reader.ReadVector8(Data,Size) then begin
  exit;
 end;
 if not TRNLP256.SharedSecret(PreMasterSecret,fPrivateKey,Data^[0],TRNLSizeUInt(Size)) then begin
  exit;
 end;

 fTranscript.Snapshot(SessionHash);
 if fUseExtendedMasterSecret then begin
  Derived:=fKeySchedule.DeriveExtendedMasterSecret(PreMasterSecret,SizeOf(PreMasterSecret),
                                                   SessionHash,SizeOf(SessionHash));
 end else begin
  Derived:=fKeySchedule.DeriveMasterSecret(PreMasterSecret,SizeOf(PreMasterSecret),
                                           fClientRandom,fServerRandom);
 end;
 if not Derived then begin
  exit;
 end;
 if fKeySchedule.DeriveKeyBlock(KeyBlock,SizeOf(KeyBlock),fClientRandom,fServerRandom) then begin
  TRNLDTLS12TrafficKeys.SplitKeyBlock(fClientKeys,fServerKeys,KeyBlock);
 end;

 FillChar(PreMasterSecret,SizeOf(PreMasterSecret),#0);
 FillChar(KeyBlock,SizeOf(KeyBlock),#0);

end;

procedure TRNLTestDTLSServer.HandleClientFinished(const aBody;const aBodySize:TRNLSizeInt);
var Expected:array[0..TRNLDTLS12KeySchedule.VerifyDataSize-1] of TRNLUInt8;
    TranscriptHash:TRNLSHA256Hash;
begin

 if aBodySize<>TRNLDTLS12KeySchedule.VerifyDataSize then begin
  exit;
 end;

 // Over everything up to but not including this message, which is why it is checked before it is
 // put into the transcript
 fTranscript.Snapshot(TranscriptHash);
 if fKeySchedule.DeriveVerifyData(Expected,true,TranscriptHash,SizeOf(TranscriptHash)) then begin
  fClientFinishedVerified:=TRNLMemory.SecureIsEqual(Expected[0],aBody,
                                                    TRNLDTLS12KeySchedule.VerifyDataSize);
 end;

end;

procedure TRNLTestDTLSServer.HandleHandshakeFragments(const aContent;const aContentSize:TRNLSizeInt);
var Content:PRNLUInt8Array;
    Position,FragmentSize:TRNLSizeInt;
    MessageType:TRNLUInt8;
    MessageSequence:TRNLUInt16;
    Length_,FragmentOffset,FragmentLength:TRNLSizeInt;
begin

 Content:=PRNLUInt8Array(TRNLPointer(@aContent));
 Position:=0;

 while Position<aContentSize do begin

  if not TRNLDTLS12Handshake.ReadHeader(Content^[Position],aContentSize-Position,
                                        MessageType,Length_,MessageSequence,
                                        FragmentOffset,FragmentLength) then begin
   break;
  end;
  FragmentSize:=TRNLDTLS12Handshake.HeaderSize+FragmentLength;

  // Whole messages only, and no reassembly at all. TRNLDTLS12Client fragments nothing it sends -
  // every flight of its fits in one datagram with room over - so a stub which took fragments would
  // be code no test could reach.
  if (FragmentOffset=0) and (FragmentLength=Length_) then begin

   if MessageType=TRNLDTLS12Handshake.TYPE_CLIENT_HELLO then begin
    HandleClientHello(Content^[Position+TRNLDTLS12Handshake.HeaderSize],Length_);
   end else if MessageType=TRNLDTLS12Handshake.TYPE_CLIENT_KEY_EXCHANGE then begin
    // Once. A retransmitted flight brings all of these again, and hashing any of them into the
    // transcript twice would leave the two sides computing over different handshakes.
    if not fSeenClientKeyExchange then begin
     fSeenClientKeyExchange:=true;
     fTranscript.AddMessage(MessageType,MessageSequence,
                            Content^[Position+TRNLDTLS12Handshake.HeaderSize],Length_);
     HandleClientKeyExchange(Content^[Position+TRNLDTLS12Handshake.HeaderSize],Length_);
    end;
   end else if MessageType=TRNLDTLS12Handshake.TYPE_CERTIFICATE then begin
    fTranscript.AddMessage(MessageType,MessageSequence,
                           Content^[Position+TRNLDTLS12Handshake.HeaderSize],Length_);
   end else if MessageType=TRNLDTLS12Handshake.TYPE_FINISHED then begin
    if not fSeenClientFinished then begin
     fSeenClientFinished:=true;
     HandleClientFinished(Content^[Position+TRNLDTLS12Handshake.HeaderSize],Length_);
     fTranscript.AddMessage(MessageType,MessageSequence,
                            Content^[Position+TRNLDTLS12Handshake.HeaderSize],Length_);
    end;
    BuildServerFinishedFlight;
   end;

  end;

  inc(Position,FragmentSize);

 end;

end;

procedure TRNLTestDTLSServer.HandleRecord(const aContentType:TRNLUInt8;
                                          const aContent;const aContentSize:TRNLSizeInt);
var Index:TRNLSizeInt;
begin

 if aContentType=TRNLDTLS12Record.CONTENT_TYPE_ALERT then begin
  inc(fCountAlertsReceived);
  if aContentSize>=2 then begin
   fLastAlertDescription:=PRNLUInt8Array(TRNLPointer(@aContent))^[1];
  end;
 end else if aContentType=TRNLDTLS12Record.CONTENT_TYPE_CHANGE_CIPHER_SPEC then begin
  // Only the first one changes anything. A repeated ChangeCipherSpec comes with a retransmitted
  // flight, and starting the replay window over for it would let every record of that flight
  // through a second time - which is the one thing the window exists to stop, and which would make
  // a client that reuses its record numbers on a retransmission look as if it worked.
  if fReceiveEpoch<>1 then begin
   fReceiveEpoch:=1;
   fReplayWindow.Initialize;
  end;
 end else if aContentType=TRNLDTLS12Record.CONTENT_TYPE_HANDSHAKE then begin
  HandleHandshakeFragments(aContent,aContentSize);
 end else if aContentType=TRNLDTLS12Record.CONTENT_TYPE_APPLICATION_DATA then begin
  inc(fCountApplicationDataRecords);
  if (aContentSize>0) and (aContentSize<=MaximumDatagramSize) then begin
   Move(aContent,fLastApplicationData.Data[0],aContentSize);
   fLastApplicationData.Size:=aContentSize;
   if fCountIncoming<length(fIncoming) then begin
    Index:=(fIncomingHead+fCountIncoming) mod length(fIncoming);
    Move(aContent,fIncoming[Index].Data[0],aContentSize);
    fIncoming[Index].Size:=aContentSize;
    inc(fCountIncoming);
   end;
  end;
 end;

end;

procedure TRNLTestDTLSServer.ProcessDatagram(const aData;const aDataSize:TRNLSizeInt);
var Data:PRNLUInt8Array;
    Position,RecordSize,FragmentSize:TRNLSizeInt;
    ContentSize,ConsumedSize:TRNLSizeUInt;
    ContentType:TRNLUInt8;
    SequenceNumber:TRNLUInt64;
    RecordEpoch,PlainEpoch:TRNLUInt16;
begin

 Data:=PRNLUInt8Array(TRNLPointer(@aData));
 Position:=0;

 while (Position+TRNLDTLS12Record.HeaderSize)<=aDataSize do begin

  RecordEpoch:=TRNLMemoryAccess.LoadBigEndianUInt16(Data^[Position+3]);
  FragmentSize:=TRNLMemoryAccess.LoadBigEndianUInt16(Data^[Position+11]);
  RecordSize:=TRNLDTLS12Record.HeaderSize+FragmentSize;
  if (Position+RecordSize)>aDataSize then begin
   break;
  end;

  if RecordEpoch=fReceiveEpoch then begin
   if fReceiveEpoch=0 then begin
    if TRNLDTLS12Record.ReadPlain(fRecordBuffer[0],ContentSize,ContentType,PlainEpoch,
                                  SequenceNumber,ConsumedSize,
                                  TRNLSizeUInt(SizeOf(fRecordBuffer)),
                                  Data^[Position],TRNLSizeUInt(RecordSize)) then begin
     HandleRecord(ContentType,fRecordBuffer[0],TRNLSizeInt(ContentSize));
    end;
   end else begin
    if TRNLDTLS12Record.Unprotect(fRecordBuffer[0],ContentSize,ContentType,
                                  SequenceNumber,ConsumedSize,
                                  TRNLSizeUInt(SizeOf(fRecordBuffer)),
                                  fClientKeys,fReceiveEpoch,fReplayWindow,
                                  Data^[Position],TRNLSizeUInt(RecordSize)) then begin
     HandleRecord(ContentType,fRecordBuffer[0],TRNLSizeInt(ContentSize));
    end;
   end;
  end;

  inc(Position,RecordSize);

 end;

end;

function TRNLTestDTLSServer.PopOutgoingDatagram(out aData;out aDataSize:TRNLSizeInt;
                                                const aMaximumDataSize:TRNLSizeInt):boolean;
begin
 result:=false;
 aDataSize:=0;
 if fCountOutgoing=0 then begin
  exit;
 end;
 if fOutgoing[fOutgoingHead].Size>aMaximumDataSize then begin
  exit;
 end;
 aDataSize:=fOutgoing[fOutgoingHead].Size;
 Move(fOutgoing[fOutgoingHead].Data[0],aData,aDataSize);
 fOutgoingHead:=(fOutgoingHead+1) mod MaximumQueuedDatagrams;
 dec(fCountOutgoing);
 result:=true;
end;

function TRNLTestDTLSServer.TakeApplicationData(out aData;out aSize:TRNLSizeInt;
                                             const aMaximumSize:TRNLSizeInt):boolean;
begin
 aSize:=0;
 result:=false;
 if (fCountIncoming=0) or (fIncoming[fIncomingHead].Size>aMaximumSize) then begin
  exit;
 end;
 aSize:=fIncoming[fIncomingHead].Size;
 Move(fIncoming[fIncomingHead].Data[0],aData,aSize);
 fIncomingHead:=(fIncomingHead+1) mod length(fIncoming);
 dec(fCountIncoming);
 result:=true;
end;

function TRNLTestDTLSServer.LastApplicationDataMatches(const aData;
                                                       const aDataSize:TRNLSizeInt):boolean;
begin
 result:=(fLastApplicationData.Size=aDataSize) and (aDataSize>0) and
         TRNLMemory.SecureIsEqual(fLastApplicationData.Data[0],aData,TRNLSizeUInt(aDataSize));
end;

function TRNLTestDTLSServer.Send(const aData;const aDataSize:TRNLSizeInt):boolean;
begin
 result:=false;
 if fSendEpoch<>1 then begin
  exit;
 end;
 fPacking.Size:=0;
 EmitRecord(TRNLDTLS12Record.CONTENT_TYPE_APPLICATION_DATA,1,aData,aDataSize);
 result:=fPacking.Size>0;
 QueuePacking;
end;

constructor TRNLTestDTLS13Server.Create(const aBehaviour:TRNLTestDTLS13ServerBehaviour);
var Index:TRNLSizeInt;
begin

 inherited Create;

 fBehaviour:=aBehaviour;
 fRandomGenerator:=TRNLRandomGenerator.Create;
 fRandomGenerator.GetRandomBytes(fServerRandom,SizeOf(fServerRandom));

 TRNLX25519.GeneratePublicPrivateKeyPair(fRandomGenerator,fX25519PublicKey,fX25519PrivateKey);
 TRNLP256.GenerateKeyPair(fRandomGenerator,fSecp256r1PrivateKey,fSecp256r1PublicKey);
 fGroup:=TRNLDTLS13ClientHello.GROUP_X25519;

 fTranscript.Initialize;
 fKeySchedule.Initialize(TRNLSHA256.Descriptor);
 fClientHandshakeKeys.Clear;
 fServerHandshakeKeys.Clear;
 fClientApplicationKeys.Clear;
 fServerApplicationKeys.Clear;

 fSendEpoch:=EpochInitial;
 fReceiveEpoch:=EpochInitial;
 for Index:=0 to 3 do begin
  fSendSequenceNumbers[Index]:=0;
  fReplayWindows[Index].Initialize;
 end;
 fNextSendMessageSequence:=0;

 fBuiltFlight:=false;
 fLostAFlight:=false;
 fSeenClientFinished:=false;

 fFlightSize:=0;
 fCountEntries:=0;
 fPacking.Size:=0;
 fOutgoingHead:=0;
 fCountOutgoing:=0;

 fCountClientHellos:=0;
 fCountFlightsSent:=0;
 fCountAlertsReceived:=0;
 fLastAlertDescription:=0;
 fClientFinishedVerified:=false;
 fCountApplicationDataRecords:=0;
 fLastApplicationData.Size:=0;
 fIncomingHead:=0;
 fCountIncoming:=0;

end;

destructor TRNLTestDTLS13Server.Destroy;
begin
 fKeySchedule.Clear;
 fClientHandshakeKeys.Clear;
 fServerHandshakeKeys.Clear;
 fClientApplicationKeys.Clear;
 fServerApplicationKeys.Clear;
 FillChar(fX25519PrivateKey,SizeOf(TRNLKey),#0);
 FillChar(fSecp256r1PrivateKey,SizeOf(fSecp256r1PrivateKey),#0);
 FreeAndNil(fRandomGenerator);
 inherited Destroy;
end;

procedure TRNLTestDTLS13Server.QueuePacking;
var Index:TRNLSizeInt;
begin
 if (fPacking.Size>0) and (fCountOutgoing<MaximumQueuedDatagrams) then begin
  Index:=(fOutgoingHead+fCountOutgoing) mod MaximumQueuedDatagrams;
  Move(fPacking.Data[0],fOutgoing[Index].Data[0],fPacking.Size);
  fOutgoing[Index].Size:=fPacking.Size;
  inc(fCountOutgoing);
 end;
 fPacking.Size:=0;
end;

procedure TRNLTestDTLS13Server.EmitRecord(const aContentType:TRNLUInt8;const aEpoch:TRNLUInt64;
                                          const aContent;const aContentSize:TRNLSizeInt);
var RecordSize:TRNLSizeInt;
    Written:TRNLSizeUInt;
    Ok:boolean;
begin

 if aEpoch=EpochInitial then begin
  RecordSize:=TRNLDTLS12Record.HeaderSize+aContentSize;
 end else begin
  RecordSize:=TRNLDTLSRecord.SentHeaderSize+aContentSize+1+TRNLDTLSRecord.TagSize;
 end;
 if (fPacking.Size+RecordSize)>MaximumDatagramSize then begin
  QueuePacking;
 end;

 if aEpoch=EpochInitial then begin
  Ok:=TRNLDTLS12Record.WritePlain(fPacking.Data[fPacking.Size],Written,
                                  TRNLSizeUInt(MaximumDatagramSize-fPacking.Size),
                                  0,fSendSequenceNumbers[EpochInitial],
                                  aContentType,aContent,aContentSize);
 end else if aEpoch=EpochApplication then begin
  Ok:=TRNLDTLSRecord.Protect(fPacking.Data[fPacking.Size],Written,
                             TRNLSizeUInt(MaximumDatagramSize-fPacking.Size),
                             fServerApplicationKeys,aEpoch,
                             fSendSequenceNumbers[EpochApplication],
                             aContentType,aContent,aContentSize);
 end else begin
  Ok:=TRNLDTLSRecord.Protect(fPacking.Data[fPacking.Size],Written,
                             TRNLSizeUInt(MaximumDatagramSize-fPacking.Size),
                             fServerHandshakeKeys,aEpoch,
                             fSendSequenceNumbers[EpochHandshake],
                             aContentType,aContent,aContentSize);
 end;
 if Ok then begin
  inc(fSendSequenceNumbers[aEpoch]);
  inc(fPacking.Size,TRNLSizeInt(Written));
 end;

end;

procedure TRNLTestDTLS13Server.EmitEntry(const aIndex,aChunkSize:TRNLSizeInt;
                                         const aReversed:boolean);
var Fragment:array[0..(TRNLDTLS12Handshake.HeaderSize+MaximumDatagramSize)-1] of TRNLUInt8;
    Offset,Length_,Count,Step,Piece:TRNLSizeInt;
begin

 Length_:=fEntries[aIndex].Size;
 if aChunkSize>=Length_ then begin
  Count:=1;
 end else begin
  Count:=(Length_+(aChunkSize-1)) div aChunkSize;
 end;
 if Count<1 then begin
  Count:=1;
 end;

 for Step:=0 to Count-1 do begin
  if aReversed then begin
   Offset:=((Count-1)-Step)*aChunkSize;
  end else begin
   Offset:=Step*aChunkSize;
  end;
  Piece:=Length_-Offset;
  if Piece>aChunkSize then begin
   Piece:=aChunkSize;
  end;
  if Piece<0 then begin
   Piece:=0;
  end;
  TRNLDTLS12Handshake.WriteHeader(Fragment[0],fEntries[aIndex].MessageType,Length_,
                                  fEntries[aIndex].MessageSequence,Offset,Piece);
  if Piece>0 then begin
   Move(fFlight[fEntries[aIndex].Offset+Offset],
        Fragment[TRNLDTLS12Handshake.HeaderSize],Piece);
  end;
  EmitRecord(TRNLDTLSRecord.CONTENT_TYPE_HANDSHAKE,fEntries[aIndex].Epoch,
             Fragment[0],TRNLDTLS12Handshake.HeaderSize+Piece);
 end;

end;

procedure TRNLTestDTLS13Server.EmitFlight;
var Index:TRNLSizeInt;
begin

 if fBehaviour=RNL_TEST_DTLS13_SERVER_SILENT then begin
  exit;
 end;

 if fBehaviour=RNL_TEST_DTLS13_SERVER_REVERSED_FRAGMENTS then begin
  // The ServerHello leads, and everything behind it goes backwards. That it has to lead is not a
  // convenience: the keys protecting the rest of the flight are derived from it, so a record of
  // the encrypted part arriving before it cannot be opened by anyone at all. This client drops
  // such a record and waits for the flight again, which is what RFC 9147 section 4.2.1 allows -
  // the alternative is buffering ciphertext against keys which may never arrive, in a buffer
  // whose size the peer decides.
  EmitEntry(0,FragmentSize,false);
  for Index:=fCountEntries-1 downto 1 do begin
   EmitEntry(Index,FragmentSize,true);
  end;
 end else begin
  for Index:=0 to fCountEntries-1 do begin
   EmitEntry(Index,MaximumDatagramSize,false);
  end;
 end;

 QueuePacking;
 inc(fCountFlightsSent);

end;

procedure TRNLTestDTLS13Server.BeginFlight;
begin
 fFlightSize:=0;
 fCountEntries:=0;
end;

function TRNLTestDTLS13Server.AppendMessage(const aMessageType:TRNLUInt8;
                                            const aBody;const aBodySize:TRNLSizeInt;
                                            const aEpoch:TRNLUInt64;
                                            const aInTranscript:boolean):boolean;
begin

 result:=false;
 if (fCountEntries>=MaximumFlightEntries) or ((fFlightSize+aBodySize)>MaximumFlightSize) then begin
  exit;
 end;

 if aBodySize>0 then begin
  Move(aBody,fFlight[fFlightSize],aBodySize);
 end;
 if aInTranscript then begin
  fTranscript.AddMessage(aMessageType,aBody,aBodySize);
 end;

 fEntries[fCountEntries].MessageType:=aMessageType;
 fEntries[fCountEntries].MessageSequence:=fNextSendMessageSequence;
 fEntries[fCountEntries].Epoch:=aEpoch;
 fEntries[fCountEntries].Offset:=fFlightSize;
 fEntries[fCountEntries].Size:=aBodySize;
 inc(fCountEntries);
 inc(fFlightSize,aBodySize);
 inc(fNextSendMessageSequence);

 result:=true;

end;

function TRNLTestDTLS13Server.BuildServerHello(const aClientShare;
                                               const aClientShareSize:TRNLSizeInt):boolean;
var Body:array[0..255] of TRNLUInt8;
    Size,Extensions,Inner:TRNLSizeInt;
    Writer:TRNLTLSWriter;
    Shared:array[0..TRNLP256.ElementSize-1] of TRNLUInt8;
    SharedKey:TRNLKey;
    Hash:TRNLSHA256Hash;
    Group:TRNLUInt16;
begin

 result:=false;

 Writer.Initialize(Body,SizeOf(Body));
 Writer.WriteUInt16(TRNLDTLS13ClientHello.VERSION_DTLS12);
 if fBehaviour=RNL_TEST_DTLS13_SERVER_HELLO_RETRY_REQUEST then begin
  Writer.WriteBytes(TRNLDTLS13ServerHello.HelloRetryRequestRandom,32);
 end else begin
  Writer.WriteBytes(fServerRandom,32);
 end;
 Writer.WriteUInt8(0);
 if fBehaviour=RNL_TEST_DTLS13_SERVER_UNOFFERED_CIPHER_SUITE then begin
  Writer.WriteUInt16($1301);
 end else begin
  Writer.WriteUInt16(TRNLDTLS13ClientHello.CIPHER_SUITE_CHACHA20_POLY1305_SHA256);
 end;
 Writer.WriteUInt8(0);

 Group:=fGroup;
 if fBehaviour=RNL_TEST_DTLS13_SERVER_UNOFFERED_GROUP then begin
  Group:=$0018;
 end;

 Extensions:=Writer.BeginVector16;
 if fBehaviour<>RNL_TEST_DTLS13_SERVER_WITHOUT_SUPPORTED_VERSIONS then begin
  Writer.WriteUInt16(TRNLDTLS13ClientHello.EXTENSION_SUPPORTED_VERSIONS);
  Inner:=Writer.BeginVector16;
  Writer.WriteUInt16(TRNLDTLS13ClientHello.VERSION_DTLS13);
  Writer.EndVector16(Inner);
 end;
 Writer.WriteUInt16(TRNLDTLS13ClientHello.EXTENSION_KEY_SHARE);
 Inner:=Writer.BeginVector16;
 Writer.WriteUInt16(Group);
 if fBehaviour<>RNL_TEST_DTLS13_SERVER_HELLO_RETRY_REQUEST then begin
  Size:=Writer.BeginVector16;
  if fGroup=TRNLDTLS13ClientHello.GROUP_X25519 then begin
   Writer.WriteBytes(fX25519PublicKey,SizeOf(TRNLKey));
  end else begin
   Writer.WriteBytes(fSecp256r1PublicKey,TRNLP256.PointSize);
  end;
  Writer.EndVector16(Size);
 end;
 Writer.EndVector16(Inner);
 Writer.EndVector16(Extensions);

 if not Writer.Valid then begin
  exit;
 end;

 BeginFlight;
 if not AppendMessage(2,Body[0],Writer.Size,EpochInitial,true) then begin
  exit;
 end;

 // A HelloRetryRequest ends the exchange here: this stub sends one and waits to be told off
 if fBehaviour=RNL_TEST_DTLS13_SERVER_HELLO_RETRY_REQUEST then begin
  result:=true;
  exit;
 end;

 if fGroup=TRNLDTLS13ClientHello.GROUP_X25519 then begin
  if not TRNLX25519.GenerateSharedSecretKey(SharedKey,
                                            PRNLKey(TRNLPointer(@aClientShare))^,
                                            fX25519PrivateKey) then begin
   exit;
  end;
  if not fKeySchedule.DeriveHandshakeSecret(SharedKey,TRNLSizeUInt(SizeOf(TRNLKey))) then begin
   exit;
  end;
 end else begin
  if not TRNLP256.SharedSecret(Shared,fSecp256r1PrivateKey,
                               aClientShare,TRNLSizeUInt(aClientShareSize)) then begin
   exit;
  end;
  if not fKeySchedule.DeriveHandshakeSecret(Shared,TRNLSizeUInt(TRNLP256.ElementSize)) then begin
   exit;
  end;
 end;

 fTranscript.Snapshot(Hash);
 result:=fKeySchedule.DeriveHandshakeTrafficSecrets(Hash,SizeOf(Hash)) and
         fClientHandshakeKeys.DeriveFrom(fKeySchedule.ClientHandshakeTrafficSecret,
                                         TRNLSizeUInt(SizeOf(TRNLSHA256Hash))) and
         fServerHandshakeKeys.DeriveFrom(fKeySchedule.ServerHandshakeTrafficSecret,
                                         TRNLSizeUInt(SizeOf(TRNLSHA256Hash)));

end;

function TRNLTestDTLS13Server.BuildRestOfFlight:boolean;
var Body:array[0..2047] of TRNLUInt8;
    Writer:TRNLTLSWriter;
    Inner,Size:TRNLSizeInt;
    LeafSize:TRNLSizeInt;
    Leaf:PRNLUInt8Array;
    Hash:TRNLSHA256Hash;
    SignedContent:array[0..TRNLDTLS13CertificateVerify.MaximumSignedContentSize-1] of TRNLUInt8;
    SignedSize:TRNLSizeInt;
    Digest:TRNLSHA256Hash;
    Context:TRNLSHA256Context;
    R_,S,K:array[0..TRNLTestECDSA.ElementSize-1] of TRNLUInt8;
    Signature:array[0..TRNLTestECDSA.MaximumSignatureSize-1] of TRNLUInt8;
    SignatureSize:TRNLSizeInt;
    VerifyData:TRNLSHA256Hash;
begin

 result:=false;

 // EncryptedExtensions, empty
 Writer.Initialize(Body,SizeOf(Body));
 Inner:=Writer.BeginVector16;
 Writer.EndVector16(Inner);
 if not (Writer.Valid and AppendMessage(8,Body[0],Writer.Size,EpochHandshake,true)) then begin
  exit;
 end;

 // Certificate: an empty request context, then the leaf and the intermediate, each with an empty
 // extension list
 if fBehaviour=RNL_TEST_DTLS13_SERVER_UNTRUSTED_CERTIFICATE then begin
  Leaf:=PRNLUInt8Array(TRNLPointer(@TRNLTestCertificates.LeafSignedByAStranger[0]));
  LeafSize:=SizeOf(TRNLTestCertificates.LeafSignedByAStranger);
 end else begin
  Leaf:=PRNLUInt8Array(TRNLPointer(@TRNLTestCertificates.Leaf[0]));
  LeafSize:=SizeOf(TRNLTestCertificates.Leaf);
 end;
 Writer.Initialize(Body,SizeOf(Body));
 // The request context, empty, and then straight into the list. There is no extension list at
 // this level - those hang off each entry, not off the message.
 Writer.WriteUInt8(0);
 // The certificate list is a uint24 vector, which the writer has no helper for, so it is measured
 // and written by hand
 Size:=(3+LeafSize+2)+(3+SizeOf(TRNLTestCertificates.Intermediate)+2);
 Writer.WriteUInt24(Size);
 Writer.WriteUInt24(LeafSize);
 Writer.WriteBytes(Leaf^[0],LeafSize);
 Writer.WriteUInt16(0);
 Writer.WriteUInt24(SizeOf(TRNLTestCertificates.Intermediate));
 Writer.WriteBytes(TRNLTestCertificates.Intermediate,SizeOf(TRNLTestCertificates.Intermediate));
 Writer.WriteUInt16(0);
 if not (Writer.Valid and AppendMessage(11,Body[0],Writer.Size,EpochHandshake,true)) then begin
  exit;
 end;

 // CertificateVerify over the transcript as it stands, which is everything up to and including
 // the Certificate
 fTranscript.Snapshot(Hash);
 if fBehaviour=RNL_TEST_DTLS13_SERVER_BAD_CERTIFICATE_VERIFY then begin
  Hash[0]:=Hash[0] xor 1;
 end;
 if not TRNLDTLS13CertificateVerify.BuildSignedContent(SignedContent,SignedSize,
                                                       SizeOf(SignedContent),
                                                       TRNLDTLS13CertificateVerify.ServerContext,
                                                       Hash,SizeOf(Hash)) then begin
  exit;
 end;
 Context.Initialize;
 Context.Update(SignedContent[0],SignedSize);
 Context.Finalize(Digest);
 repeat
  fRandomGenerator.GetRandomBytes(K,SizeOf(K));
 until TRNLTestECDSA.Sign(R_,S,RNL_TEST_LEAF_PRIVATE_KEY,K,Digest,SizeOf(Digest));
 if not TRNLTestECDSA.EncodeSignature(Signature,SignatureSize,SizeOf(Signature),R_,S) then begin
  exit;
 end;
 Writer.Initialize(Body,SizeOf(Body));
 Writer.WriteUInt16(TRNLDTLS13ClientHello.SIGNATURE_ECDSA_SECP256R1_SHA256);
 Inner:=Writer.BeginVector16;
 Writer.WriteBytes(Signature[0],SignatureSize);
 Writer.EndVector16(Inner);
 if not (Writer.Valid and AppendMessage(15,Body[0],Writer.Size,EpochHandshake,true)) then begin
  exit;
 end;

 // Finished over the transcript including the CertificateVerify
 fTranscript.Snapshot(Hash);
 if not TRNLDTLS13KeySchedule.ComputeVerifyData(TRNLSHA256.Descriptor,VerifyData,
                                                fKeySchedule.ServerHandshakeTrafficSecret,
                                                TRNLSizeUInt(SizeOf(TRNLSHA256Hash)),
                                                Hash,TRNLSizeUInt(SizeOf(Hash))) then begin
  exit;
 end;
 if fBehaviour=RNL_TEST_DTLS13_SERVER_WRONG_VERIFY_DATA then begin
  VerifyData[0]:=VerifyData[0] xor 1;
 end;
 if not AppendMessage(20,VerifyData,SizeOf(VerifyData),EpochHandshake,true) then begin
  exit;
 end;

 // And the application keys, which the client will derive at the same point
 fTranscript.Snapshot(Hash);
 result:=fKeySchedule.DeriveMasterSecret and
         fKeySchedule.DeriveApplicationTrafficSecrets(Hash,SizeOf(Hash)) and
         fClientApplicationKeys.DeriveFrom(fKeySchedule.ClientApplicationTrafficSecret,
                                           TRNLSizeUInt(SizeOf(TRNLSHA256Hash))) and
         fServerApplicationKeys.DeriveFrom(fKeySchedule.ServerApplicationTrafficSecret,
                                           TRNLSizeUInt(SizeOf(TRNLSHA256Hash)));

end;

procedure TRNLTestDTLS13Server.HandleClientHello(const aBody;const aBodySize:TRNLSizeInt);
var Reader,Extensions,Shares,Share:TRNLTLSReader;
    Data:PRNLUInt8Array;
    Size:TRNLSizeInt;
    ExtensionType,Group:TRNLUInt16;
    Version:TRNLUInt16;
    ChosenShare:array[0..TRNLP256.PointSize-1] of TRNLUInt8;
    ChosenShareSize:TRNLSizeInt;
    WantedGroup:TRNLUInt16;
begin

 inc(fCountClientHellos);

 // A repeated ClientHello gets the flight which was already built, sequence numbers and all
 if fBuiltFlight then begin
  EmitFlight;
  exit;
 end;

 if fBehaviour=RNL_TEST_DTLS13_SERVER_SECP256R1 then begin
  WantedGroup:=TRNLDTLS13ClientHello.GROUP_SECP256R1;
 end else begin
  WantedGroup:=TRNLDTLS13ClientHello.GROUP_X25519;
 end;
 ChosenShareSize:=0;

 Reader.Initialize(aBody,aBodySize);
 if not Reader.ReadUInt16(Version) then begin
  exit;
 end;
 if not Reader.ReadBytes(Data,TRNLDTLS13ClientHello.RandomSize) then begin
  exit;
 end;
 // legacy_session_id and legacy_cookie, both of which DTLS 1.3 requires to be empty here
 if not (Reader.ReadVector8(Data,Size) and Reader.ReadVector8(Data,Size)) then begin
  exit;
 end;
 if not (Reader.ReadVector16(Data,Size) and Reader.ReadVector8(Data,Size)) then begin
  exit;
 end;
 if not Reader.ReadVector16(Data,Size) then begin
  exit;
 end;
 Extensions.Initialize(Data^[0],Size);

 while not Extensions.AtEnd do begin
  if not (Extensions.ReadUInt16(ExtensionType) and Extensions.ReadVector16(Data,Size)) then begin
   exit;
  end;
  if ExtensionType=TRNLDTLS13ClientHello.EXTENSION_KEY_SHARE then begin
   Shares.Initialize(Data^[0],Size);
   if not Shares.ReadVector16(Data,Size) then begin
    exit;
   end;
   Share.Initialize(Data^[0],Size);
   while not Share.AtEnd do begin
    if not (Share.ReadUInt16(Group) and Share.ReadVector16(Data,Size)) then begin
     exit;
    end;
    if (Group=WantedGroup) and (Size<=TRNLP256.PointSize) then begin
     Move(Data^[0],ChosenShare[0],Size);
     ChosenShareSize:=Size;
    end;
   end;
  end;
 end;

 if ChosenShareSize=0 then begin
  exit;
 end;
 fGroup:=WantedGroup;

 // The transcript starts at the ClientHello, and there is no cookie exchange to leave out of it
 fTranscript.Initialize;
 fTranscript.AddMessage(1,aBody,aBodySize);

 if fBehaviour=RNL_TEST_DTLS13_SERVER_FATAL_ALERT then begin
  BeginFlight;
  fFlight[0]:=2;
  fFlight[1]:=40;
  EmitRecord(TRNLDTLSRecord.CONTENT_TYPE_ALERT,EpochInitial,fFlight[0],2);
  QueuePacking;
  inc(fCountFlightsSent);
  exit;
 end;

 if not BuildServerHello(ChosenShare[0],ChosenShareSize) then begin
  exit;
 end;

 if fBehaviour<>RNL_TEST_DTLS13_SERVER_HELLO_RETRY_REQUEST then begin
  if not BuildRestOfFlight then begin
   exit;
  end;
  if fBehaviour=RNL_TEST_DTLS13_SERVER_MESSAGES_OUT_OF_ORDER then begin
   // Certificate before EncryptedExtensions, which is the one ordering a client must refuse even
   // though every message in it is perfectly well formed
   fEntries[1].MessageSequence:=fEntries[2].MessageSequence;
   fEntries[2].MessageSequence:=fEntries[1].MessageSequence-1;
  end;
 end;

 fBuiltFlight:=true;

 if (fBehaviour=RNL_TEST_DTLS13_SERVER_LOSES_ITS_FLIGHT) and not fLostAFlight then begin
  fLostAFlight:=true;
  exit;
 end;

 EmitFlight;

end;

procedure TRNLTestDTLS13Server.HandleClientFinished(const aBody;const aBodySize:TRNLSizeInt);
var Expected:TRNLSHA256Hash;
    Hash:TRNLSHA256Hash;
begin
 if aBodySize<>SizeOf(TRNLSHA256Hash) then begin
  exit;
 end;
 // Over the transcript up to and including the server's own Finished, which is where it stands
 fTranscript.Snapshot(Hash);
 if TRNLDTLS13KeySchedule.ComputeVerifyData(TRNLSHA256.Descriptor,Expected,
                                            fKeySchedule.ClientHandshakeTrafficSecret,
                                            TRNLSizeUInt(SizeOf(TRNLSHA256Hash)),
                                            Hash,TRNLSizeUInt(SizeOf(Hash))) then begin
  fClientFinishedVerified:=TRNLMemory.SecureIsEqual(Expected,aBody,SizeOf(TRNLSHA256Hash));
 end;
 fSendEpoch:=EpochApplication;
 fReceiveEpoch:=EpochApplication;
 fReplayWindows[EpochApplication].Initialize;
end;

procedure TRNLTestDTLS13Server.HandleHandshakeFragments(const aContent;
                                                        const aContentSize:TRNLSizeInt);
var Content:PRNLUInt8Array;
    Position,FragmentSize:TRNLSizeInt;
    MessageType:TRNLUInt8;
    MessageSequence:TRNLUInt16;
    Length_,FragmentOffset,FragmentLength:TRNLSizeInt;
begin

 Content:=PRNLUInt8Array(TRNLPointer(@aContent));
 Position:=0;

 while Position<aContentSize do begin
  if not TRNLDTLS12Handshake.ReadHeader(Content^[Position],aContentSize-Position,
                                        MessageType,Length_,MessageSequence,
                                        FragmentOffset,FragmentLength) then begin
   break;
  end;
  FragmentSize:=TRNLDTLS12Handshake.HeaderSize+FragmentLength;
  // Whole messages only: TRNLDTLS13Client fragments nothing it sends
  if (FragmentOffset=0) and (FragmentLength=Length_) then begin
   if MessageType=1 then begin
    HandleClientHello(Content^[Position+TRNLDTLS12Handshake.HeaderSize],Length_);
   end else if MessageType=20 then begin
    if not fSeenClientFinished then begin
     fSeenClientFinished:=true;
     HandleClientFinished(Content^[Position+TRNLDTLS12Handshake.HeaderSize],Length_);
    end;
   end;
  end;
  inc(Position,FragmentSize);
 end;

end;

procedure TRNLTestDTLS13Server.HandleRecord(const aContentType:TRNLUInt8;
                                            const aContent;const aContentSize:TRNLSizeInt);
var Index:TRNLSizeInt;
begin
 if aContentType=TRNLDTLSRecord.CONTENT_TYPE_ALERT then begin
  inc(fCountAlertsReceived);
  if aContentSize>=2 then begin
   fLastAlertDescription:=PRNLUInt8Array(TRNLPointer(@aContent))^[1];
  end;
 end else if aContentType=TRNLDTLSRecord.CONTENT_TYPE_HANDSHAKE then begin
  HandleHandshakeFragments(aContent,aContentSize);
 end else if aContentType=TRNLDTLSRecord.CONTENT_TYPE_APPLICATION_DATA then begin
  inc(fCountApplicationDataRecords);
  if (aContentSize>0) and (aContentSize<=MaximumDatagramSize) then begin
   Move(aContent,fLastApplicationData.Data[0],aContentSize);
   fLastApplicationData.Size:=aContentSize;
   if fCountIncoming<length(fIncoming) then begin
    Index:=(fIncomingHead+fCountIncoming) mod length(fIncoming);
    Move(aContent,fIncoming[Index].Data[0],aContentSize);
    fIncoming[Index].Size:=aContentSize;
    inc(fCountIncoming);
   end;
  end;
 end;
 // An ACK is read and dropped: this stub never repeats a subset of a flight
end;

procedure TRNLTestDTLS13Server.ProcessDatagram(const aData;const aDataSize:TRNLSizeInt);
var Data:PRNLUInt8Array;
    Position,RecordSize,FragmentSize:TRNLSizeInt;
    ContentSize,ConsumedSize:TRNLSizeUInt;
    ContentType:TRNLUInt8;
    SequenceNumber:TRNLUInt64;
    PlainEpoch:TRNLUInt16;
begin

 Data:=PRNLUInt8Array(TRNLPointer(@aData));
 Position:=0;

 while Position<aDataSize do begin

  if (Data^[Position] and TRNLDTLSRecord.HEADER_FIXED_MASK)=TRNLDTLSRecord.HEADER_FIXED_BITS then begin

   if TRNLDTLSRecord.Unprotect(fRecordBuffer[0],ContentSize,ContentType,SequenceNumber,
                               ConsumedSize,TRNLSizeUInt(SizeOf(fRecordBuffer)),
                               fClientHandshakeKeys,EpochHandshake,
                               fReplayWindows[EpochHandshake],
                               Data^[Position],TRNLSizeUInt(aDataSize-Position)) then begin
    HandleRecord(ContentType,fRecordBuffer[0],TRNLSizeInt(ContentSize));
    inc(Position,TRNLSizeInt(ConsumedSize));
   end else if TRNLDTLSRecord.Unprotect(fRecordBuffer[0],ContentSize,ContentType,SequenceNumber,
                                        ConsumedSize,TRNLSizeUInt(SizeOf(fRecordBuffer)),
                                        fClientApplicationKeys,EpochApplication,
                                        fReplayWindows[EpochApplication],
                                        Data^[Position],TRNLSizeUInt(aDataSize-Position)) then begin
    HandleRecord(ContentType,fRecordBuffer[0],TRNLSizeInt(ContentSize));
    inc(Position,TRNLSizeInt(ConsumedSize));
   end else begin
    break;
   end;

  end else begin

   if (Position+TRNLDTLS12Record.HeaderSize)>aDataSize then begin
    break;
   end;
   FragmentSize:=TRNLMemoryAccess.LoadBigEndianUInt16(Data^[Position+11]);
   RecordSize:=TRNLDTLS12Record.HeaderSize+FragmentSize;
   if (Position+RecordSize)>aDataSize then begin
    break;
   end;
   if TRNLDTLS12Record.ReadPlain(fRecordBuffer[0],ContentSize,ContentType,PlainEpoch,
                                 SequenceNumber,ConsumedSize,
                                 TRNLSizeUInt(SizeOf(fRecordBuffer)),
                                 Data^[Position],TRNLSizeUInt(RecordSize)) then begin
    HandleRecord(ContentType,fRecordBuffer[0],TRNLSizeInt(ContentSize));
   end;
   inc(Position,RecordSize);

  end;

 end;

end;

function TRNLTestDTLS13Server.PopOutgoingDatagram(out aData;out aDataSize:TRNLSizeInt;
                                                  const aMaximumDataSize:TRNLSizeInt):boolean;
begin
 result:=false;
 aDataSize:=0;
 if (fCountOutgoing=0) or (fOutgoing[fOutgoingHead].Size>aMaximumDataSize) then begin
  exit;
 end;
 aDataSize:=fOutgoing[fOutgoingHead].Size;
 Move(fOutgoing[fOutgoingHead].Data[0],aData,aDataSize);
 fOutgoingHead:=(fOutgoingHead+1) mod MaximumQueuedDatagrams;
 dec(fCountOutgoing);
 result:=true;
end;

function TRNLTestDTLS13Server.Send(const aData;const aDataSize:TRNLSizeInt):boolean;
begin
 result:=false;
 if fSendEpoch<>EpochApplication then begin
  exit;
 end;
 fPacking.Size:=0;
 EmitRecord(TRNLDTLSRecord.CONTENT_TYPE_APPLICATION_DATA,EpochApplication,aData,aDataSize);
 result:=fPacking.Size>0;
 QueuePacking;
end;

function TRNLTestDTLS13Server.TakeApplicationData(out aData;out aSize:TRNLSizeInt;
                                             const aMaximumSize:TRNLSizeInt):boolean;
begin
 aSize:=0;
 result:=false;
 if (fCountIncoming=0) or (fIncoming[fIncomingHead].Size>aMaximumSize) then begin
  exit;
 end;
 aSize:=fIncoming[fIncomingHead].Size;
 Move(fIncoming[fIncomingHead].Data[0],aData,aSize);
 fIncomingHead:=(fIncomingHead+1) mod length(fIncoming);
 dec(fCountIncoming);
 result:=true;
end;

function TRNLTestDTLS13Server.LastApplicationDataMatches(const aData;
                                                         const aDataSize:TRNLSizeInt):boolean;
begin
 result:=(fLastApplicationData.Size=aDataSize) and (aDataSize>0) and
         TRNLMemory.SecureIsEqual(fLastApplicationData.Data[0],aData,TRNLSizeUInt(aDataSize));
end;


constructor TRNLTestDTLSRelay.Create(const aInstance:TRNLInstance;
                                     const aNetwork:TRNLNetwork;
                                     const aListenHost:TRNLRawByteString;
                                     const aListenPort:TRNLUInt16;
                                     const aTargetAddress:TRNLAddress;
                                     const aFamily:TRNLAddressFamily;
                                     const aVersion:TRNLTURNDTLSVersion);
var Address:TRNLAddress;
begin

 fInstance:=aInstance;
 fNetwork:=aNetwork;
 fFamily:=aFamily;
 fTargetAddress:=aTargetAddress;
 fVersion:=aVersion;
 fHasClient:=false;
 fCountClientDatagrams:=0;
 fCountForwarded:=0;
 fCountReturned:=0;
 fLock:=TCriticalSection.Create;

 if fVersion=RNL_TURN_DTLS_VERSION_1_3 then begin
  fServer13:=TRNLTestDTLS13Server.Create(RNL_TEST_DTLS13_SERVER_CORRECT);
 end else begin
  fServer12:=TRNLTestDTLSServer.Create(RNL_TEST_DTLS_SERVER_CORRECT,false);
 end;

 FillChar(Address,SizeOf(TRNLAddress),#0);
 fNetwork.AddressSetHost(Address,aListenHost);
 Address.Port:=aListenPort;
 fListenSocket:=fNetwork.SocketCreate(RNL_SOCKET_TYPE_DATAGRAM,fFamily);
 if fListenSocket<>RNL_SOCKET_NULL then begin
  fNetwork.SocketBind(fListenSocket,@Address,fFamily);
 end;

 // A second socket towards the relay, so that what comes back from it can be told apart from what
 // comes from the client by which socket it arrived on
 fForwardSocket:=fNetwork.SocketCreate(RNL_SOCKET_TYPE_DATAGRAM,fFamily);
 if fForwardSocket<>RNL_SOCKET_NULL then begin
  fNetwork.SocketBind(fForwardSocket,nil,fFamily);
 end;

 inherited Create(false);

end;

destructor TRNLTestDTLSRelay.Destroy;
begin
 Terminate;
 WaitFor;
 if fListenSocket<>RNL_SOCKET_NULL then begin
  fNetwork.SocketDestroy(fListenSocket);
 end;
 if fForwardSocket<>RNL_SOCKET_NULL then begin
  fNetwork.SocketDestroy(fForwardSocket);
 end;
 FreeAndNil(fServer12);
 FreeAndNil(fServer13);
 FreeAndNil(fLock);
 inherited Destroy;
end;

function TRNLTestDTLSRelay.GetCountForwarded:TRNLSizeInt;
begin
 fLock.Acquire;
 try
  result:=fCountForwarded;
 finally
  fLock.Release;
 end;
end;

procedure TRNLTestDTLSRelay.Flush;
var Datagram:array[0..2047] of TRNLUInt8;
    DatagramSize:TRNLSizeInt;
begin
 if not fHasClient then begin
  exit;
 end;
 if assigned(fServer12) then begin
  while fServer12.PopOutgoingDatagram(Datagram,DatagramSize,SizeOf(Datagram)) do begin
   fNetwork.Send(fListenSocket,@fClientAddress,Datagram,DatagramSize,fFamily);
  end;
 end else begin
  while fServer13.PopOutgoingDatagram(Datagram,DatagramSize,SizeOf(Datagram)) do begin
   fNetwork.Send(fListenSocket,@fClientAddress,Datagram,DatagramSize,fFamily);
  end;
 end;
end;

procedure TRNLTestDTLSRelay.Execute;
var Sockets:array[0..1] of TRNLSocket;
    WaitConditions:TRNLSocketWaitConditions;
    Datagram:array[0..2047] of TRNLUInt8;
    Plain:array[0..2047] of TRNLUInt8;
    Address:TRNLAddress;
    Size,PlainSize:TRNLSizeInt;
begin

 if (fListenSocket=RNL_SOCKET_NULL) or (fForwardSocket=RNL_SOCKET_NULL) then begin
  exit;
 end;

 Sockets[0]:=fListenSocket;
 Sockets[1]:=fForwardSocket;

 while not Terminated do begin

  WaitConditions:=[RNL_SOCKET_WAIT_CONDITION_IO_RECEIVE];
  if not fNetwork.SocketWait(Sockets,WaitConditions,10,nil) then begin
   continue;
  end;
  if not (RNL_SOCKET_WAIT_CONDITION_IO_RECEIVE in WaitConditions) then begin
   continue;
  end;

  // From the client: a record. What comes out of it goes on to the relay, and what the record
  // layer wants to say back goes out at once.
  Size:=fNetwork.Receive(fListenSocket,@Address,Datagram,SizeOf(Datagram),fFamily);
  if Size>0 then begin
   fLock.Acquire;
   try
    fClientAddress:=Address;
    fHasClient:=true;
    inc(fCountClientDatagrams);
    if assigned(fServer12) then begin
     fServer12.ProcessDatagram(Datagram,Size);
    end else begin
     fServer13.ProcessDatagram(Datagram,Size);
    end;
    Flush;
    while ((assigned(fServer12) and fServer12.TakeApplicationData(Plain,PlainSize,SizeOf(Plain))) or
           (assigned(fServer13) and fServer13.TakeApplicationData(Plain,PlainSize,SizeOf(Plain)))) do begin
     fNetwork.Send(fForwardSocket,@fTargetAddress,Plain,PlainSize,fFamily);
     inc(fCountForwarded);
    end;
   finally
    fLock.Release;
   end;
  end;

  // From the relay: plaintext, which goes back to the client through the record layer
  Size:=fNetwork.Receive(fForwardSocket,@Address,Datagram,SizeOf(Datagram),fFamily);
  if (Size>0) and Address.Equals(fTargetAddress) then begin
   fLock.Acquire;
   try
    if assigned(fServer12) then begin
     fServer12.Send(Datagram,Size);
    end else begin
     fServer13.Send(Datagram,Size);
    end;
    Flush;
    inc(fCountReturned);
   finally
    fLock.Release;
   end;
  end;

 end;

end;

end.
