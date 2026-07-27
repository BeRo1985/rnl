(******************************************************************************
 *                         RNL TEST TURN SERVER                               *
 ******************************************************************************
 *                        Version 2026-07-27-00-00-0000                       *
 ******************************************************************************
 *                                                                            *
 * A TURN server complete enough to carry an RNL connection over it, so that   *
 * TRNLTURNNetwork can be tested against something deterministic instead of    *
 * against whatever a public relay happens to do today.                        *
 *                                                                            *
 * It speaks the part of RFC 8656 a client actually needs: Allocate with long  *
 * term credentials, Refresh, CreatePermission, ChannelBind, Send indications  *
 * and Data indications, plus ChannelData frames in both directions.           *
 *                                                                            *
 * Each allocation gets a socket of its own, because that is what a relayed    *
 * address is: an address a peer can send to which forwards to exactly one     *
 * client. Without that second socket there would be nothing for a peer to     *
 * aim at and the whole exercise would be a loopback.                         *
 *                                                                            *
 * It runs in a thread of its own, which it has to: the allocation exchange in *
 * TRNLTURNNetwork.SocketBind is blocking, so nobody could answer it from the  *
 * same thread. That is safe here because TRNLVirtualNetwork locks around      *
 * Send, Receive and SocketWait, and releases the lock before it waits.        *
 *                                                                            *
 * The behaviours below are the ones worth being able to produce on demand: a  *
 * nonce which goes stale, a server which wants the newer integrity method,    *
 * and one which refuses to allocate at all. Each of them is a path through    *
 * the client that no correct server would ever exercise.                     *
 *                                                                            *
 ******************************************************************************)
unit RNLTestTURNServer;
{$ifdef fpc}
 {$mode delphi}
{$endif}
{$h+}

{$ifdef win32}
 {$define Windows}
{$endif}
{$ifdef win64}
 {$define Windows}
{$endif}

interface

uses SysUtils,
     Classes,
     SyncObjs,
     RNL;

type // What of the exchange a test wants to look at afterwards
     TRNLTestTURNServerCounter=
      (
       RNL_TEST_TURN_COUNT_ALLOCATE_REQUESTS,
       RNL_TEST_TURN_COUNT_REFRESH_REQUESTS,
       RNL_TEST_TURN_COUNT_CREATE_PERMISSION_REQUESTS,
       RNL_TEST_TURN_COUNT_CHANNEL_BIND_REQUESTS,
       RNL_TEST_TURN_COUNT_SEND_INDICATIONS,
       RNL_TEST_TURN_COUNT_CHANNEL_DATA_FROM_CLIENT,
       RNL_TEST_TURN_COUNT_FORWARDED_TO_PEER,
       RNL_TEST_TURN_COUNT_FORWARDED_TO_CLIENT,
       RNL_TEST_TURN_COUNT_REJECTED_FOR_NO_PERMISSION,
       RNL_TEST_TURN_COUNT_UNAUTHORIZED,
       RNL_TEST_TURN_COUNT_STALE_NONCES,
       // How many allocate requests named the address family they wanted
       RNL_TEST_TURN_COUNT_REQUESTED_ADDRESS_FAMILY
      );

     TRNLTestTURNServerBehaviour=
      (
       // Everything by the book
       RNL_TEST_TURN_SERVER_CORRECT,
       // Answers the first authenticated request with 438, which is what a server does when the
       // nonce it handed out has expired in the meantime. Routine rather than a failure, and the
       // only way to reach the retry path in the client.
       RNL_TEST_TURN_SERVER_STALE_NONCE_ONCE,
       // Names SHA-256 as the password algorithm, so the key is derived and the integrity computed
       // the way RFC 8489 wants rather than the way RFC 5389 did
       RNL_TEST_TURN_SERVER_REQUIRE_SHA256,
       // Refuses to allocate. A client has to come out of that with a usable socket and no relay,
       // not with a broken one.
       RNL_TEST_TURN_SERVER_REFUSE_ALLOCATION,
       // Refuses the address family that was asked for, with 440. Final rather than retryable: what
       // to ask for instead is the deployment's decision, not the client's.
       RNL_TEST_TURN_SERVER_REFUSE_ADDRESS_FAMILY
      );

     TRNLTestTURNServer=class(TThread)
      private

       const MaximumAllocations=8;
             MaximumPermissionsPerAllocation=8;
             MaximumChannelsPerAllocation=8;

       type TRNLTestTURNChannel=record
             Used:boolean;
             Number:TRNLUInt16;
             PeerAddress:TRNLAddress;
            end;

            // One accepted stream from a client. Over TCP a client is not an address any more but a
            // connection, and a frame can arrive in pieces, so each one carries its own buffer.
            TRNLTestTURNStream=record
             Used:boolean;
             Socket:TRNLSocket;
             Address:TRNLAddress;
             Buffer:array[0..TRNLSTUNMessage.MaximumSize*2-1] of TRNLUInt8;
             BufferSize:TRNLSizeInt;
            end;

            TRNLTestTURNAllocation=record
             Used:boolean;
             ClientAddress:TRNLAddress;
             // Which stream this allocation was made over, or null for one made over datagrams. Every
             // answer towards this client has to leave the same way it came in.
             ClientStream:TRNLSocket;
             // The socket a peer aims at, which is what makes this a relay rather than a loopback
             Socket:TRNLSocket;
             RelayedAddress:TRNLAddress;
             Lifetime:TRNLUInt32;
             Permissions:array[0..MaximumPermissionsPerAllocation-1] of TRNLHostAddress;
             CountPermissions:TRNLSizeInt;
             Channels:array[0..MaximumChannelsPerAllocation-1] of TRNLTestTURNChannel;
            end;

      private

       fInstance:TRNLInstance;

       fNetwork:TRNLNetwork;

       fSocket:TRNLSocket;

       fBehaviour:TRNLTestTURNServerBehaviour;

       fRealm:TRNLRawByteString;

       fNonce:TRNLRawByteString;

       fUsername:TRNLRawByteString;

       fPassword:TRNLRawByteString;

       fRelayedHost:TRNLHostAddress;

       fNextRelayedPort:TRNLUInt16;

       fAllocations:array[0..MaximumAllocations-1] of TRNLTestTURNAllocation;

       // Null unless a TCP port was asked for. RFC 8656 lets a client reach a relay over a stream,
       // which is the only way in from a network that lets no UDP out.
       fListenSocket:TRNLSocket;

       fStreams:array[0..MaximumAllocations-1] of TRNLTestTURNStream;

       // Der Stream, über den die gerade bearbeitete Anfrage hereinkam, oder null bei Datagrammen.
       // Ein Feld und kein Parameter, weil der gesamte Versand im selben Thread unter derselben
       // Sperre abläuft und ein Parameter sonst durch jeden Handler gefädelt werden müsste.
       fCurrentStream:TRNLSocket;

       fStaleNonceSpent:boolean;

       fLock:TCriticalSection;

       fCountAllocateRequests:TRNLSizeInt;
       fCountRefreshRequests:TRNLSizeInt;
       fCountCreatePermissionRequests:TRNLSizeInt;
       fCountChannelBindRequests:TRNLSizeInt;
       fCountSendIndications:TRNLSizeInt;
       fCountChannelDataFromClient:TRNLSizeInt;
       fCountForwardedToPeer:TRNLSizeInt;
       fCountForwardedToClient:TRNLSizeInt;
       fCountRejectedForNoPermission:TRNLSizeInt;
       fCountUnauthorized:TRNLSizeInt;
       fCountStaleNonces:TRNLSizeInt;
       fCountRequestedAddressFamily:TRNLSizeInt;


       // The key the client is expected to have derived, which is what an arriving MESSAGE-INTEGRITY
       // has to verify under
       procedure DeriveExpectedKey(out aKey;out aKeySize:TRNLSizeInt;const aUseSHA256:boolean);

       function FindAllocationByClient(const aClientAddress:TRNLAddress):TRNLSizeInt;
       function FindAllocationBySocket(const aSocket:TRNLSocket):TRNLSizeInt;
       function CreateAllocation(const aClientAddress:TRNLAddress):TRNLSizeInt;
       function HasPermission(const aIndex:TRNLSizeInt;const aPeerHost:TRNLHostAddress):boolean;
       procedure AddPermission(const aIndex:TRNLSizeInt;const aPeerHost:TRNLHostAddress);
       function FindChannelByNumber(const aIndex:TRNLSizeInt;const aNumber:TRNLUInt16):TRNLSizeInt;
       function FindChannelByPeer(const aIndex:TRNLSizeInt;const aPeerAddress:TRNLAddress):TRNLSizeInt;

       // aStream null means answer as a datagram to aAddress, otherwise as a frame in that stream
       procedure SendMessage_(const aSocket:TRNLSocket;const aAddress:TRNLAddress;
                              var aMessage:TRNLSTUNMessage;const aStream:TRNLSocket=RNL_SOCKET_NULL);
       procedure SendFrame(const aSocket:TRNLSocket;const aAddress:TRNLAddress;
                           const aData;const aDataSize:TRNLSizeInt;const aStream:TRNLSocket=RNL_SOCKET_NULL);
       function AcceptStreams:boolean;
       function PumpStream(const aIndex:TRNLSizeInt):boolean;
       function TakeFrame(const aIndex:TRNLSizeInt;out aFrame;const aMaximumSize:TRNLSizeInt;
                          out aFrameSize:TRNLSizeInt):boolean;
       procedure ForgetStream(const aIndex:TRNLSizeInt);
       procedure SendErrorResponse(const aAddress:TRNLAddress;
                                   var aRequest:TRNLSTUNMessage;
                                   const aCode:TRNLUInt32;
                                   const aReason:TRNLRawByteString;
                                   const aWithCredentialHints:boolean);
       // True once the request carries credentials which verify. Everything else answers 401 with
       // the realm and the nonce, which is the exchange every long term credential starts with.
       function Authenticate(const aAddress:TRNLAddress;var aRequest:TRNLSTUNMessage):boolean;

       procedure HandleAllocate(const aAddress:TRNLAddress;var aRequest:TRNLSTUNMessage);
       procedure HandleRefresh(const aAddress:TRNLAddress;var aRequest:TRNLSTUNMessage);
       procedure HandleCreatePermission(const aAddress:TRNLAddress;var aRequest:TRNLSTUNMessage);
       procedure HandleChannelBind(const aAddress:TRNLAddress;var aRequest:TRNLSTUNMessage);
       procedure HandleSendIndication(const aAddress:TRNLAddress;var aRequest:TRNLSTUNMessage);
       procedure HandleChannelDataFromClient(const aAddress:TRNLAddress;
                                             const aData;const aDataSize:TRNLSizeInt);
       procedure HandleFromPeer(const aAllocationIndex:TRNLSizeInt;
                                const aPeerAddress:TRNLAddress;
                                const aData;const aDataSize:TRNLSizeInt);
       procedure HandleFromClient(const aAddress:TRNLAddress;const aData;const aDataSize:TRNLSizeInt;
                                  const aStream:TRNLSocket=RNL_SOCKET_NULL);

      protected

       procedure Execute; override;

      public

       constructor Create(const aInstance:TRNLInstance;
                          const aNetwork:TRNLNetwork;
                          const aPort:TRNLUInt16;
                          const aBehaviour:TRNLTestTURNServerBehaviour;
                          const aBindHost:TRNLHostAddress;
                          const aRelayedHost:TRNLHostAddress;
                          const aUsername:TRNLRawByteString;
                          const aPassword:TRNLRawByteString;
                          const aRealm:TRNLRawByteString='rnl.test';
                          // Zero means no stream port at all, which is every test that does not care
                          const aTCPPort:TRNLUInt16=0); reintroduce;
       destructor Destroy; override;

       // One call with an enum rather than eleven properties, which is both shorter here and
       // clearer at the call site
       function Count(const aWhich:TRNLTestTURNServerCounter):TRNLSizeInt;

      published

       property Behaviour:TRNLTestTURNServerBehaviour read fBehaviour;

     end;

implementation

const POLL_TIMEOUT_MILLISECONDS=10;

      FIRST_RELAYED_PORT=50000;

      SERVER_LIFETIME=600;

constructor TRNLTestTURNServer.Create(const aInstance:TRNLInstance;
                                      const aNetwork:TRNLNetwork;
                                      const aPort:TRNLUInt16;
                                      const aBehaviour:TRNLTestTURNServerBehaviour;
                                      const aBindHost:TRNLHostAddress;
                                      const aRelayedHost:TRNLHostAddress;
                                      const aUsername:TRNLRawByteString;
                                      const aPassword:TRNLRawByteString;
                                      const aRealm:TRNLRawByteString='rnl.test';
                                      const aTCPPort:TRNLUInt16=0);
var Address:TRNLAddress;
    Index:TRNLSizeInt;
begin

 fInstance:=aInstance;
 fNetwork:=aNetwork;
 fBehaviour:=aBehaviour;
 fRealm:=aRealm;
 // Any value will do as long as the client hands it back unchanged, which is the whole of what a
 // nonce is for here
 fNonce:='0123456789abcdef';
 fUsername:=aUsername;
 fPassword:=aPassword;
 fRelayedHost:=aRelayedHost;
 fNextRelayedPort:=FIRST_RELAYED_PORT;
 fCurrentStream:=RNL_SOCKET_NULL;
 fStaleNonceSpent:=false;

 for Index:=0 to MaximumAllocations-1 do begin
  fAllocations[Index].Used:=false;
  fAllocations[Index].Socket:=RNL_SOCKET_NULL;
  fAllocations[Index].ClientStream:=RNL_SOCKET_NULL;
  fStreams[Index].Used:=false;
  fStreams[Index].Socket:=RNL_SOCKET_NULL;
  fStreams[Index].BufferSize:=0;
 end;

 fListenSocket:=RNL_SOCKET_NULL;

 fCountAllocateRequests:=0;
 fCountRefreshRequests:=0;
 fCountCreatePermissionRequests:=0;
 fCountChannelBindRequests:=0;
 fCountSendIndications:=0;
 fCountChannelDataFromClient:=0;
 fCountForwardedToPeer:=0;
 fCountForwardedToClient:=0;
 fCountRejectedForNoPermission:=0;
 fCountUnauthorized:=0;
 fCountStaleNonces:=0;
 fCountRequestedAddressFamily:=0;

 fLock:=TCriticalSection.Create;

 // IPv4 only, for the same reason TRNLTestHostPair binds IPv4 only: on the virtual network both
 // families would end up on the very same localhost address
 fSocket:=fNetwork.SocketCreate(RNL_SOCKET_TYPE_DATAGRAM,RNL_IPV4);
 if fSocket<>RNL_SOCKET_NULL then begin
  FillChar(Address,SizeOf(TRNLAddress),#0);
  Address.Host:=aBindHost;
  Address.Port:=aPort;
  fNetwork.SocketSetOption(fSocket,RNL_SOCKET_OPTION_NONBLOCK,1);
  fNetwork.SocketSetOption(fSocket,RNL_SOCKET_OPTION_REUSEADDR,1);
  if not fNetwork.SocketBind(fSocket,@Address,RNL_IPV4) then begin
   fNetwork.SocketDestroy(fSocket);
   fSocket:=RNL_SOCKET_NULL;
  end;
 end;

 // A stream port only when one was asked for. Everything relayed can then arrive either way, which
 // is what a real relay offers as well.
 if aTCPPort<>0 then begin
  fListenSocket:=fNetwork.SocketCreate(RNL_SOCKET_TYPE_STREAM,RNL_IPV4);
  if fListenSocket<>RNL_SOCKET_NULL then begin
   FillChar(Address,SizeOf(TRNLAddress),#0);
   Address.Host:=aBindHost;
   Address.Port:=aTCPPort;
   fNetwork.SocketSetOption(fListenSocket,RNL_SOCKET_OPTION_REUSEADDR,1);
   if fNetwork.SocketBind(fListenSocket,@Address,RNL_IPV4) and
      fNetwork.SocketListen(fListenSocket,MaximumAllocations) then begin
    fNetwork.SocketSetOption(fListenSocket,RNL_SOCKET_OPTION_NONBLOCK,1);
   end else begin
    fNetwork.SocketDestroy(fListenSocket);
    fListenSocket:=RNL_SOCKET_NULL;
   end;
  end;
 end;

 inherited Create(false);

end;

destructor TRNLTestTURNServer.Destroy;
var Index:TRNLSizeInt;
begin
 Terminate;
 WaitFor;
 for Index:=0 to MaximumAllocations-1 do begin
  if fAllocations[Index].Socket<>RNL_SOCKET_NULL then begin
   fNetwork.SocketDestroy(fAllocations[Index].Socket);
   fAllocations[Index].Socket:=RNL_SOCKET_NULL;
  end;
 end;
 for Index:=0 to MaximumAllocations-1 do begin
  if fStreams[Index].Socket<>RNL_SOCKET_NULL then begin
   fNetwork.SocketShutdown(fStreams[Index].Socket,RNL_SOCKET_SHUTDOWN_READ_WRITE);
   fNetwork.SocketDestroy(fStreams[Index].Socket);
   fStreams[Index].Socket:=RNL_SOCKET_NULL;
  end;
 end;
 if fListenSocket<>RNL_SOCKET_NULL then begin
  fNetwork.SocketDestroy(fListenSocket);
  fListenSocket:=RNL_SOCKET_NULL;
 end;
 if fSocket<>RNL_SOCKET_NULL then begin
  fNetwork.SocketDestroy(fSocket);
  fSocket:=RNL_SOCKET_NULL;
 end;
 FreeAndNil(fLock);
 inherited Destroy;
end;

function TRNLTestTURNServer.Count(const aWhich:TRNLTestTURNServerCounter):TRNLSizeInt;
begin
 fLock.Acquire;
 try
  case aWhich of
   RNL_TEST_TURN_COUNT_ALLOCATE_REQUESTS:begin
    result:=fCountAllocateRequests;
   end;
   RNL_TEST_TURN_COUNT_REFRESH_REQUESTS:begin
    result:=fCountRefreshRequests;
   end;
   RNL_TEST_TURN_COUNT_CREATE_PERMISSION_REQUESTS:begin
    result:=fCountCreatePermissionRequests;
   end;
   RNL_TEST_TURN_COUNT_CHANNEL_BIND_REQUESTS:begin
    result:=fCountChannelBindRequests;
   end;
   RNL_TEST_TURN_COUNT_SEND_INDICATIONS:begin
    result:=fCountSendIndications;
   end;
   RNL_TEST_TURN_COUNT_CHANNEL_DATA_FROM_CLIENT:begin
    result:=fCountChannelDataFromClient;
   end;
   RNL_TEST_TURN_COUNT_FORWARDED_TO_PEER:begin
    result:=fCountForwardedToPeer;
   end;
   RNL_TEST_TURN_COUNT_FORWARDED_TO_CLIENT:begin
    result:=fCountForwardedToClient;
   end;
   RNL_TEST_TURN_COUNT_REJECTED_FOR_NO_PERMISSION:begin
    result:=fCountRejectedForNoPermission;
   end;
   RNL_TEST_TURN_COUNT_UNAUTHORIZED:begin
    result:=fCountUnauthorized;
   end;
   RNL_TEST_TURN_COUNT_STALE_NONCES:begin
    result:=fCountStaleNonces;
   end;
   else begin
    result:=fCountRequestedAddressFamily;
   end;
  end;
 finally
  fLock.Release;
 end;
end;

procedure TRNLTestTURNServer.DeriveExpectedKey(out aKey;out aKeySize:TRNLSizeInt;const aUseSHA256:boolean);
var Credentials:TRNLTURNCredentials;
begin
 // Derived through the very same record the client uses, which is deliberate: what is under test
 // here is the message layer around the key, and RFC 4231 already pins the key derivation itself
 Credentials.Clear;
 Credentials.Username:=fUsername;
 Credentials.Password:=fPassword;
 Credentials.Realm:=fRealm;
 Credentials.UseSHA256:=aUseSHA256;
 Credentials.DeriveKey;
 Move(Credentials.Key,aKey,SizeOf(TRNLTURNCredentials.TRNLTURNKey));
 aKeySize:=Credentials.KeySize;
 Credentials.Clear;
end;

function TRNLTestTURNServer.FindAllocationByClient(const aClientAddress:TRNLAddress):TRNLSizeInt;
var Index:TRNLSizeInt;
begin
 result:=-1;
 for Index:=0 to MaximumAllocations-1 do begin
  if fAllocations[Index].Used and fAllocations[Index].ClientAddress.Equals(aClientAddress) then begin
   result:=Index;
   exit;
  end;
 end;
end;

function TRNLTestTURNServer.FindAllocationBySocket(const aSocket:TRNLSocket):TRNLSizeInt;
var Index:TRNLSizeInt;
begin
 result:=-1;
 for Index:=0 to MaximumAllocations-1 do begin
  if fAllocations[Index].Used and (fAllocations[Index].Socket=aSocket) then begin
   result:=Index;
   exit;
  end;
 end;
end;

function TRNLTestTURNServer.CreateAllocation(const aClientAddress:TRNLAddress):TRNLSizeInt;
var Index,ChannelIndex:TRNLSizeInt;
    Socket:TRNLSocket;
    Address:TRNLAddress;
begin

 result:=-1;

 for Index:=0 to MaximumAllocations-1 do begin
  if not fAllocations[Index].Used then begin
   result:=Index;
   break;
  end;
 end;
 if result<0 then begin
  exit;
 end;

 Socket:=fNetwork.SocketCreate(RNL_SOCKET_TYPE_DATAGRAM,RNL_IPV4);
 if Socket=RNL_SOCKET_NULL then begin
  result:=-1;
  exit;
 end;

 FillChar(Address,SizeOf(TRNLAddress),#0);
 Address.Host:=fRelayedHost;
 Address.Port:=fNextRelayedPort;
 inc(fNextRelayedPort);

 fNetwork.SocketSetOption(Socket,RNL_SOCKET_OPTION_NONBLOCK,1);
 fNetwork.SocketSetOption(Socket,RNL_SOCKET_OPTION_REUSEADDR,1);
 if not fNetwork.SocketBind(Socket,@Address,RNL_IPV4) then begin
  fNetwork.SocketDestroy(Socket);
  result:=-1;
  exit;
 end;

 fAllocations[result].Used:=true;
 fAllocations[result].ClientAddress:=aClientAddress;
 fAllocations[result].ClientStream:=fCurrentStream;
 fAllocations[result].Socket:=Socket;
 fAllocations[result].RelayedAddress:=Address;
 fAllocations[result].Lifetime:=SERVER_LIFETIME;
 fAllocations[result].CountPermissions:=0;
 for ChannelIndex:=0 to MaximumChannelsPerAllocation-1 do begin
  fAllocations[result].Channels[ChannelIndex].Used:=false;
 end;

end;

function TRNLTestTURNServer.HasPermission(const aIndex:TRNLSizeInt;const aPeerHost:TRNLHostAddress):boolean;
var Index:TRNLSizeInt;
begin
 result:=false;
 for Index:=0 to fAllocations[aIndex].CountPermissions-1 do begin
  if fAllocations[aIndex].Permissions[Index].Equals(aPeerHost) then begin
   result:=true;
   exit;
  end;
 end;
end;

procedure TRNLTestTURNServer.AddPermission(const aIndex:TRNLSizeInt;const aPeerHost:TRNLHostAddress);
begin
 if HasPermission(aIndex,aPeerHost) or
    (fAllocations[aIndex].CountPermissions>=MaximumPermissionsPerAllocation) then begin
  exit;
 end;
 fAllocations[aIndex].Permissions[fAllocations[aIndex].CountPermissions]:=aPeerHost;
 inc(fAllocations[aIndex].CountPermissions);
end;

function TRNLTestTURNServer.FindChannelByNumber(const aIndex:TRNLSizeInt;const aNumber:TRNLUInt16):TRNLSizeInt;
var Index:TRNLSizeInt;
begin
 result:=-1;
 for Index:=0 to MaximumChannelsPerAllocation-1 do begin
  if fAllocations[aIndex].Channels[Index].Used and
     (fAllocations[aIndex].Channels[Index].Number=aNumber) then begin
   result:=Index;
   exit;
  end;
 end;
end;

function TRNLTestTURNServer.FindChannelByPeer(const aIndex:TRNLSizeInt;const aPeerAddress:TRNLAddress):TRNLSizeInt;
var Index:TRNLSizeInt;
begin
 result:=-1;
 for Index:=0 to MaximumChannelsPerAllocation-1 do begin
  if fAllocations[aIndex].Channels[Index].Used and
     fAllocations[aIndex].Channels[Index].PeerAddress.Equals(aPeerAddress) then begin
   result:=Index;
   exit;
  end;
 end;
end;

procedure TRNLTestTURNServer.SendFrame(const aSocket:TRNLSocket;const aAddress:TRNLAddress;
                                       const aData;const aDataSize:TRNLSizeInt;const aStream:TRNLSocket=RNL_SOCKET_NULL);
var Padded:TRNLSizeInt;
    Padding:array[0..3] of TRNLUInt8;
begin
 if aStream=RNL_SOCKET_NULL then begin
  fNetwork.Send(aSocket,@aAddress,aData,aDataSize,RNL_IPV4);
  exit;
 end;
 if fNetwork.SendStream(aStream,aData,aDataSize)<>aDataSize then begin
  exit;
 end;
 // Every frame in a stream starts on a four byte boundary, so a ChannelData payload which is not a
 // multiple of four is followed by padding
 Padded:=((aDataSize+3) and not TRNLSizeInt(3))-aDataSize;
 if Padded>0 then begin
  FillChar(Padding,SizeOf(Padding),#0);
  fNetwork.SendStream(aStream,Padding[0],Padded);
 end;
end;

function TRNLTestTURNServer.AcceptStreams:boolean;
var Index,Free_:TRNLSizeInt;
    Socket:TRNLSocket;
    Address:TRNLAddress;
begin

 result:=false;

 if fListenSocket=RNL_SOCKET_NULL then begin
  exit;
 end;

 repeat

  FillChar(Address,SizeOf(TRNLAddress),#0);
  Socket:=fNetwork.SocketAccept(fListenSocket,@Address,RNL_IPV4);
  if Socket=RNL_SOCKET_NULL then begin
   exit;
  end;

  Free_:=-1;
  for Index:=0 to MaximumAllocations-1 do begin
   if not fStreams[Index].Used then begin
    Free_:=Index;
    break;
   end;
  end;

  if Free_<0 then begin
   // As many streams as there are allocations, which is the same bound; one more would have nowhere
   // to belong anyway
   fNetwork.SocketShutdown(Socket,RNL_SOCKET_SHUTDOWN_READ_WRITE);
   fNetwork.SocketDestroy(Socket);
   exit;
  end;

  fNetwork.SocketSetOption(Socket,RNL_SOCKET_OPTION_NONBLOCK,1);
  fStreams[Free_].Used:=true;
  fStreams[Free_].Socket:=Socket;
  fStreams[Free_].Address:=Address;
  fStreams[Free_].BufferSize:=0;
  result:=true;

 until false;

end;

function TRNLTestTURNServer.PumpStream(const aIndex:TRNLSizeInt):boolean;
var Received:TRNLSizeInt;
begin
 result:=true;
 while fStreams[aIndex].BufferSize<TRNLSizeInt(SizeOf(fStreams[aIndex].Buffer)) do begin
  Received:=fNetwork.ReceiveStream(fStreams[aIndex].Socket,
                                   fStreams[aIndex].Buffer[fStreams[aIndex].BufferSize],
                                   TRNLSizeInt(SizeOf(fStreams[aIndex].Buffer))-fStreams[aIndex].BufferSize);
  if Received>0 then begin
   inc(fStreams[aIndex].BufferSize,Received);
  end else if Received=0 then begin
   exit;
  end else begin
   result:=false;
   exit;
  end;
 end;
end;

function TRNLTestTURNServer.TakeFrame(const aIndex:TRNLSizeInt;out aFrame;const aMaximumSize:TRNLSizeInt;
                                      out aFrameSize:TRNLSizeInt):boolean;
var Needed,Payload:TRNLSizeInt;
begin

 result:=false;
 aFrameSize:=0;

 if fStreams[aIndex].BufferSize<TRNLSTUNMessage.ChannelDataHeaderSize then begin
  exit;
 end;

 if (fStreams[aIndex].Buffer[0] and $c0)=0 then begin
  if fStreams[aIndex].BufferSize<TRNLSTUNMessage.HeaderSize then begin
   exit;
  end;
  Payload:=TRNLMemoryAccess.LoadBigEndianUInt16(fStreams[aIndex].Buffer[2]);
  Needed:=TRNLSTUNMessage.HeaderSize+Payload;
 end else begin
  Payload:=TRNLMemoryAccess.LoadBigEndianUInt16(fStreams[aIndex].Buffer[2]);
  Needed:=(TRNLSTUNMessage.ChannelDataHeaderSize+Payload+3) and not TRNLSizeInt(3);
 end;

 if (Needed<=0) or (Needed>TRNLSizeInt(SizeOf(fStreams[aIndex].Buffer))) then begin
  fStreams[aIndex].BufferSize:=0;
  exit;
 end;

 if fStreams[aIndex].BufferSize<Needed then begin
  exit;
 end;

 if Needed<=aMaximumSize then begin
  Move(fStreams[aIndex].Buffer[0],aFrame,Needed);
  aFrameSize:=Needed;
  result:=true;
 end;

 dec(fStreams[aIndex].BufferSize,Needed);
 if fStreams[aIndex].BufferSize>0 then begin
  Move(fStreams[aIndex].Buffer[Needed],fStreams[aIndex].Buffer[0],fStreams[aIndex].BufferSize);
 end;

end;

procedure TRNLTestTURNServer.ForgetStream(const aIndex:TRNLSizeInt);
var Index:TRNLSizeInt;
begin
 for Index:=0 to MaximumAllocations-1 do begin
  if fAllocations[Index].Used and (fAllocations[Index].ClientStream=fStreams[aIndex].Socket) then begin
   if fAllocations[Index].Socket<>RNL_SOCKET_NULL then begin
    fNetwork.SocketDestroy(fAllocations[Index].Socket);
    fAllocations[Index].Socket:=RNL_SOCKET_NULL;
   end;
   fAllocations[Index].Used:=false;
   fAllocations[Index].ClientStream:=RNL_SOCKET_NULL;
  end;
 end;
 if fStreams[aIndex].Socket<>RNL_SOCKET_NULL then begin
  fNetwork.SocketShutdown(fStreams[aIndex].Socket,RNL_SOCKET_SHUTDOWN_READ_WRITE);
  fNetwork.SocketDestroy(fStreams[aIndex].Socket);
  fStreams[aIndex].Socket:=RNL_SOCKET_NULL;
 end;
 fStreams[aIndex].Used:=false;
 fStreams[aIndex].BufferSize:=0;
end;

procedure TRNLTestTURNServer.SendMessage_(const aSocket:TRNLSocket;const aAddress:TRNLAddress;
                                          var aMessage:TRNLSTUNMessage;const aStream:TRNLSocket=RNL_SOCKET_NULL);
begin
 if aMessage.Valid then begin
  SendFrame(aSocket,aAddress,PRNLUInt8Array(aMessage.DataPointer)^[0],aMessage.Size,aStream);
 end;
end;

procedure TRNLTestTURNServer.SendErrorResponse(const aAddress:TRNLAddress;
                                               var aRequest:TRNLSTUNMessage;
                                               const aCode:TRNLUInt32;
                                               const aReason:TRNLRawByteString;
                                               const aWithCredentialHints:boolean);
var Response:TRNLSTUNMessage;
    Value:array[0..3] of TRNLUInt8;
    Payload:TRNLRawByteString;
begin

 Response.Initialize(aRequest.MessageMethod or RNL_STUN_CLASS_ERROR_RESPONSE,aRequest.TransactionID);

 // Two reserved bytes, then the class as one digit and the number as two
 FillChar(Value,SizeOf(Value),#0);
 Value[2]:=TRNLUInt8((aCode div 100) and $07);
 Value[3]:=TRNLUInt8(aCode mod 100);
 SetLength(Payload,4+length(aReason));
 Move(Value[0],Payload[1],4);
 if length(aReason)>0 then begin
  Move(aReason[1],Payload[5],length(aReason));
 end;
 Response.AddStringAttribute(RNL_STUN_ATTRIBUTE_ERROR_CODE,Payload);

 if aWithCredentialHints then begin
  Response.AddStringAttribute(RNL_STUN_ATTRIBUTE_REALM,fRealm);
  Response.AddStringAttribute(RNL_STUN_ATTRIBUTE_NONCE,fNonce);
  if fBehaviour=RNL_TEST_TURN_SERVER_REQUIRE_SHA256 then begin
   Response.AddUInt16Attribute(RNL_STUN_ATTRIBUTE_PASSWORD_ALGORITHM,RNL_STUN_PASSWORD_ALGORITHM_SHA256);
  end;
 end;

 Response.AddFingerprint;

 SendMessage_(fSocket,aAddress,Response,fCurrentStream);

end;

function TRNLTestTURNServer.Authenticate(const aAddress:TRNLAddress;var aRequest:TRNLSTUNMessage):boolean;
var Key:TRNLTURNCredentials.TRNLTURNKey;
    KeySize:TRNLSizeInt;
    Nonce:TRNLRawByteString;
    UseSHA256,HasIntegrity:boolean;
begin

 result:=false;

 UseSHA256:=fBehaviour=RNL_TEST_TURN_SERVER_REQUIRE_SHA256;

 if UseSHA256 then begin
  HasIntegrity:=aRequest.HasAttribute(RNL_STUN_ATTRIBUTE_MESSAGE_INTEGRITY_SHA256);
 end else begin
  HasIntegrity:=aRequest.HasAttribute(RNL_STUN_ATTRIBUTE_MESSAGE_INTEGRITY);
 end;

 if not HasIntegrity then begin
  // Nothing to check, so this is the first attempt and it gets told what it needs to know
  inc(fCountUnauthorized);
  SendErrorResponse(aAddress,aRequest,401,'Unauthorized',true);
  exit;
 end;

 if not aRequest.ReadStringAttribute(RNL_STUN_ATTRIBUTE_NONCE,Nonce) then begin
  inc(fCountUnauthorized);
  SendErrorResponse(aAddress,aRequest,401,'Unauthorized',true);
  exit;
 end;

 // A nonce which has gone stale is answered with 438 and a fresh one, exactly once, so that the
 // retry path in the client is reached without leaving it in a loop
 if (fBehaviour=RNL_TEST_TURN_SERVER_STALE_NONCE_ONCE) and not fStaleNonceSpent then begin
  fStaleNonceSpent:=true;
  fNonce:='fedcba9876543210';
  inc(fCountStaleNonces);
  SendErrorResponse(aAddress,aRequest,438,'Stale Nonce',true);
  exit;
 end;

 if Nonce<>fNonce then begin
  inc(fCountStaleNonces);
  SendErrorResponse(aAddress,aRequest,438,'Stale Nonce',true);
  exit;
 end;

 DeriveExpectedKey(Key,KeySize,UseSHA256);
 if KeySize<=0 then begin
  exit;
 end;

 if UseSHA256 then begin
  result:=aRequest.VerifyMessageIntegritySHA256(Key[0],KeySize);
 end else begin
  result:=aRequest.VerifyMessageIntegrity(Key[0],KeySize);
 end;

 if not result then begin
  inc(fCountUnauthorized);
  SendErrorResponse(aAddress,aRequest,401,'Unauthorized',true);
 end;

end;

procedure TRNLTestTURNServer.HandleAllocate(const aAddress:TRNLAddress;var aRequest:TRNLSTUNMessage);
var Response:TRNLSTUNMessage;
    Index:TRNLSizeInt;
    Key:TRNLTURNCredentials.TRNLTURNKey;
    KeySize:TRNLSizeInt;
    RequestedFamily:TRNLUInt32;
begin

 inc(fCountAllocateRequests);

 if not Authenticate(aAddress,aRequest) then begin
  exit;
 end;

 if fBehaviour=RNL_TEST_TURN_SERVER_REFUSE_ALLOCATION then begin
  SendErrorResponse(aAddress,aRequest,486,'Allocation Quota Reached',false);
  exit;
 end;

 // Whether the client named the family it wants is worth counting: the attribute is comprehension
 // required, so sending it where it is not needed would be a bug and not a nicety
 if aRequest.ReadUInt32Attribute(RNL_TURN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY,RequestedFamily) then begin
  inc(fCountRequestedAddressFamily);
  if fBehaviour=RNL_TEST_TURN_SERVER_REFUSE_ADDRESS_FAMILY then begin
   SendErrorResponse(aAddress,aRequest,440,'Address Family not Supported',false);
   exit;
  end;
 end;

 Index:=FindAllocationByClient(aAddress);
 if Index<0 then begin
  Index:=CreateAllocation(aAddress);
 end;
 if Index<0 then begin
  SendErrorResponse(aAddress,aRequest,508,'Insufficient Capacity',false);
  exit;
 end;

 Response.Initialize(RNL_TURN_METHOD_ALLOCATE or RNL_STUN_CLASS_SUCCESS_RESPONSE,aRequest.TransactionID);
 Response.AddXORAddressAttribute(RNL_TURN_ATTRIBUTE_XOR_RELAYED_ADDRESS,fAllocations[Index].RelayedAddress);
 Response.AddXORAddressAttribute(RNL_STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,aAddress);
 Response.AddUInt32Attribute(RNL_TURN_ATTRIBUTE_LIFETIME,fAllocations[Index].Lifetime);
 DeriveExpectedKey(Key,KeySize,fBehaviour=RNL_TEST_TURN_SERVER_REQUIRE_SHA256);
 if fBehaviour=RNL_TEST_TURN_SERVER_REQUIRE_SHA256 then begin
  Response.AddMessageIntegritySHA256(Key[0],KeySize);
 end else begin
  Response.AddMessageIntegrity(Key[0],KeySize);
 end;
 Response.AddFingerprint;

 SendMessage_(fSocket,aAddress,Response,fCurrentStream);

end;

procedure TRNLTestTURNServer.HandleRefresh(const aAddress:TRNLAddress;var aRequest:TRNLSTUNMessage);
var Response:TRNLSTUNMessage;
    Index:TRNLSizeInt;
    Lifetime:TRNLUInt32;
begin

 inc(fCountRefreshRequests);

 if not Authenticate(aAddress,aRequest) then begin
  exit;
 end;

 Index:=FindAllocationByClient(aAddress);
 if Index<0 then begin
  SendErrorResponse(aAddress,aRequest,437,'Allocation Mismatch',false);
  exit;
 end;

 if aRequest.ReadUInt32Attribute(RNL_TURN_ATTRIBUTE_LIFETIME,Lifetime) and (Lifetime=0) then begin
  // A refresh with a lifetime of zero is how a client says it is done with the allocation
  fNetwork.SocketDestroy(fAllocations[Index].Socket);
  fAllocations[Index].Socket:=RNL_SOCKET_NULL;
  fAllocations[Index].Used:=false;
  Lifetime:=0;
 end else begin
  Lifetime:=fAllocations[Index].Lifetime;
 end;

 Response.Initialize(RNL_TURN_METHOD_REFRESH or RNL_STUN_CLASS_SUCCESS_RESPONSE,aRequest.TransactionID);
 Response.AddUInt32Attribute(RNL_TURN_ATTRIBUTE_LIFETIME,Lifetime);
 Response.AddFingerprint;

 SendMessage_(fSocket,aAddress,Response,fCurrentStream);

end;

procedure TRNLTestTURNServer.HandleCreatePermission(const aAddress:TRNLAddress;var aRequest:TRNLSTUNMessage);
var Response:TRNLSTUNMessage;
    Index:TRNLSizeInt;
    PeerAddress:TRNLAddress;
begin

 inc(fCountCreatePermissionRequests);

 if not Authenticate(aAddress,aRequest) then begin
  exit;
 end;

 Index:=FindAllocationByClient(aAddress);
 if Index<0 then begin
  SendErrorResponse(aAddress,aRequest,437,'Allocation Mismatch',false);
  exit;
 end;

 if not aRequest.ReadAddressAttribute(RNL_TURN_ATTRIBUTE_XOR_PEER_ADDRESS,PeerAddress) then begin
  SendErrorResponse(aAddress,aRequest,400,'Bad Request',false);
  exit;
 end;

 // By address and not by port, which is what RFC 8656 section 9 makes of a permission
 AddPermission(Index,PeerAddress.Host);

 Response.Initialize(RNL_TURN_METHOD_CREATE_PERMISSION or RNL_STUN_CLASS_SUCCESS_RESPONSE,aRequest.TransactionID);
 Response.AddFingerprint;

 SendMessage_(fSocket,aAddress,Response,fCurrentStream);

end;

procedure TRNLTestTURNServer.HandleChannelBind(const aAddress:TRNLAddress;var aRequest:TRNLSTUNMessage);
var Response:TRNLSTUNMessage;
    Index,ChannelIndex,Free_:TRNLSizeInt;
    PeerAddress:TRNLAddress;
    ChannelNumber:TRNLUInt16;
begin

 inc(fCountChannelBindRequests);

 if not Authenticate(aAddress,aRequest) then begin
  exit;
 end;

 Index:=FindAllocationByClient(aAddress);
 if Index<0 then begin
  SendErrorResponse(aAddress,aRequest,437,'Allocation Mismatch',false);
  exit;
 end;

 if not (aRequest.ReadUInt16Attribute(RNL_TURN_ATTRIBUTE_CHANNEL_NUMBER,ChannelNumber) and
         aRequest.ReadAddressAttribute(RNL_TURN_ATTRIBUTE_XOR_PEER_ADDRESS,PeerAddress)) then begin
  SendErrorResponse(aAddress,aRequest,400,'Bad Request',false);
  exit;
 end;

 if (ChannelNumber<RNL_TURN_CHANNEL_NUMBER_FIRST) or (ChannelNumber>RNL_TURN_CHANNEL_NUMBER_LAST) then begin
  SendErrorResponse(aAddress,aRequest,400,'Bad Request',false);
  exit;
 end;

 ChannelIndex:=FindChannelByNumber(Index,ChannelNumber);
 if ChannelIndex<0 then begin
  Free_:=-1;
  for ChannelIndex:=0 to MaximumChannelsPerAllocation-1 do begin
   if not fAllocations[Index].Channels[ChannelIndex].Used then begin
    Free_:=ChannelIndex;
    break;
   end;
  end;
  if Free_<0 then begin
   SendErrorResponse(aAddress,aRequest,508,'Insufficient Capacity',false);
   exit;
  end;
  ChannelIndex:=Free_;
  fAllocations[Index].Channels[ChannelIndex].Used:=true;
  fAllocations[Index].Channels[ChannelIndex].Number:=ChannelNumber;
 end;

 fAllocations[Index].Channels[ChannelIndex].PeerAddress:=PeerAddress;

 // A channel bind carries a permission with it, which is what saves a client one round trip
 AddPermission(Index,PeerAddress.Host);

 Response.Initialize(RNL_TURN_METHOD_CHANNEL_BIND or RNL_STUN_CLASS_SUCCESS_RESPONSE,aRequest.TransactionID);
 Response.AddFingerprint;

 SendMessage_(fSocket,aAddress,Response,fCurrentStream);

end;

procedure TRNLTestTURNServer.HandleSendIndication(const aAddress:TRNLAddress;var aRequest:TRNLSTUNMessage);
var Index,PayloadPosition,PayloadSize:TRNLSizeInt;
    PeerAddress:TRNLAddress;
begin

 inc(fCountSendIndications);

 // Indications carry no integrity, by design: RFC 8656 leaves them unsigned because a relay cannot
 // do anything with a forged one that it could not do anyway
 Index:=FindAllocationByClient(aAddress);
 if Index<0 then begin
  exit;
 end;

 if not (aRequest.ReadAddressAttribute(RNL_TURN_ATTRIBUTE_XOR_PEER_ADDRESS,PeerAddress) and
         aRequest.FindAttribute(RNL_TURN_ATTRIBUTE_DATA,PayloadPosition,PayloadSize)) then begin
  exit;
 end;

 if not HasPermission(Index,PeerAddress.Host) then begin
  // Silently dropped, which is what a relay does: an indication has no error response
  inc(fCountRejectedForNoPermission);
  exit;
 end;

 fNetwork.Send(fAllocations[Index].Socket,
               @PeerAddress,
               PRNLUInt8Array(aRequest.DataPointer)^[PayloadPosition],
               PayloadSize,
               RNL_IPV4);
 inc(fCountForwardedToPeer);

end;

procedure TRNLTestTURNServer.HandleChannelDataFromClient(const aAddress:TRNLAddress;
                                                         const aData;const aDataSize:TRNLSizeInt);
var Index,ChannelIndex,PayloadSize:TRNLSizeInt;
    ChannelNumber:TRNLUInt16;
    Data:PRNLUInt8Array;
begin

 inc(fCountChannelDataFromClient);

 Data:=@aData;

 if aDataSize<TRNLSTUNMessage.ChannelDataHeaderSize then begin
  exit;
 end;

 ChannelNumber:=TRNLMemoryAccess.LoadBigEndianUInt16(Data^[0]);
 PayloadSize:=TRNLMemoryAccess.LoadBigEndianUInt16(Data^[2]);

 if (TRNLSTUNMessage.ChannelDataHeaderSize+PayloadSize)>aDataSize then begin
  exit;
 end;

 Index:=FindAllocationByClient(aAddress);
 if Index<0 then begin
  exit;
 end;

 ChannelIndex:=FindChannelByNumber(Index,ChannelNumber);
 if ChannelIndex<0 then begin
  exit;
 end;

 if not HasPermission(Index,fAllocations[Index].Channels[ChannelIndex].PeerAddress.Host) then begin
  inc(fCountRejectedForNoPermission);
  exit;
 end;

 fNetwork.Send(fAllocations[Index].Socket,
               @fAllocations[Index].Channels[ChannelIndex].PeerAddress,
               Data^[TRNLSTUNMessage.ChannelDataHeaderSize],
               PayloadSize,
               RNL_IPV4);
 inc(fCountForwardedToPeer);

end;

procedure TRNLTestTURNServer.HandleFromPeer(const aAllocationIndex:TRNLSizeInt;
                                            const aPeerAddress:TRNLAddress;
                                            const aData;const aDataSize:TRNLSizeInt);
var ChannelIndex:TRNLSizeInt;
    Frame:array[0..TRNLSTUNMessage.MaximumSize-1] of TRNLUInt8;
    Indication:TRNLSTUNMessage;
    TransactionID:TRNLSTUNTransactionID;
    Index:TRNLSizeInt;
begin

 if not HasPermission(aAllocationIndex,aPeerAddress.Host) then begin
  // Nobody asked for this peer to be let in, so it does not get in
  inc(fCountRejectedForNoPermission);
  exit;
 end;

 ChannelIndex:=FindChannelByPeer(aAllocationIndex,aPeerAddress);

 if ChannelIndex>=0 then begin
  if (TRNLSTUNMessage.ChannelDataHeaderSize+aDataSize)>TRNLSizeInt(SizeOf(Frame)) then begin
   exit;
  end;
  TRNLMemoryAccess.StoreBigEndianUInt16(Frame[0],fAllocations[aAllocationIndex].Channels[ChannelIndex].Number);
  TRNLMemoryAccess.StoreBigEndianUInt16(Frame[2],TRNLUInt16(aDataSize));
  Move(aData,Frame[TRNLSTUNMessage.ChannelDataHeaderSize],aDataSize);
  SendFrame(fSocket,
            fAllocations[aAllocationIndex].ClientAddress,
            Frame[0],
            TRNLSTUNMessage.ChannelDataHeaderSize+aDataSize,
            fAllocations[aAllocationIndex].ClientStream);
  inc(fCountForwardedToClient);
  exit;
 end;

 // No channel for that peer, so it goes as a Data indication. The transaction id of an indication
 // is not answered by anybody, so anything unrepeated will do.
 for Index:=0 to SizeOf(TRNLSTUNTransactionID)-1 do begin
  TransactionID[Index]:=TRNLUInt8((fCountForwardedToClient+Index) and $ff);
 end;
 Indication.Initialize(RNL_TURN_METHOD_DATA or RNL_STUN_CLASS_INDICATION,TransactionID);
 Indication.AddXORAddressAttribute(RNL_TURN_ATTRIBUTE_XOR_PEER_ADDRESS,aPeerAddress);
 Indication.AddAttribute(RNL_TURN_ATTRIBUTE_DATA,aData,aDataSize);
 SendMessage_(fSocket,fAllocations[aAllocationIndex].ClientAddress,Indication,
              fAllocations[aAllocationIndex].ClientStream);
 inc(fCountForwardedToClient);

end;

procedure TRNLTestTURNServer.HandleFromClient(const aAddress:TRNLAddress;const aData;const aDataSize:TRNLSizeInt;
                                              const aStream:TRNLSocket=RNL_SOCKET_NULL);
var Request:TRNLSTUNMessage;
begin

 fCurrentStream:=aStream;

 // The two high bits are what tell the two framings apart, exactly as they do on the client side
 if (PRNLUInt8Array(TRNLPointer(@aData))^[0] and $c0)<>0 then begin
  HandleChannelDataFromClient(aAddress,aData,aDataSize);
  exit;
 end;

 if not Request.Assign(aData,aDataSize) then begin
  exit;
 end;

 case Request.MessageMethod of
  RNL_TURN_METHOD_ALLOCATE:begin
   if Request.MessageClass=RNL_STUN_CLASS_REQUEST then begin
    HandleAllocate(aAddress,Request);
   end;
  end;
  RNL_TURN_METHOD_REFRESH:begin
   if Request.MessageClass=RNL_STUN_CLASS_REQUEST then begin
    HandleRefresh(aAddress,Request);
   end;
  end;
  RNL_TURN_METHOD_CREATE_PERMISSION:begin
   if Request.MessageClass=RNL_STUN_CLASS_REQUEST then begin
    HandleCreatePermission(aAddress,Request);
   end;
  end;
  RNL_TURN_METHOD_CHANNEL_BIND:begin
   if Request.MessageClass=RNL_STUN_CLASS_REQUEST then begin
    HandleChannelBind(aAddress,Request);
   end;
  end;
  RNL_TURN_METHOD_SEND:begin
   if Request.MessageClass=RNL_STUN_CLASS_INDICATION then begin
    HandleSendIndication(aAddress,Request);
   end;
  end;
  else begin
   // Something this server has no business answering
  end;
 end;

end;

procedure TRNLTestTURNServer.Execute;
var Sockets:array of TRNLSocket;
    WaitConditions:TRNLSocketWaitConditions;
    Buffer:array[0..TRNLSTUNMessage.MaximumSize-1] of TRNLUInt8;
    CountSockets,Index,ReceivedSize,AllocationIndex:TRNLSizeInt;
    SenderAddress:TRNLAddress;
begin

 Sockets:=nil;

 if fSocket=RNL_SOCKET_NULL then begin
  exit;
 end;

 while not Terminated do begin

  // The control socket plus one per allocation, rebuilt every round because an allocation can come
  // and go while this runs
  fLock.Acquire;
  try
   // The datagram socket, the stream listener if there is one, one socket per allocation and one per
   // accepted stream
   SetLength(Sockets,(MaximumAllocations*2)+2);
   CountSockets:=0;
   Sockets[CountSockets]:=fSocket;
   inc(CountSockets);
   if fListenSocket<>RNL_SOCKET_NULL then begin
    Sockets[CountSockets]:=fListenSocket;
    inc(CountSockets);
   end;
   for Index:=0 to MaximumAllocations-1 do begin
    if fAllocations[Index].Used and (fAllocations[Index].Socket<>RNL_SOCKET_NULL) then begin
     Sockets[CountSockets]:=fAllocations[Index].Socket;
     inc(CountSockets);
    end;
   end;
   for Index:=0 to MaximumAllocations-1 do begin
    if fStreams[Index].Used and (fStreams[Index].Socket<>RNL_SOCKET_NULL) then begin
     Sockets[CountSockets]:=fStreams[Index].Socket;
     inc(CountSockets);
    end;
   end;
   SetLength(Sockets,CountSockets);
  finally
   fLock.Release;
  end;

  WaitConditions:=[RNL_SOCKET_WAIT_CONDITION_IO_RECEIVE];
  if not fNetwork.SocketWait(Sockets,WaitConditions,POLL_TIMEOUT_MILLISECONDS,nil) then begin
   break;
  end;

  if not (RNL_SOCKET_WAIT_CONDITION_IO_RECEIVE in WaitConditions) then begin
   continue;
  end;

  // Which of them had something is not reported, so every one of them is asked. They are all non
  // blocking, so an empty one costs nothing.
  fLock.Acquire;
  try

   ReceivedSize:=fNetwork.Receive(fSocket,@SenderAddress,Buffer,SizeOf(Buffer),RNL_IPV4);
   if ReceivedSize>0 then begin
    HandleFromClient(SenderAddress,Buffer,ReceivedSize);
   end;

   AcceptStreams;

   // Every accepted stream: read what there is, then take out whatever adds up to whole frames. A
   // stream which has died takes its allocation with it, because the client behind it is gone.
   for Index:=0 to MaximumAllocations-1 do begin
    if fStreams[Index].Used and (fStreams[Index].Socket<>RNL_SOCKET_NULL) then begin
     if PumpStream(Index) then begin
      while TakeFrame(Index,Buffer,SizeOf(Buffer),ReceivedSize) do begin
       HandleFromClient(fStreams[Index].Address,Buffer,ReceivedSize,fStreams[Index].Socket);
      end;
     end else begin
      ForgetStream(Index);
     end;
    end;
   end;

   for Index:=0 to MaximumAllocations-1 do begin
    if fAllocations[Index].Used and (fAllocations[Index].Socket<>RNL_SOCKET_NULL) then begin
     ReceivedSize:=fNetwork.Receive(fAllocations[Index].Socket,@SenderAddress,Buffer,SizeOf(Buffer),RNL_IPV4);
     if ReceivedSize>0 then begin
      AllocationIndex:=FindAllocationBySocket(fAllocations[Index].Socket);
      if AllocationIndex>=0 then begin
       HandleFromPeer(AllocationIndex,SenderAddress,Buffer,ReceivedSize);
      end;
     end;
    end;
   end;

  finally
   fLock.Release;
  end;

 end;

end;

end.
