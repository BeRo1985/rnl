(*******************************************************************************
 *                         RNL TEST STUN SERVER                                *
 *******************************************************************************
 *                        Version 2026-07-27-00-00-0000                        *
 *******************************************************************************
 *                                                                             *
 * A STUN server just complete enough to answer a binding request, so that     *
 * TRNLSTUNClient can be tested against something deterministic instead of     *
 * against whatever a public server on the internet happens to do today.       *
 *                                                                             *
 * It runs in a thread of its own, which it has to: TRNLSTUNClient.Query is    *
 * blocking, so nobody could answer it from the same thread. That is safe here *
 * because TRNLVirtualNetwork locks around Send, Receive and SocketWait, and   *
 * releases the lock before it waits.                                          *
 *                                                                             *
 * The interesting part is not the correct answer but the wrong ones. A parser *
 * for datagrams from a stranger is exactly where length fields must not be    *
 * believed, and the only way to show that they are not is to send lengths     *
 * which lie. Every variant of TRNLTestSTUNServerBehaviour below is one such   *
 * lie, plus the two shapes a well behaved but old or chatty server produces.  *
 *                                                                             *
 *******************************************************************************)
unit RNLTestSTUNServer;
{$ifdef fpc}
 {$mode delphi}
{$endif}
{$h+}

interface

uses SysUtils,
     Classes,
     SyncObjs,
     RNL;

type TRNLTestSTUNServerBehaviour=
      (
       // A correct binding success response with XOR-MAPPED-ADDRESS and FINGERPRINT, reporting
       // the address the server was configured with
       RNL_TEST_STUN_SERVER_CORRECT,
       // The same, except that it reports the address the request actually came from, which is
       // what a real server does and what makes a NAT in between visible at all
       RNL_TEST_STUN_SERVER_REPORTING_SENDER,
       // Answers nothing at all, which is what an unreachable server looks like
       RNL_TEST_STUN_SERVER_SILENT,
       // Correct in every way except that the transaction ID is not the one which was asked
       RNL_TEST_STUN_SERVER_WRONG_TRANSACTION_ID,
       // Correct in every way except the fingerprint
       RNL_TEST_STUN_SERVER_WRONG_FINGERPRINT,
       // Announces an eight byte address value but sends only four of them
       RNL_TEST_STUN_SERVER_TRUNCATED_ATTRIBUTE,
       // Announces an attribute far longer than the whole datagram
       RNL_TEST_STUN_SERVER_ATTRIBUTE_LENGTH_BEYOND_DATAGRAM,
       // A message length which is not a multiple of four, which attributes always are
       RNL_TEST_STUN_SERVER_UNALIGNED_MESSAGE_LENGTH,
       // Only the plain MAPPED-ADDRESS, the way a server older than RFC 5389 answers
       RNL_TEST_STUN_SERVER_PLAIN_MAPPED_ADDRESS_ONLY,
       // An unknown comprehension required attribute ahead of the useful one
       RNL_TEST_STUN_SERVER_UNKNOWN_ATTRIBUTE_FIRST
      );

     TRNLTestSTUNServer=class(TThread)
      private

       fInstance:TRNLInstance;

       fNetwork:TRNLNetwork;

       fSocket:TRNLSocket;

       fBehaviour:TRNLTestSTUNServerBehaviour;

       // What the server claims to see the client at. A fixed value rather than the real source
       // address, so that a test can assert on it exactly and independently of how the network
       // underneath hands out addresses.
       fReportedAddress:TRNLAddress;

       fLock:TCriticalSection;

       fCountRequests:TRNLSizeInt;
       fCountAnswers:TRNLSizeInt;

       function GetCountRequests:TRNLSizeInt;
       function GetCountAnswers:TRNLSizeInt;

       class function ChecksumCRC32(const aLocation;const aSize:TRNLSizeUInt):TRNLUInt32; static;

       function BuildResponse(out aResponse;const aTransactionID;const aSenderAddress:TRNLAddress):TRNLSizeInt;

      protected

       procedure Execute; override;

      public

       // aBindHost decides which address the server is reachable at. Left at RNL_HOST_ANY it
       // lands on localhost, which is all a single server needs; telling two of them apart by
       // host is what NAT mapping detection asks for, and that needs concrete ones.
       constructor Create(const aInstance:TRNLInstance;
                          const aNetwork:TRNLNetwork;
                          const aPort:TRNLUInt16;
                          const aBehaviour:TRNLTestSTUNServerBehaviour;
                          const aReportedAddress:TRNLAddress;
                          const aBindHost:TRNLHostAddress); reintroduce; overload;
       constructor Create(const aInstance:TRNLInstance;
                          const aNetwork:TRNLNetwork;
                          const aPort:TRNLUInt16;
                          const aBehaviour:TRNLTestSTUNServerBehaviour;
                          const aReportedAddress:TRNLAddress); overload;
       destructor Destroy; override;

       property CountRequests:TRNLSizeInt read GetCountRequests;
       property CountAnswers:TRNLSizeInt read GetCountAnswers;

     end;

     // A server which can answer from somewhere other than where it was asked, which is what RFC 5780
     // needs and what makes the filtering behaviour of a nat determinable at all.
     //
     // Four sockets, exactly as the RFC describes: two addresses times two ports. A CHANGE-REQUEST
     // decides which of them the answer leaves from, OTHER-ADDRESS tells the client that there is a
     // second address, and RESPONSE-ORIGIN says where an answer actually came from.
     //
     // Built on TRNLSTUNMessage rather than by hand, unlike the server above: that one exists to
     // produce malformed answers and therefore has to lay out its own bytes, while this one only ever
     // sends correct ones and the message layer is pinned against the RFC 5769 vector.
     TRNLTestSTUNBehaviourServer=class(TThread)
      private

       type TRNLTestSTUNBehaviourSocket=record
             Socket:TRNLSocket;
             Address:TRNLAddress;
            end;

      private

       fInstance:TRNLInstance;

       fNetwork:TRNLNetwork;

       // Index 0 is primary address and primary port, 1 is primary address and alternate port,
       // 2 is alternate address and primary port, 3 is both alternate
       fSockets:array[0..3] of TRNLTestSTUNBehaviourSocket;

       // Off, no CHANGE-REQUEST is honoured and no OTHER-ADDRESS offered, which is what a server
       // without the extension looks like
       fSupportsChangeRequest:boolean;

       fLock:TCriticalSection;

       fCountRequests:TRNLSizeInt;
       fCountChangeRequests:TRNLSizeInt;
       fCountAnswersFromElsewhere:TRNLSizeInt;

       function BindSocket(const aIndex:TRNLSizeInt;const aAddress:TRNLAddress):boolean;

       function GetCountRequests:TRNLSizeInt;
       function GetCountChangeRequests:TRNLSizeInt;
       function GetCountAnswersFromElsewhere:TRNLSizeInt;

      protected

       procedure Execute; override;

      public

       constructor Create(const aInstance:TRNLInstance;
                          const aNetwork:TRNLNetwork;
                          const aPrimaryHost,aAlternateHost:TRNLHostAddress;
                          const aPrimaryPort,aAlternatePort:TRNLUInt16;
                          const aSupportsChangeRequest:boolean=true); reintroduce;
       destructor Destroy; override;

      published

       property CountRequests:TRNLSizeInt read GetCountRequests;
       property CountChangeRequests:TRNLSizeInt read GetCountChangeRequests;
       property CountAnswersFromElsewhere:TRNLSizeInt read GetCountAnswersFromElsewhere;

     end;

implementation

const POLL_TIMEOUT_MILLISECONDS=10;

      // Room for the largest response any behaviour below produces
      MAXIMUM_RESPONSE_SIZE=64;

constructor TRNLTestSTUNServer.Create(const aInstance:TRNLInstance;
                                      const aNetwork:TRNLNetwork;
                                      const aPort:TRNLUInt16;
                                      const aBehaviour:TRNLTestSTUNServerBehaviour;
                                      const aReportedAddress:TRNLAddress);
begin
 Create(aInstance,aNetwork,aPort,aBehaviour,aReportedAddress,RNL_HOST_ANY);
end;

constructor TRNLTestSTUNServer.Create(const aInstance:TRNLInstance;
                                      const aNetwork:TRNLNetwork;
                                      const aPort:TRNLUInt16;
                                      const aBehaviour:TRNLTestSTUNServerBehaviour;
                                      const aReportedAddress:TRNLAddress;
                                      const aBindHost:TRNLHostAddress);
var Address:TRNLAddress;
begin

 fInstance:=aInstance;
 fNetwork:=aNetwork;
 fBehaviour:=aBehaviour;
 fReportedAddress:=aReportedAddress;
 fCountRequests:=0;
 fCountAnswers:=0;

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

 inherited Create(false);

end;

destructor TRNLTestSTUNServer.Destroy;
begin
 Terminate;
 WaitFor;
 if fSocket<>RNL_SOCKET_NULL then begin
  fNetwork.SocketDestroy(fSocket);
  fSocket:=RNL_SOCKET_NULL;
 end;
 FreeAndNil(fLock);
 inherited Destroy;
end;

function TRNLTestSTUNServer.GetCountRequests:TRNLSizeInt;
begin
 fLock.Acquire;
 try
  result:=fCountRequests;
 finally
  fLock.Release;
 end;
end;

function TRNLTestSTUNServer.GetCountAnswers:TRNLSizeInt;
begin
 fLock.Acquire;
 try
  result:=fCountAnswers;
 finally
  fLock.Release;
 end;
end;

class function TRNLTestSTUNServer.ChecksumCRC32(const aLocation;const aSize:TRNLSizeUInt):TRNLUInt32;
const REVERSED_BIT_ORDER_POLYNOMIAL=TRNLUInt32($edb88320);
var Position,BitIndex:TRNLSizeUInt;
begin
 // CRC-32 in its IEEE form, which is what STUN's FINGERPRINT is defined in terms of. RNL has this
 // too, but in its implementation section, so it is not reachable from here.
 result:=$ffffffff;
 if aSize>0 then begin
  for Position:=0 to aSize-1 do begin
   result:=result xor PRNLUInt8Array(TRNLPointer(@aLocation))^[Position];
   for BitIndex:=0 to 7 do begin
    if (result and 1)<>0 then begin
     result:=(result shr 1) xor REVERSED_BIT_ORDER_POLYNOMIAL;
    end else begin
     result:=result shr 1;
    end;
   end;
  end;
 end;
 result:=not result;
end;

function TRNLTestSTUNServer.BuildResponse(out aResponse;const aTransactionID;const aSenderAddress:TRNLAddress):TRNLSizeInt;
var Data:PRNLUInt8Array;
    Position,AttributeSizeField,MessageLengthField:TRNLSizeInt;
    Fingerprint:TRNLUInt32;
    Index:TRNLSizeInt;
    XORMask:array[0..15] of TRNLUInt8;
    AddressAttributeType:TRNLUInt16;
    WithFingerprint:boolean;
    ReportedAddress:TRNLAddress;
begin

 if fBehaviour=RNL_TEST_STUN_SERVER_REPORTING_SENDER then begin
  ReportedAddress:=aSenderAddress;
 end else begin
  ReportedAddress:=fReportedAddress;
 end;

 Data:=@aResponse;
 FillChar(Data^[0],MAXIMUM_RESPONSE_SIZE,#0);

 TRNLMemoryAccess.StoreBigEndianUInt16(Data^[0],TRNLSTUNClient.MessageTypeBindingSuccessResponse);
 TRNLMemoryAccess.StoreBigEndianUInt32(Data^[4],TRNLSTUNClient.MagicCookie);
 Move(aTransactionID,Data^[8],TRNLSTUNClient.TransactionIDSize);

 if fBehaviour=RNL_TEST_STUN_SERVER_WRONG_TRANSACTION_ID then begin
  Data^[8]:=Data^[8] xor $ff;
 end;

 // The mask is the magic cookie followed by whatever transaction ID this response carries, so that
 // a wrong transaction ID stays the only thing that is wrong
 TRNLMemoryAccess.StoreBigEndianUInt32(XORMask[0],TRNLSTUNClient.MagicCookie);
 Move(Data^[8],XORMask[4],TRNLSTUNClient.TransactionIDSize);

 Position:=TRNLSTUNClient.HeaderSize;

 if fBehaviour=RNL_TEST_STUN_SERVER_UNKNOWN_ATTRIBUTE_FIRST then begin
  // 0x0009 is comprehension required and means nothing in a binding response, so a client has to
  // walk over it rather than give up
  TRNLMemoryAccess.StoreBigEndianUInt16(Data^[Position+0],TRNLUInt16($0009));
  TRNLMemoryAccess.StoreBigEndianUInt16(Data^[Position+2],4);
  TRNLMemoryAccess.StoreBigEndianUInt32(Data^[Position+4],TRNLUInt32($deadbeef));
  inc(Position,TRNLSTUNClient.AttributeHeaderSize+4);
 end;

 if fBehaviour=RNL_TEST_STUN_SERVER_PLAIN_MAPPED_ADDRESS_ONLY then begin
  AddressAttributeType:=TRNLSTUNClient.AttributeMappedAddress;
 end else begin
  AddressAttributeType:=TRNLSTUNClient.AttributeXORMappedAddress;
 end;

 AttributeSizeField:=8;
 if fBehaviour=RNL_TEST_STUN_SERVER_ATTRIBUTE_LENGTH_BEYOND_DATAGRAM then begin
  AttributeSizeField:=$fffc;
 end;

 TRNLMemoryAccess.StoreBigEndianUInt16(Data^[Position+0],AddressAttributeType);
 TRNLMemoryAccess.StoreBigEndianUInt16(Data^[Position+2],AttributeSizeField);
 Data^[Position+4]:=0;
 Data^[Position+5]:=TRNLSTUNClient.AddressFamilyIPV4;
 if AddressAttributeType=TRNLSTUNClient.AttributeXORMappedAddress then begin
  TRNLMemoryAccess.StoreBigEndianUInt16(Data^[Position+6],
                                        ReportedAddress.Port xor TRNLUInt16(TRNLSTUNClient.MagicCookie shr 16));
  for Index:=0 to 3 do begin
   Data^[Position+8+Index]:=ReportedAddress.Host.Addr[12+Index] xor XORMask[Index];
  end;
 end else begin
  TRNLMemoryAccess.StoreBigEndianUInt16(Data^[Position+6],ReportedAddress.Port);
  for Index:=0 to 3 do begin
   Data^[Position+8+Index]:=ReportedAddress.Host.Addr[12+Index];
  end;
 end;

 if fBehaviour=RNL_TEST_STUN_SERVER_TRUNCATED_ATTRIBUTE then begin
  // Still announces eight bytes of value, but stops after four of them
  inc(Position,TRNLSTUNClient.AttributeHeaderSize+4);
 end else begin
  inc(Position,TRNLSTUNClient.AttributeHeaderSize+8);
 end;

 WithFingerprint:=not (fBehaviour in [RNL_TEST_STUN_SERVER_TRUNCATED_ATTRIBUTE,
                                      RNL_TEST_STUN_SERVER_ATTRIBUTE_LENGTH_BEYOND_DATAGRAM,
                                      RNL_TEST_STUN_SERVER_UNALIGNED_MESSAGE_LENGTH]);

 if WithFingerprint then begin
  MessageLengthField:=(Position+TRNLSTUNClient.FingerprintAttributeSize)-TRNLSTUNClient.HeaderSize;
 end else begin
  MessageLengthField:=Position-TRNLSTUNClient.HeaderSize;
 end;

 if fBehaviour=RNL_TEST_STUN_SERVER_UNALIGNED_MESSAGE_LENGTH then begin
  // One byte of padding too many, announced as such, so the length stops being a multiple of four
  Data^[Position]:=0;
  inc(Position);
  inc(MessageLengthField);
 end;

 TRNLMemoryAccess.StoreBigEndianUInt16(Data^[2],MessageLengthField);

 if WithFingerprint then begin
  TRNLMemoryAccess.StoreBigEndianUInt16(Data^[Position+0],TRNLSTUNClient.AttributeFingerprint);
  TRNLMemoryAccess.StoreBigEndianUInt16(Data^[Position+2],4);
  Fingerprint:=ChecksumCRC32(Data^[0],Position) xor TRNLSTUNClient.FingerprintXORValue;
  if fBehaviour=RNL_TEST_STUN_SERVER_WRONG_FINGERPRINT then begin
   Fingerprint:=Fingerprint xor $ffffffff;
  end;
  TRNLMemoryAccess.StoreBigEndianUInt32(Data^[Position+4],Fingerprint);
  inc(Position,TRNLSTUNClient.FingerprintAttributeSize);
 end;

 result:=Position;

end;

procedure TRNLTestSTUNServer.Execute;
var Sockets:array[0..0] of TRNLSocket;
    WaitConditions:TRNLSocketWaitConditions;
    Request:array[0..TRNLSTUNClient.MaximumMessageSize-1] of TRNLUInt8;
    Response:array[0..MAXIMUM_RESPONSE_SIZE-1] of TRNLUInt8;
    RequestSize,ResponseSize:TRNLSizeInt;
    ClientAddress:TRNLAddress;
begin

 if fSocket=RNL_SOCKET_NULL then begin
  exit;
 end;

 Sockets[0]:=fSocket;

 while not Terminated do begin

  WaitConditions:=[RNL_SOCKET_WAIT_CONDITION_IO_RECEIVE];
  if not fNetwork.SocketWait(Sockets,WaitConditions,POLL_TIMEOUT_MILLISECONDS,nil) then begin
   break;
  end;

  if not (RNL_SOCKET_WAIT_CONDITION_IO_RECEIVE in WaitConditions) then begin
   continue;
  end;

  RequestSize:=fNetwork.Receive(fSocket,@ClientAddress,Request,SizeOf(Request),RNL_IPV4);
  if RequestSize<TRNLSizeInt(TRNLSTUNClient.HeaderSize) then begin
   continue;
  end;

  if (TRNLMemoryAccess.LoadBigEndianUInt16(Request[0])<>TRNLSTUNClient.MessageTypeBindingRequest) or
     (TRNLMemoryAccess.LoadBigEndianUInt32(Request[4])<>TRNLSTUNClient.MagicCookie) then begin
   continue;
  end;

  fLock.Acquire;
  try
   inc(fCountRequests);
  finally
   fLock.Release;
  end;

  if fBehaviour=RNL_TEST_STUN_SERVER_SILENT then begin
   continue;
  end;

  ResponseSize:=BuildResponse(Response,Request[8],ClientAddress);

  if fNetwork.Send(fSocket,@ClientAddress,Response,ResponseSize,RNL_IPV4)=ResponseSize then begin
   fLock.Acquire;
   try
    inc(fCountAnswers);
   finally
    fLock.Release;
   end;
  end;

 end;

end;


constructor TRNLTestSTUNBehaviourServer.Create(const aInstance:TRNLInstance;
                                               const aNetwork:TRNLNetwork;
                                               const aPrimaryHost,aAlternateHost:TRNLHostAddress;
                                               const aPrimaryPort,aAlternatePort:TRNLUInt16;
                                               const aSupportsChangeRequest:boolean=true);
var Index:TRNLSizeInt;
    Address:TRNLAddress;
begin

 fInstance:=aInstance;
 fNetwork:=aNetwork;
 fSupportsChangeRequest:=aSupportsChangeRequest;
 fCountRequests:=0;
 fCountChangeRequests:=0;
 fCountAnswersFromElsewhere:=0;

 fLock:=TCriticalSection.Create;

 for Index:=0 to 3 do begin
  fSockets[Index].Socket:=RNL_SOCKET_NULL;
 end;

 // Two addresses times two ports, which is what RFC 5780 wants of a server that is to be usable for
 // behaviour discovery
 for Index:=0 to 3 do begin
  FillChar(Address,SizeOf(TRNLAddress),#0);
  if (Index and 2)<>0 then begin
   Address.Host:=aAlternateHost;
  end else begin
   Address.Host:=aPrimaryHost;
  end;
  if (Index and 1)<>0 then begin
   Address.Port:=aAlternatePort;
  end else begin
   Address.Port:=aPrimaryPort;
  end;
  BindSocket(Index,Address);
 end;

 inherited Create(false);

end;

destructor TRNLTestSTUNBehaviourServer.Destroy;
var Index:TRNLSizeInt;
begin
 Terminate;
 WaitFor;
 for Index:=0 to 3 do begin
  if fSockets[Index].Socket<>RNL_SOCKET_NULL then begin
   fNetwork.SocketDestroy(fSockets[Index].Socket);
   fSockets[Index].Socket:=RNL_SOCKET_NULL;
  end;
 end;
 FreeAndNil(fLock);
 inherited Destroy;
end;

function TRNLTestSTUNBehaviourServer.BindSocket(const aIndex:TRNLSizeInt;const aAddress:TRNLAddress):boolean;
var Address:TRNLAddress;
begin
 result:=false;
 fSockets[aIndex].Address:=aAddress;
 fSockets[aIndex].Socket:=fNetwork.SocketCreate(RNL_SOCKET_TYPE_DATAGRAM,RNL_IPV4);
 if fSockets[aIndex].Socket<>RNL_SOCKET_NULL then begin
  Address:=aAddress;
  fNetwork.SocketSetOption(fSockets[aIndex].Socket,RNL_SOCKET_OPTION_NONBLOCK,1);
  fNetwork.SocketSetOption(fSockets[aIndex].Socket,RNL_SOCKET_OPTION_REUSEADDR,1);
  if fNetwork.SocketBind(fSockets[aIndex].Socket,@Address,RNL_IPV4) then begin
   result:=true;
  end else begin
   fNetwork.SocketDestroy(fSockets[aIndex].Socket);
   fSockets[aIndex].Socket:=RNL_SOCKET_NULL;
  end;
 end;
end;

function TRNLTestSTUNBehaviourServer.GetCountRequests:TRNLSizeInt;
begin
 fLock.Acquire;
 try
  result:=fCountRequests;
 finally
  fLock.Release;
 end;
end;

function TRNLTestSTUNBehaviourServer.GetCountChangeRequests:TRNLSizeInt;
begin
 fLock.Acquire;
 try
  result:=fCountChangeRequests;
 finally
  fLock.Release;
 end;
end;

function TRNLTestSTUNBehaviourServer.GetCountAnswersFromElsewhere:TRNLSizeInt;
begin
 fLock.Acquire;
 try
  result:=fCountAnswersFromElsewhere;
 finally
  fLock.Release;
 end;
end;

procedure TRNLTestSTUNBehaviourServer.Execute;
var Sockets:array of TRNLSocket;
    WaitConditions:TRNLSocketWaitConditions;
    Buffer:array[0..TRNLSTUNMessage.MaximumSize-1] of TRNLUInt8;
    Request,Response:TRNLSTUNMessage;
    Index,AnswerIndex,ReceivedSize:TRNLSizeInt;
    SenderAddress:TRNLAddress;
    ChangeFlags:TRNLUInt32;
begin

 Sockets:=nil;
 try

  SetLength(Sockets,4);
  for Index:=0 to 3 do begin
   Sockets[Index]:=fSockets[Index].Socket;
   if Sockets[Index]=RNL_SOCKET_NULL then begin
    exit;
   end;
  end;

  while not Terminated do begin

   WaitConditions:=[RNL_SOCKET_WAIT_CONDITION_IO_RECEIVE];
   if not fNetwork.SocketWait(Sockets,WaitConditions,POLL_TIMEOUT_MILLISECONDS,nil) then begin
    break;
   end;

   if not (RNL_SOCKET_WAIT_CONDITION_IO_RECEIVE in WaitConditions) then begin
    continue;
   end;

   // Which of them had something is not reported, so all four are asked. They are non blocking, so an
   // empty one costs nothing.
   for Index:=0 to 3 do begin

    ReceivedSize:=fNetwork.Receive(fSockets[Index].Socket,@SenderAddress,Buffer,SizeOf(Buffer),RNL_IPV4);
    if ReceivedSize<=0 then begin
     continue;
    end;

    if not Request.Assign(Buffer,ReceivedSize) then begin
     continue;
    end;

    if Request.MessageType<>(RNL_STUN_METHOD_BINDING or RNL_STUN_CLASS_REQUEST) then begin
     continue;
    end;

    fLock.Acquire;
    try
     inc(fCountRequests);
    finally
     fLock.Release;
    end;

    // Which socket the answer leaves from is the whole substance of RFC 5780: the bits say change the
    // address, the port, or both, and the answer coming from there at all is the information
    AnswerIndex:=Index;
    ChangeFlags:=0;
    if fSupportsChangeRequest and
       Request.ReadUInt32Attribute(RNL_STUN_ATTRIBUTE_CHANGE_REQUEST,ChangeFlags) and
       (ChangeFlags<>0) then begin
     fLock.Acquire;
     try
      inc(fCountChangeRequests);
     finally
      fLock.Release;
     end;
     if (ChangeFlags and RNL_STUN_CHANGE_REQUEST_PORT)<>0 then begin
      AnswerIndex:=AnswerIndex xor 1;
     end;
     if (ChangeFlags and RNL_STUN_CHANGE_REQUEST_IP)<>0 then begin
      AnswerIndex:=AnswerIndex xor 2;
     end;
    end;

    Response.Initialize(RNL_STUN_METHOD_BINDING or RNL_STUN_CLASS_SUCCESS_RESPONSE,Request.TransactionID);
    // What the server sees the sender as, which behind a nat is the translated address
    Response.AddXORAddressAttribute(RNL_STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,SenderAddress);
    // Where this answer is coming from, so a client can tell that it really did change
    Response.AddXORAddressAttribute(RNL_STUN_ATTRIBUTE_RESPONSE_ORIGIN,fSockets[AnswerIndex].Address);
    if fSupportsChangeRequest then begin
     // The other address and port, which is what says that asking for a change is worth trying
     Response.AddXORAddressAttribute(RNL_STUN_ATTRIBUTE_OTHER_ADDRESS,fSockets[Index xor 3].Address);
    end;
    Response.AddFingerprint;

    if Response.Valid and
       (fNetwork.Send(fSockets[AnswerIndex].Socket,@SenderAddress,
                      PRNLUInt8Array(Response.DataPointer)^[0],Response.Size,RNL_IPV4)=Response.Size) then begin
     if AnswerIndex<>Index then begin
      fLock.Acquire;
      try
       inc(fCountAnswersFromElsewhere);
      finally
       fLock.Release;
      end;
     end;
    end;

   end;

  end;

 finally
  Sockets:=nil;
 end;

end;

end.
