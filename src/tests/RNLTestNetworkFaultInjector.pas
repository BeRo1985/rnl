(********************************************************************************
 *                      RNL TEST NETWORK FAULT INJECTOR                         *
 ********************************************************************************
 *                        Version 2026-07-27-00-00-0000                         *
 ********************************************************************************
 *                                                                              *
 * TRNLNetworkInterferenceSimulator simulates everything which can happen to a  *
 * packet on its way, but it can not simulate anything which can happen to the  *
 * local socket itself, and TRNLVirtualNetwork has neither a MTU nor a send     *
 * buffer which could ever fill up. That is precisely why a whole class of      *
 * defects only ever shows up in real world usage:                              *
 *                                                                              *
 *   TRNLRealNetwork.Send    -> 0  on EWOULDBLOCK / EMSGSIZE                    *
 *                           -> -1 on everything else                           *
 *   TRNLRealNetwork.Receive -> 0  on transient conditions                      *
 *                           -> -1 on a structurally broken socket              *
 *                                                                              *
 * TRNLVirtualNetwork.Send in contrast basically always returns aDataLength,    *
 * and TRNLNetworkInterferenceSimulator.Send even sets result:=aDataLength      *
 * unconditionally as soon as any latency or jitter is configured, so that the  *
 * whole send error handling is dead code in every simulator based test.        *
 *                                                                              *
 * This decorator closes exactly that gap. It is intentionally kept in the      *
 * tests directory and not in RNL.pas itself, since it is test tooling and not  *
 * library functionality.                                                       *
 *                                                                              *
 * All probability factors use the very same semantics as the ones of           *
 * TRNLNetworkInterferenceSimulator: 0 means never, $ffffffff means always, and *
 * everything in between is compared against a random 32 bit value, so that     *
 * $ffffffff div 2 is roughly 50 percent.                                       *
 *                                                                              *
 ********************************************************************************)
unit RNLTestNetworkFaultInjector;
{$ifdef fpc}
 {$mode delphi}
{$endif}
{$h+}

interface

uses SysUtils,
     Classes,
     SyncObjs,
     RNL;

// Every handshake datagram has the same length regardless of its contents, because of the anti
// amplification padding, so any one of the packet records gives that length. The packet records
// themselves are public, which is what keeps this free of hard coded offsets: field positions
// are taken from the records and follow along automatically should the layout ever change.
//
// What is not reachable from here is RNL's ChecksumCRC32C, which lives in the implementation
// section, so the checksum has to be recomputed with a local copy of the algorithm.
const RNL_TEST_HANDSHAKE_PACKET_SIZE=SizeOf(TRNLProtocolHandshakePacketConnectionRequest);

      // Long enough for any single scalar field which is worth manipulating
      RNL_TEST_MAXIMUM_REWRITE_LENGTH=16;

type TRNLNetworkFaultInjector=class(TRNLNetwork)
      private

       fNetwork:TRNLNetwork;

       fLock:TCriticalSection;

       fRandomGenerator:TRNLRandomGenerator;

       // Send returns 0, as TRNLRealNetwork.Send does on EWOULDBLOCK / ENOBUFS / EMSGSIZE
       fSoftSendFailureProbabilityFactor:TRNLUInt32;

       // Send returns -1, as TRNLRealNetwork.Send does on any other errno
       fHardSendFailureProbabilityFactor:TRNLUInt32;

       // Receive returns 0 although a datagram was there, as TRNLRealNetwork.Receive does
       // whenever an ICMP error got queued onto the socket
       fSoftReceiveFailureProbabilityFactor:TRNLUInt32;

       // Receive returns -1, as TRNLRealNetwork.Receive does for a broken socket
       fHardReceiveFailureProbabilityFactor:TRNLUInt32;

       // Datagrams above this size are rejected with a soft send failure, which is what a
       // real socket does with EMSGSIZE once the datagram exceeds the path MTU. Zero means
       // no limit at all, which is the TRNLVirtualNetwork behaviour.
       fMaximumDatagramSize:TRNLSizeUInt;

       // Deterministic, as opposed to probabilistic, outgoing packet loss, so that a test
       // can lose one exactly known datagram and then measure what the retransmission
       // actually costs
       fCountOutgoingDatagramsToDrop:TRNLSizeInt;
       fMinimumSizeOfOutgoingDatagramsToDrop:TRNLSizeUInt;
       fRestrictDropToAddress:boolean;
       fDropToAddress:TRNLAddress;

       // Rewrites the source address of every datagram coming from fRebindFromAddress, which is
       // what a NAT rebinding, a carrier grade NAT reassigning its ports, or a handover between
       // networks looks like from the far side
       fRebindEnabled:boolean;
       fRebindFromAddress:TRNLAddress;
       fRebindToAddress:TRNLAddress;

       // Overwrites one field of every outgoing handshake packet of one particular type. This is
       // what it takes to test whether a field is authenticated at all: a field which nothing
       // covers can be changed in flight without the handshake noticing, and the only way to
       // show that is to change it.
       fRewriteEnabled:boolean;
       fRewritePacketType:TRNLUInt8;
       fRewriteOffset:TRNLSizeUInt;
       fRewriteLength:TRNLSizeUInt;
       fRewriteValue:array[0..RNL_TEST_MAXIMUM_REWRITE_LENGTH-1] of TRNLUInt8;

       fCountSoftSendFailures:TRNLUInt64;
       fCountHardSendFailures:TRNLUInt64;
       fCountSoftReceiveFailures:TRNLUInt64;
       fCountHardReceiveFailures:TRNLUInt64;
       fCountOversizedDatagrams:TRNLUInt64;
       fCountDeterministicallyDroppedDatagrams:TRNLUInt64;
       fCountRebindenSourceAddresses:TRNLUInt64;

       // Which source addresses datagrams towards one particular destination have left from.
       // With one socket per address family that is always one; with one socket per interface it is
       // as many as were actually paired with that destination, which is the only way to see the
       // fan out from the outside.
       fObserveSourcesEnabled:boolean;
       fObserveSourcesToAddress:TRNLAddress;
       fObservedSourceAddresses:array of TRNLAddress;
       fCountDatagramsToStaleAddress:TRNLUInt64;
       fCountRewrittenHandshakePackets:TRNLUInt64;

       function Roll(const aProbabilityFactor:TRNLUInt32):boolean;
       procedure RememberSourceAddress(const aSocket:TRNLSocket);

       class function HandshakePacketChecksum(const aData;const aDataLength:TRNLSizeUInt):TRNLUInt32; static;

      public

       constructor Create(const aInstance:TRNLInstance;const aNetwork:TRNLNetwork); reintroduce;
       destructor Destroy; override;

       procedure ResetCounters;

       // Silently discards the next aCount outgoing datagrams of at least aMinimumSize
       // bytes, while still reporting a successful send, so that this behaves like ordinary
       // loss somewhere on the way and not like a local socket failure. The size threshold
       // keeps the small keep alive and acknowledgement datagrams out of the way, so that a
       // test can target its own payload carrying datagrams precisely.
       procedure DropNextOutgoingDatagrams(const aCount:TRNLSizeInt;
                                           const aMinimumSize:TRNLSizeUInt=0);

       // The same, but restricted to datagrams headed for one particular address. Since both
       // hosts of a test share one network, the destination address is what tells the two
       // directions apart, and that is what it takes to lose an acknowledgement of one side
       // without touching the payload of the other.
       procedure DropNextOutgoingDatagramsToAddress(const aAddress:TRNLAddress;
                                                    const aCount:TRNLSizeInt;
                                                    const aMinimumSize:TRNLSizeUInt=0);

       // Models a complete address change of one side, the way a NAT rebinding or a network
       // handover really behaves, which needs all three of these at once:
       //   every datagram arriving from aFromAddress appears to come from aToAddress instead,
       //   every datagram sent towards aToAddress is delivered to aFromAddress, and
       //   every datagram sent towards aFromAddress is lost, because that mapping is gone.
       // The last one is what makes the difference observable at all. Without it the old address
       // stays reachable and a counter side which never notices the change keeps working by
       // accident, which is precisely the situation a real network does not offer.
       // The datagram payload is never touched, so it still passes its authentication.
       procedure RebindSourceAddress(const aFromAddress,aToAddress:TRNLAddress);
       procedure StopRebindingSourceAddress;
       // Starts remembering the distinct source addresses of everything sent towards that address
       procedure ObserveOutgoingSourceAddressesTo(const aAddress:TRNLAddress);
       procedure StopObservingOutgoingSourceAddresses;
       function CountDistinctObservedSourceAddresses:TRNLSizeInt;
       function ObservedSourceAddress(const aIndex:TRNLSizeInt):TRNLAddress;

       // Overwrites aValueLength bytes at aOffset in every outgoing handshake packet whose type
       // is aPacketType, and recomputes the packet checksum afterwards.
       //
       // Repairing the checksum is the whole point. Without it the counter side would discard the
       // datagram at its checksum check and never look at the manipulated field, so the test
       // would prove that a corrupted datagram gets dropped, which nobody doubts, instead of
       // whether that particular field is authenticated. With the checksum repaired, the only
       // thing standing between the manipulation and a completed handshake is whatever really
       // covers the field.
       procedure RewriteOutgoingHandshakeField(const aPacketType:TRNLUInt8;
                                               const aOffset:TRNLSizeUInt;
                                               const aValue;
                                               const aValueLength:TRNLSizeUInt);
       procedure StopRewritingOutgoingHandshakeFields;

       function AddressSetHost(var aAddress:TRNLAddress;const aName:TRNLRawByteString):boolean; override;
       function AddressGetHost(const aAddress:TRNLAddress;out aName;const aNameLength:TRNLInt32;const aFlags:TRNLInt32=0):boolean; override;
       function AddressGetHostIP(const aAddress:TRNLAddress;out aName;const aNameLength:TRNLInt32):boolean; override;
       function SocketCreate(const aType:TRNLSocketType;const aFamily:TRNLAddressFamily):TRNLSocket; override;
       procedure SocketDestroy(const aSocket:TRNLSocket); override;
       function SocketShutdown(const aSocket:TRNLSocket;const aHow:TRNLSocketShutdown=RNL_SOCKET_SHUTDOWN_READ_WRITE):boolean; override;
       function SocketGetAddress(const aSocket:TRNLSocket;out aAddress:TRNLAddress;const aFamily:TRNLAddressFamily):boolean; override;
       function SocketSetOption(const aSocket:TRNLSocket;const aOption:TRNLSocketOption;const aValue:TRNLInt32):boolean; override;
       function SocketGetOption(const aSocket:TRNLSocket;const aOption:TRNLSocketOption;out aValue:TRNLInt32):boolean; override;
       function SocketBind(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aFamily:TRNLAddressFamily):boolean; override;
       function SocketListen(const aSocket:TRNLSocket;const aBackLog:TRNLInt32):boolean; override;
       function SocketConnect(const aSocket:TRNLSocket;const aAddress:TRNLAddress;const aFamily:TRNLAddressFamily):boolean; override;
       function SocketAccept(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aFamily:TRNLAddressFamily):TRNLSocket; override;
       function SocketSelect(const aMaxSocket:TRNLSocket;var aReadSet,aWriteSet:TRNLSocketSet;const aTimeout:TRNLInt64;const aEvent:TRNLNetworkEvent=nil):TRNLInt32; override;
       function SocketWait(const aSockets:array of TRNLSocket;var aConditions:TRNLSocketWaitConditions;const aTimeout:TRNLInt64;const aEvent:TRNLNetworkEvent=nil):boolean; override;
       function Send(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aData;const aDataLength:TRNLSizeInt;const aFamily:TRNLAddressFamily):TRNLSizeInt; override;
       function Receive(const aSocket:TRNLSocket;const aAddress:PRNLAddress;out aData;const aDataLength:TRNLSizeInt;const aFamily:TRNLAddressFamily):TRNLSizeInt; override;

      published

       property SoftSendFailureProbabilityFactor:TRNLUInt32 read fSoftSendFailureProbabilityFactor write fSoftSendFailureProbabilityFactor;
       property HardSendFailureProbabilityFactor:TRNLUInt32 read fHardSendFailureProbabilityFactor write fHardSendFailureProbabilityFactor;
       property SoftReceiveFailureProbabilityFactor:TRNLUInt32 read fSoftReceiveFailureProbabilityFactor write fSoftReceiveFailureProbabilityFactor;
       property HardReceiveFailureProbabilityFactor:TRNLUInt32 read fHardReceiveFailureProbabilityFactor write fHardReceiveFailureProbabilityFactor;
       property MaximumDatagramSize:TRNLSizeUInt read fMaximumDatagramSize write fMaximumDatagramSize;

       property CountSoftSendFailures:TRNLUInt64 read fCountSoftSendFailures;
       property CountHardSendFailures:TRNLUInt64 read fCountHardSendFailures;
       property CountSoftReceiveFailures:TRNLUInt64 read fCountSoftReceiveFailures;
       property CountHardReceiveFailures:TRNLUInt64 read fCountHardReceiveFailures;
       property CountOversizedDatagrams:TRNLUInt64 read fCountOversizedDatagrams;
       property CountDeterministicallyDroppedDatagrams:TRNLUInt64 read fCountDeterministicallyDroppedDatagrams;
       property CountRebindenSourceAddresses:TRNLUInt64 read fCountRebindenSourceAddresses;
       property CountDatagramsToStaleAddress:TRNLUInt64 read fCountDatagramsToStaleAddress;
       property CountRewrittenHandshakePackets:TRNLUInt64 read fCountRewrittenHandshakePackets;

     end;

implementation

constructor TRNLNetworkFaultInjector.Create(const aInstance:TRNLInstance;const aNetwork:TRNLNetwork);
begin

 inherited Create(aInstance);

 fNetwork:=aNetwork;

 fLock:=TCriticalSection.Create;

 fRandomGenerator:=TRNLRandomGenerator.Create;

 fSoftSendFailureProbabilityFactor:=0;
 fHardSendFailureProbabilityFactor:=0;
 fSoftReceiveFailureProbabilityFactor:=0;
 fHardReceiveFailureProbabilityFactor:=0;

 fMaximumDatagramSize:=0;

 fCountOutgoingDatagramsToDrop:=0;
 fMinimumSizeOfOutgoingDatagramsToDrop:=0;
 fRestrictDropToAddress:=false;

 fRebindEnabled:=false;

 fRewriteEnabled:=false;
 fRewritePacketType:=0;
 fRewriteOffset:=0;
 fRewriteLength:=0;

 ResetCounters;

end;

destructor TRNLNetworkFaultInjector.Destroy;
begin
 FreeAndNil(fRandomGenerator);
 FreeAndNil(fLock);
 inherited Destroy;
end;

procedure TRNLNetworkFaultInjector.ResetCounters;
begin
 fLock.Acquire;
 try
  fCountSoftSendFailures:=0;
  fCountHardSendFailures:=0;
  fCountSoftReceiveFailures:=0;
  fCountHardReceiveFailures:=0;
  fCountOversizedDatagrams:=0;
  fCountDeterministicallyDroppedDatagrams:=0;
  fCountRebindenSourceAddresses:=0;
  fCountDatagramsToStaleAddress:=0;
  fCountRewrittenHandshakePackets:=0;
 finally
  fLock.Release;
 end;
end;

procedure TRNLNetworkFaultInjector.DropNextOutgoingDatagrams(const aCount:TRNLSizeInt;
                                                             const aMinimumSize:TRNLSizeUInt=0);
begin
 fLock.Acquire;
 try
  fCountOutgoingDatagramsToDrop:=aCount;
  fMinimumSizeOfOutgoingDatagramsToDrop:=aMinimumSize;
  fRestrictDropToAddress:=false;
 finally
  fLock.Release;
 end;
end;

procedure TRNLNetworkFaultInjector.DropNextOutgoingDatagramsToAddress(const aAddress:TRNLAddress;
                                                                      const aCount:TRNLSizeInt;
                                                                      const aMinimumSize:TRNLSizeUInt=0);
begin
 fLock.Acquire;
 try
  fCountOutgoingDatagramsToDrop:=aCount;
  fMinimumSizeOfOutgoingDatagramsToDrop:=aMinimumSize;
  fDropToAddress:=aAddress;
  fRestrictDropToAddress:=true;
 finally
  fLock.Release;
 end;
end;

procedure TRNLNetworkFaultInjector.RebindSourceAddress(const aFromAddress,aToAddress:TRNLAddress);
begin
 fLock.Acquire;
 try
  fRebindFromAddress:=aFromAddress;
  fRebindToAddress:=aToAddress;
  fRebindEnabled:=true;
 finally
  fLock.Release;
 end;
end;

// Asks the network underneath what that socket is bound to, which is the source address the far
// side is going to see. Called with the lock already held.
procedure TRNLNetworkFaultInjector.RememberSourceAddress(const aSocket:TRNLSocket);
var SourceAddress:TRNLAddress;
    Index,Count:TRNLSizeInt;
begin
 if not fNetwork.SocketGetAddress(aSocket,SourceAddress,RNL_IPV4) then begin
  exit;
 end;
 for Index:=0 to length(fObservedSourceAddresses)-1 do begin
  if fObservedSourceAddresses[Index].Equals(SourceAddress) then begin
   exit;
  end;
 end;
 Count:=length(fObservedSourceAddresses);
 SetLength(fObservedSourceAddresses,Count+1);
 fObservedSourceAddresses[Count]:=SourceAddress;
end;

procedure TRNLNetworkFaultInjector.ObserveOutgoingSourceAddressesTo(const aAddress:TRNLAddress);
begin
 fLock.Acquire;
 try
  fObserveSourcesToAddress:=aAddress;
  fObservedSourceAddresses:=nil;
  fObserveSourcesEnabled:=true;
 finally
  fLock.Release;
 end;
end;

procedure TRNLNetworkFaultInjector.StopObservingOutgoingSourceAddresses;
begin
 fLock.Acquire;
 try
  fObserveSourcesEnabled:=false;
 finally
  fLock.Release;
 end;
end;

function TRNLNetworkFaultInjector.CountDistinctObservedSourceAddresses:TRNLSizeInt;
begin
 fLock.Acquire;
 try
  result:=length(fObservedSourceAddresses);
 finally
  fLock.Release;
 end;
end;

function TRNLNetworkFaultInjector.ObservedSourceAddress(const aIndex:TRNLSizeInt):TRNLAddress;
begin
 fLock.Acquire;
 try
  if (aIndex>=0) and (aIndex<length(fObservedSourceAddresses)) then begin
   result:=fObservedSourceAddresses[aIndex];
  end else begin
   FillChar(result,SizeOf(TRNLAddress),#0);
  end;
 finally
  fLock.Release;
 end;
end;

procedure TRNLNetworkFaultInjector.StopRebindingSourceAddress;
begin
 fLock.Acquire;
 try
  fRebindEnabled:=false;
 finally
  fLock.Release;
 end;
end;

class function TRNLNetworkFaultInjector.HandshakePacketChecksum(const aData;const aDataLength:TRNLSizeUInt):TRNLUInt32;
const REVERSED_BIT_ORDER_POLYNOMIAL=TRNLUInt32($82f63b78);
var Position,BitIndex:TRNLSizeUInt;
begin
 // CRC-32C, the very same one RNL uses for its handshake packets: initial value all ones, the
 // Castagnoli polynomial in reversed bit order, final complement. Written out bit by bit rather
 // than with a table, since it runs a handful of times per test and clarity is worth more here
 // than speed.
 result:=$ffffffff;
 if aDataLength>0 then begin
  for Position:=0 to aDataLength-1 do begin
   result:=result xor PRNLUInt8Array(TRNLPointer(@aData))^[Position];
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

procedure TRNLNetworkFaultInjector.RewriteOutgoingHandshakeField(const aPacketType:TRNLUInt8;
                                                                 const aOffset:TRNLSizeUInt;
                                                                 const aValue;
                                                                 const aValueLength:TRNLSizeUInt);
begin
 if (aValueLength=0) or
    (aValueLength>RNL_TEST_MAXIMUM_REWRITE_LENGTH) or
    ((aOffset+aValueLength)>RNL_TEST_HANDSHAKE_PACKET_SIZE) then begin
  raise ERangeError.Create('RewriteOutgoingHandshakeField: field does not fit into a handshake packet');
 end;
 fLock.Acquire;
 try
  fRewritePacketType:=aPacketType;
  fRewriteOffset:=aOffset;
  fRewriteLength:=aValueLength;
  Move(aValue,fRewriteValue[0],aValueLength);
  fRewriteEnabled:=true;
 finally
  fLock.Release;
 end;
end;

procedure TRNLNetworkFaultInjector.StopRewritingOutgoingHandshakeFields;
begin
 fLock.Acquire;
 try
  fRewriteEnabled:=false;
 finally
  fLock.Release;
 end;
end;

function TRNLNetworkFaultInjector.Roll(const aProbabilityFactor:TRNLUInt32):boolean;
begin
 case aProbabilityFactor of
  0:begin
   result:=false;
  end;
  TRNLUInt32($ffffffff):begin
   result:=true;
  end;
  else begin
   fLock.Acquire;
   try
    result:=fRandomGenerator.GetUInt32<aProbabilityFactor;
   finally
    fLock.Release;
   end;
  end;
 end;
end;

function TRNLNetworkFaultInjector.AddressSetHost(var aAddress:TRNLAddress;const aName:TRNLRawByteString):boolean;
begin
 result:=fNetwork.AddressSetHost(aAddress,aName);
end;

function TRNLNetworkFaultInjector.AddressGetHost(const aAddress:TRNLAddress;out aName;const aNameLength:TRNLInt32;const aFlags:TRNLInt32=0):boolean;
begin
 result:=fNetwork.AddressGetHost(aAddress,aName,aNameLength,aFlags);
end;

function TRNLNetworkFaultInjector.AddressGetHostIP(const aAddress:TRNLAddress;out aName;const aNameLength:TRNLInt32):boolean;
begin
 result:=fNetwork.AddressGetHostIP(aAddress,aName,aNameLength);
end;

function TRNLNetworkFaultInjector.SocketCreate(const aType:TRNLSocketType;const aFamily:TRNLAddressFamily):TRNLSocket;
begin
 result:=fNetwork.SocketCreate(aType,aFamily);
end;

procedure TRNLNetworkFaultInjector.SocketDestroy(const aSocket:TRNLSocket);
begin
 fNetwork.SocketDestroy(aSocket);
end;

function TRNLNetworkFaultInjector.SocketShutdown(const aSocket:TRNLSocket;const aHow:TRNLSocketShutdown=RNL_SOCKET_SHUTDOWN_READ_WRITE):boolean;
begin
 result:=fNetwork.SocketShutdown(aSocket,aHow);
end;

function TRNLNetworkFaultInjector.SocketGetAddress(const aSocket:TRNLSocket;out aAddress:TRNLAddress;const aFamily:TRNLAddressFamily):boolean;
begin
 result:=fNetwork.SocketGetAddress(aSocket,aAddress,aFamily);
end;

function TRNLNetworkFaultInjector.SocketSetOption(const aSocket:TRNLSocket;const aOption:TRNLSocketOption;const aValue:TRNLInt32):boolean;
begin
 result:=fNetwork.SocketSetOption(aSocket,aOption,aValue);
end;

function TRNLNetworkFaultInjector.SocketGetOption(const aSocket:TRNLSocket;const aOption:TRNLSocketOption;out aValue:TRNLInt32):boolean;
begin
 result:=fNetwork.SocketGetOption(aSocket,aOption,aValue);
end;

function TRNLNetworkFaultInjector.SocketBind(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aFamily:TRNLAddressFamily):boolean;
begin
 result:=fNetwork.SocketBind(aSocket,aAddress,aFamily);
end;

function TRNLNetworkFaultInjector.SocketListen(const aSocket:TRNLSocket;const aBackLog:TRNLInt32):boolean;
begin
 result:=fNetwork.SocketListen(aSocket,aBackLog);
end;

function TRNLNetworkFaultInjector.SocketConnect(const aSocket:TRNLSocket;const aAddress:TRNLAddress;const aFamily:TRNLAddressFamily):boolean;
begin
 result:=fNetwork.SocketConnect(aSocket,aAddress,aFamily);
end;

function TRNLNetworkFaultInjector.SocketAccept(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aFamily:TRNLAddressFamily):TRNLSocket;
begin
 result:=fNetwork.SocketAccept(aSocket,aAddress,aFamily);
end;

function TRNLNetworkFaultInjector.SocketSelect(const aMaxSocket:TRNLSocket;var aReadSet,aWriteSet:TRNLSocketSet;const aTimeout:TRNLInt64;const aEvent:TRNLNetworkEvent=nil):TRNLInt32;
begin
 result:=fNetwork.SocketSelect(aMaxSocket,aReadSet,aWriteSet,aTimeout,aEvent);
end;

function TRNLNetworkFaultInjector.SocketWait(const aSockets:array of TRNLSocket;var aConditions:TRNLSocketWaitConditions;const aTimeout:TRNLInt64;const aEvent:TRNLNetworkEvent=nil):boolean;
begin
 result:=fNetwork.SocketWait(aSockets,aConditions,aTimeout,aEvent);
end;

function TRNLNetworkFaultInjector.Send(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aData;const aDataLength:TRNLSizeInt;const aFamily:TRNLAddressFamily):TRNLSizeInt;
var DoDrop,DoRedirect,DoRewrite:boolean;
    RedirectedAddress:TRNLAddress;
    RewrittenPacket:array[0..RNL_TEST_HANDSHAKE_PACKET_SIZE-1] of TRNLUInt8;
    IncomingHeader,RewrittenHeader:PRNLProtocolHandshakePacketHeader;
begin

 DoDrop:=false;
 DoRedirect:=false;
 DoRewrite:=false;

 if assigned(aAddress) then begin
  fLock.Acquire;
  try
   if fObserveSourcesEnabled and aAddress^.Equals(fObserveSourcesToAddress) then begin
    RememberSourceAddress(aSocket);
   end;
   if fRebindEnabled then begin
    if aAddress^.Equals(fRebindToAddress) then begin
     // Towards the new address, so deliver it to the socket which really sits behind it
     RedirectedAddress:=fRebindFromAddress;
     DoRedirect:=true;
    end else if aAddress^.Equals(fRebindFromAddress) then begin
     // Towards the stale address, whose mapping no longer exists
     inc(fCountDatagramsToStaleAddress);
     DoDrop:=true;
    end;
   end;
  finally
   fLock.Release;
  end;
 end;

 if DoDrop then begin
  // Lost, because nothing is listening behind that mapping any more
  result:=aDataLength;
  exit;
 end;

 if DoRedirect then begin
  result:=fNetwork.Send(aSocket,@RedirectedAddress,aData,aDataLength,aFamily);
  exit;
 end;

 fLock.Acquire;
 try
  if (fCountOutgoingDatagramsToDrop>0) and
     (aDataLength>=TRNLSizeInt(fMinimumSizeOfOutgoingDatagramsToDrop)) and
     ((not fRestrictDropToAddress) or
      (assigned(aAddress) and aAddress^.Equals(fDropToAddress))) then begin
   dec(fCountOutgoingDatagramsToDrop);
   inc(fCountDeterministicallyDroppedDatagrams);
   DoDrop:=true;
  end;
 finally
  fLock.Release;
 end;

 if DoDrop then begin
  // Lost somewhere on the way, so the send itself has to look entirely successful
  result:=aDataLength;
  exit;
 end;

 if (fMaximumDatagramSize>0) and
    (aDataLength>TRNLSizeInt(fMaximumDatagramSize)) then begin
  // EMSGSIZE
  fLock.Acquire;
  try
   inc(fCountOversizedDatagrams);
   inc(fCountSoftSendFailures);
  finally
   fLock.Release;
  end;
  result:=0;
  exit;
 end;

 if Roll(fHardSendFailureProbabilityFactor) then begin
  fLock.Acquire;
  try
   inc(fCountHardSendFailures);
  finally
   fLock.Release;
  end;
  result:=-1;
  exit;
 end;

 if Roll(fSoftSendFailureProbabilityFactor) then begin
  fLock.Acquire;
  try
   inc(fCountSoftSendFailures);
  finally
   fLock.Release;
  end;
  result:=0;
  exit;
 end;

 fLock.Acquire;
 try
  // A handshake datagram is recognised the same way RNL itself recognises it, by the signature in
  // its header, plus the fixed length which the anti amplification padding gives every one of them
  IncomingHeader:=PRNLProtocolHandshakePacketHeader(TRNLPointer(@aData));
  DoRewrite:=fRewriteEnabled and
             (aDataLength=TRNLSizeInt(RNL_TEST_HANDSHAKE_PACKET_SIZE)) and
             (IncomingHeader^.Signature[0]=TRNLUInt8(ord('R'))) and
             (IncomingHeader^.Signature[1]=TRNLUInt8(ord('N'))) and
             (IncomingHeader^.Signature[2]=TRNLUInt8(ord('L'))) and
             (IncomingHeader^.Signature[3]=TRNLUInt8($ff)) and
             (IncomingHeader^.PacketType=fRewritePacketType);
  if DoRewrite then begin
   Move(aData,RewrittenPacket[0],RNL_TEST_HANDSHAKE_PACKET_SIZE);
   Move(fRewriteValue[0],RewrittenPacket[fRewriteOffset],fRewriteLength);
   inc(fCountRewrittenHandshakePackets);
  end;
 finally
  fLock.Release;
 end;

 if DoRewrite then begin
  // The checksum covers the whole datagram with its own field zeroed, so it has to be redone
  // after the patch, exactly as TRNLHost.AddHandshakePacketChecksum does it
  RewrittenHeader:=PRNLProtocolHandshakePacketHeader(TRNLPointer(@RewrittenPacket[0]));
  RewrittenHeader^.Checksum:=0;
  RewrittenHeader^.Checksum:=HandshakePacketChecksum(RewrittenPacket[0],RNL_TEST_HANDSHAKE_PACKET_SIZE);
  result:=fNetwork.Send(aSocket,aAddress,RewrittenPacket[0],aDataLength,aFamily);
  exit;
 end;

 result:=fNetwork.Send(aSocket,aAddress,aData,aDataLength,aFamily);

end;

function TRNLNetworkFaultInjector.Receive(const aSocket:TRNLSocket;const aAddress:PRNLAddress;out aData;const aDataLength:TRNLSizeInt;const aFamily:TRNLAddressFamily):TRNLSizeInt;
begin

 if Roll(fHardReceiveFailureProbabilityFactor) then begin
  fLock.Acquire;
  try
   inc(fCountHardReceiveFailures);
  finally
   fLock.Release;
  end;
  result:=-1;
  exit;
 end;

 result:=fNetwork.Receive(aSocket,aAddress,aData,aDataLength,aFamily);

 // Only a datagram which really was there can be dropped, otherwise this would just be an
 // ordinary empty receive anyway and would not test anything at all
 if (result>0) and Roll(fSoftReceiveFailureProbabilityFactor) then begin
  fLock.Acquire;
  try
   inc(fCountSoftReceiveFailures);
  finally
   fLock.Release;
  end;
  result:=0;
 end;

 if (result>0) and assigned(aAddress) then begin
  fLock.Acquire;
  try
   if fRebindEnabled and aAddress^.Equals(fRebindFromAddress) then begin
    aAddress^:=fRebindToAddress;
    inc(fCountRebindenSourceAddresses);
   end;
  finally
   fLock.Release;
  end;
 end;

end;

end.
