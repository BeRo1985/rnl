(******************************************************************************
 *                      RNL TEST NETWORK FAULT INJECTOR                       *
 ******************************************************************************
 *                        Version 2026-07-27-00-00-0000                       *
 ******************************************************************************
 *                                                                            *
 * TRNLNetworkInterferenceSimulator simulates everything which can happen to a *
 * packet on its way, but it can not simulate anything which can happen to the *
 * local socket itself, and TRNLVirtualNetwork has neither a MTU nor a send     *
 * buffer which could ever fill up. That is precisely why a whole class of      *
 * defects only ever shows up in real world usage:                             *
 *                                                                            *
 *   TRNLRealNetwork.Send    -> 0  on EWOULDBLOCK / EMSGSIZE                   *
 *                           -> -1 on everything else                          *
 *   TRNLRealNetwork.Receive -> 0  on transient conditions                      *
 *                           -> -1 on a structurally broken socket             *
 *                                                                            *
 * TRNLVirtualNetwork.Send in contrast basically always returns aDataLength,    *
 * and TRNLNetworkInterferenceSimulator.Send even sets result:=aDataLength      *
 * unconditionally as soon as any latency or jitter is configured, so that the  *
 * whole send error handling is dead code in every simulator based test.        *
 *                                                                            *
 * This decorator closes exactly that gap. It is intentionally kept in the      *
 * tests directory and not in RNL.pas itself, since it is test tooling and not  *
 * library functionality.                                                      *
 *                                                                            *
 * All probability factors use the very same semantics as the ones of           *
 * TRNLNetworkInterferenceSimulator: 0 means never, $ffffffff means always, and *
 * everything in between is compared against a random 32 bit value, so that     *
 * $ffffffff div 2 is roughly 50 percent.                                      *
 *                                                                            *
 ******************************************************************************)
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

       fCountSoftSendFailures:TRNLUInt64;
       fCountHardSendFailures:TRNLUInt64;
       fCountSoftReceiveFailures:TRNLUInt64;
       fCountHardReceiveFailures:TRNLUInt64;
       fCountOversizedDatagrams:TRNLUInt64;
       fCountDeterministicallyDroppedDatagrams:TRNLUInt64;
       fCountRebindenSourceAddresses:TRNLUInt64;
       fCountDatagramsToStaleAddress:TRNLUInt64;

       function Roll(const aProbabilityFactor:TRNLUInt32):boolean;

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

procedure TRNLNetworkFaultInjector.StopRebindingSourceAddress;
begin
 fLock.Acquire;
 try
  fRebindEnabled:=false;
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
var DoDrop,DoRedirect:boolean;
    RedirectedAddress:TRNLAddress;
begin

 DoDrop:=false;
 DoRedirect:=false;

 if assigned(aAddress) then begin
  fLock.Acquire;
  try
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
