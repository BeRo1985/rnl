(********************************************************************************
 *                        RNL TEST NETWORK BOTTLENECK                           *
 ********************************************************************************
 *                        Version 2026-07-28-00-00-0000                         *
 ********************************************************************************
 *                                                                              *
 * The existing simulators PRESCRIBE delay and loss: TRNLNetworkInterference-   *
 * Simulator is told a latency and adds it to every datagram, and it is told a  *
 * loss probability and rolls a die. Neither of the two numbers has anything to *
 * do with how much is being sent.                                              *
 *                                                                              *
 * A congestion controller reacts to the exact opposite: to a queue which       *
 * ARISES from its own sending rate, and to loss which happens because that     *
 * queue ran full. Against a prescribed latency there is nothing to control,    *
 * and a prescribed loss probability punishes every rate equally, so no         *
 * controller can be told apart from any other one. That is the gap this        *
 * decorator closes, and until it exists, no statement about a controller is    *
 * verifiable.                                                                  *
 *                                                                              *
 * The model is a link with a drain rate and a queue of finite depth:           *
 *                                                                              *
 *   - Each datagram occupies the link for size / drain rate seconds.           *
 *   - A datagram which arrives while the link is still busy waits, and its     *
 *     waiting time is the queueing delay a controller can measure as a rise    *
 *     of the round trip time above its minimum.                                *
 *   - When the queue is full, the arriving datagram is dropped at the tail.    *
 *     The SENDER still sees a successful send, because a datagram which is     *
 *     discarded somewhere downstream is indistinguishable from one which was   *
 *     handed over to the network - which is precisely the situation a real     *
 *     bottleneck creates.                                                      *
 *                                                                              *
 * The depth is expressible in bytes and in milliseconds, and both matter: a    *
 * home router with a deep buffer is the bufferbloat case, where delay grows    *
 * for a long time before anything is lost, and a router with a shallow one is  *
 * the modern case, where loss arrives early and delay stays low. A controller  *
 * which only works against one of the two is not a controller.                 *
 *                                                                              *
 * Cross traffic is modelled as a share of the drain rate which is not          *
 * available to us. That is the rate effect of a competing flow and nothing     *
 * else: a real competitor would also occupy part of the queue, and therefore   *
 * raise the standing delay, which this deliberately does not do. Stated here   *
 * rather than left to be discovered.                                           *
 *                                                                              *
 * Which datagrams a link applies to is decided by their DESTINATION address,   *
 * so the two directions of a connection are two separate links and are         *
 * configured separately - asymmetric access is the normal case, not the        *
 * exception. Everything which matches no link passes through untouched, which  *
 * keeps STUN, TURN and discovery traffic out of the measurement.               *
 *                                                                              *
 * Accounting is done in microseconds, not in the milliseconds TRNLTime counts  *
 * in: at a drain rate of a megabyte per second a datagram occupies the link    *
 * for well under a millisecond, and rounded to milliseconds every such link    *
 * would come out as infinitely fast.                                           *
 *                                                                              *
 * Kept in the tests directory, like the fault injector: this is test tooling   *
 * and not library functionality.                                               *
 *                                                                              *
 ********************************************************************************)
unit RNLTestNetworkBottleneck;
{$ifdef fpc}
 {$mode delphi}
{$endif}
{$h+}

interface

uses SysUtils,
     Classes,
     SyncObjs,
     Math,
     RNL;

// Two per connection direction is enough for everything which is planned, and a fixed count keeps
// the readouts addressable by a plain index
const RNL_TEST_BOTTLENECK_MAXIMUM_LINKS=4;

      RNL_TEST_BOTTLENECK_MICROSECONDS_PER_SECOND=TRNLInt64(1000000);

      RNL_TEST_BOTTLENECK_MICROSECONDS_PER_MILLISECOND=TRNLInt64(1000);

      // A link is never allowed to drain at zero bytes per second, because that is not a bottleneck
      // any more but a cut cable, and the departure time of a datagram would not be computable
      RNL_TEST_BOTTLENECK_MINIMUM_EFFECTIVE_DRAIN_RATE=TRNLInt64(1);

type TRNLTestNetworkBottleneck=class(TRNLNetwork)
      private

       type TRNLTestNetworkBottleneckDatagram=record
             LinkIndex:TRNLSizeInt;
             DepartureMicroseconds:TRNLInt64;
             Socket:TRNLSocket;
             Address:TRNLAddress;
             Data:TBytes;
             Family:TRNLAddressFamily;
            end;

            TRNLTestNetworkBottleneckDatagrams=array of TRNLTestNetworkBottleneckDatagram;

            TRNLTestNetworkBottleneckLink=record
             Used:boolean;
             Address:TRNLAddress;
             DrainRateBytesPerSecond:TRNLUInt32;
             CrossTrafficBytesPerSecond:TRNLUInt32;
             QueueDepthBytes:TRNLUInt32;
             QueueDepthMilliseconds:TRNLUInt32;
             // When the link becomes free again, on the same scale as the instance time multiplied
             // by a thousand
             NextDepartureMicroseconds:TRNLInt64;
             QueueBytes:TRNLInt64;
             CountQueuedDatagrams:TRNLUInt64;
             CountDroppedDatagrams:TRNLUInt64;
             CountDeliveredDatagrams:TRNLUInt64;
             PeakQueueBytes:TRNLInt64;
             PeakQueueDelayMilliseconds:TRNLInt64;
             LastQueueDelayMilliseconds:TRNLInt64;
            end;

            TRNLTestNetworkBottleneckLinks=array[0..RNL_TEST_BOTTLENECK_MAXIMUM_LINKS-1] of TRNLTestNetworkBottleneckLink;

      private

       fNetwork:TRNLNetwork;

       fLock:TCriticalSection;

       fLinks:TRNLTestNetworkBottleneckLinks;

       // In arrival order, which is not departure order: across two links of different speed a
       // datagram queued later can be due earlier, so releasing means scanning and compacting rather
       // than taking from the front. The queue is bounded by the configured depth, so it stays short
       fQueue:TRNLTestNetworkBottleneckDatagrams;

       fCountQueue:TRNLSizeInt;

       function FindLink(const aAddress:PRNLAddress):TRNLSizeInt;

       function CurrentMicroseconds:TRNLInt64;

       function EffectiveDrainRate(const aLinkIndex:TRNLSizeInt):TRNLInt64;

       procedure Update;

       function ClampTimeout(const aTimeout:TRNLInt64):TRNLInt64;

      public

       constructor Create(const aInstance:TRNLInstance;const aNetwork:TRNLNetwork); reintroduce;
       destructor Destroy; override;

       // Everything sent to aAddress goes through a link of aDrainRateBytesPerSecond whose queue is
       // bounded by aQueueDepthBytes and by aQueueDepthMilliseconds. Zero means unbounded for either
       // depth, and a drain rate of zero leaves the link switched off. Returns the link index, or a
       // negative value when no slot is left.
       function AddLink(const aAddress:TRNLAddress;
                        const aDrainRateBytesPerSecond:TRNLUInt32;
                        const aQueueDepthBytes:TRNLUInt32=0;
                        const aQueueDepthMilliseconds:TRNLUInt32=0):TRNLSizeInt;

       // A competing flow which occupies this much of the drain rate and leaves the rest to us
       procedure SetCrossTraffic(const aLinkIndex:TRNLSizeInt;const aBytesPerSecond:TRNLUInt32);

       procedure SetDrainRate(const aLinkIndex:TRNLSizeInt;const aBytesPerSecond:TRNLUInt32);

       procedure RemoveLinks;

       procedure ResetCounters;

       function LinkCount:TRNLSizeInt;

       function LinkQueuedDatagrams(const aLinkIndex:TRNLSizeInt):TRNLUInt64;
       function LinkDroppedDatagrams(const aLinkIndex:TRNLSizeInt):TRNLUInt64;
       function LinkDeliveredDatagrams(const aLinkIndex:TRNLSizeInt):TRNLUInt64;
       function LinkCurrentQueueBytes(const aLinkIndex:TRNLSizeInt):TRNLInt64;
       function LinkPeakQueueBytes(const aLinkIndex:TRNLSizeInt):TRNLInt64;
       function LinkPeakQueueDelayMilliseconds(const aLinkIndex:TRNLSizeInt):TRNLInt64;
       function LinkLastQueueDelayMilliseconds(const aLinkIndex:TRNLSizeInt):TRNLInt64;
       function LinkEffectiveDrainRate(const aLinkIndex:TRNLSizeInt):TRNLInt64;

       function TotalQueuedDatagrams:TRNLUInt64;
       function TotalDroppedDatagrams:TRNLUInt64;
       function TotalDeliveredDatagrams:TRNLUInt64;

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

     end;

implementation

constructor TRNLTestNetworkBottleneck.Create(const aInstance:TRNLInstance;const aNetwork:TRNLNetwork);
begin
 inherited Create(aInstance);
 fNetwork:=aNetwork;
 fLock:=TCriticalSection.Create;
 fQueue:=nil;
 fCountQueue:=0;
 RemoveLinks;
end;

destructor TRNLTestNetworkBottleneck.Destroy;
begin
 fQueue:=nil;
 FreeAndNil(fLock);
 inherited Destroy;
end;

function TRNLTestNetworkBottleneck.AddLink(const aAddress:TRNLAddress;
                                           const aDrainRateBytesPerSecond:TRNLUInt32;
                                           const aQueueDepthBytes:TRNLUInt32=0;
                                           const aQueueDepthMilliseconds:TRNLUInt32=0):TRNLSizeInt;
var Index:TRNLSizeInt;
begin
 result:=-1;
 fLock.Acquire;
 try
  for Index:=0 to RNL_TEST_BOTTLENECK_MAXIMUM_LINKS-1 do begin
   if not fLinks[Index].Used then begin
    FillChar(fLinks[Index],SizeOf(TRNLTestNetworkBottleneckLink),#0);
    fLinks[Index].Used:=true;
    fLinks[Index].Address:=aAddress;
    fLinks[Index].DrainRateBytesPerSecond:=aDrainRateBytesPerSecond;
    fLinks[Index].QueueDepthBytes:=aQueueDepthBytes;
    fLinks[Index].QueueDepthMilliseconds:=aQueueDepthMilliseconds;
    result:=Index;
    break;
   end;
  end;
 finally
  fLock.Release;
 end;
end;

procedure TRNLTestNetworkBottleneck.SetCrossTraffic(const aLinkIndex:TRNLSizeInt;const aBytesPerSecond:TRNLUInt32);
begin
 if (aLinkIndex>=0) and (aLinkIndex<RNL_TEST_BOTTLENECK_MAXIMUM_LINKS) then begin
  fLock.Acquire;
  try
   fLinks[aLinkIndex].CrossTrafficBytesPerSecond:=aBytesPerSecond;
  finally
   fLock.Release;
  end;
 end;
end;

procedure TRNLTestNetworkBottleneck.SetDrainRate(const aLinkIndex:TRNLSizeInt;const aBytesPerSecond:TRNLUInt32);
begin
 if (aLinkIndex>=0) and (aLinkIndex<RNL_TEST_BOTTLENECK_MAXIMUM_LINKS) then begin
  fLock.Acquire;
  try
   fLinks[aLinkIndex].DrainRateBytesPerSecond:=aBytesPerSecond;
  finally
   fLock.Release;
  end;
 end;
end;

procedure TRNLTestNetworkBottleneck.RemoveLinks;
var Index:TRNLSizeInt;
begin
 fLock.Acquire;
 try
  for Index:=0 to RNL_TEST_BOTTLENECK_MAXIMUM_LINKS-1 do begin
   FillChar(fLinks[Index],SizeOf(TRNLTestNetworkBottleneckLink),#0);
  end;
 finally
  fLock.Release;
 end;
end;

procedure TRNLTestNetworkBottleneck.ResetCounters;
var Index:TRNLSizeInt;
begin
 fLock.Acquire;
 try
  for Index:=0 to RNL_TEST_BOTTLENECK_MAXIMUM_LINKS-1 do begin
   fLinks[Index].CountQueuedDatagrams:=0;
   fLinks[Index].CountDroppedDatagrams:=0;
   fLinks[Index].CountDeliveredDatagrams:=0;
   fLinks[Index].PeakQueueBytes:=0;
   fLinks[Index].PeakQueueDelayMilliseconds:=0;
   fLinks[Index].LastQueueDelayMilliseconds:=0;
  end;
 finally
  fLock.Release;
 end;
end;

function TRNLTestNetworkBottleneck.LinkCount:TRNLSizeInt;
var Index:TRNLSizeInt;
begin
 result:=0;
 fLock.Acquire;
 try
  for Index:=0 to RNL_TEST_BOTTLENECK_MAXIMUM_LINKS-1 do begin
   if fLinks[Index].Used then begin
    inc(result);
   end;
  end;
 finally
  fLock.Release;
 end;
end;

function TRNLTestNetworkBottleneck.LinkQueuedDatagrams(const aLinkIndex:TRNLSizeInt):TRNLUInt64;
begin
 result:=0;
 if (aLinkIndex>=0) and (aLinkIndex<RNL_TEST_BOTTLENECK_MAXIMUM_LINKS) then begin
  fLock.Acquire;
  try
   result:=fLinks[aLinkIndex].CountQueuedDatagrams;
  finally
   fLock.Release;
  end;
 end;
end;

function TRNLTestNetworkBottleneck.LinkDroppedDatagrams(const aLinkIndex:TRNLSizeInt):TRNLUInt64;
begin
 result:=0;
 if (aLinkIndex>=0) and (aLinkIndex<RNL_TEST_BOTTLENECK_MAXIMUM_LINKS) then begin
  fLock.Acquire;
  try
   result:=fLinks[aLinkIndex].CountDroppedDatagrams;
  finally
   fLock.Release;
  end;
 end;
end;

function TRNLTestNetworkBottleneck.LinkDeliveredDatagrams(const aLinkIndex:TRNLSizeInt):TRNLUInt64;
begin
 result:=0;
 if (aLinkIndex>=0) and (aLinkIndex<RNL_TEST_BOTTLENECK_MAXIMUM_LINKS) then begin
  fLock.Acquire;
  try
   result:=fLinks[aLinkIndex].CountDeliveredDatagrams;
  finally
   fLock.Release;
  end;
 end;
end;

function TRNLTestNetworkBottleneck.LinkCurrentQueueBytes(const aLinkIndex:TRNLSizeInt):TRNLInt64;
begin
 result:=0;
 if (aLinkIndex>=0) and (aLinkIndex<RNL_TEST_BOTTLENECK_MAXIMUM_LINKS) then begin
  fLock.Acquire;
  try
   result:=fLinks[aLinkIndex].QueueBytes;
  finally
   fLock.Release;
  end;
 end;
end;

function TRNLTestNetworkBottleneck.LinkPeakQueueBytes(const aLinkIndex:TRNLSizeInt):TRNLInt64;
begin
 result:=0;
 if (aLinkIndex>=0) and (aLinkIndex<RNL_TEST_BOTTLENECK_MAXIMUM_LINKS) then begin
  fLock.Acquire;
  try
   result:=fLinks[aLinkIndex].PeakQueueBytes;
  finally
   fLock.Release;
  end;
 end;
end;

function TRNLTestNetworkBottleneck.LinkPeakQueueDelayMilliseconds(const aLinkIndex:TRNLSizeInt):TRNLInt64;
begin
 result:=0;
 if (aLinkIndex>=0) and (aLinkIndex<RNL_TEST_BOTTLENECK_MAXIMUM_LINKS) then begin
  fLock.Acquire;
  try
   result:=fLinks[aLinkIndex].PeakQueueDelayMilliseconds;
  finally
   fLock.Release;
  end;
 end;
end;

function TRNLTestNetworkBottleneck.LinkLastQueueDelayMilliseconds(const aLinkIndex:TRNLSizeInt):TRNLInt64;
begin
 result:=0;
 if (aLinkIndex>=0) and (aLinkIndex<RNL_TEST_BOTTLENECK_MAXIMUM_LINKS) then begin
  fLock.Acquire;
  try
   result:=fLinks[aLinkIndex].LastQueueDelayMilliseconds;
  finally
   fLock.Release;
  end;
 end;
end;

function TRNLTestNetworkBottleneck.LinkEffectiveDrainRate(const aLinkIndex:TRNLSizeInt):TRNLInt64;
begin
 result:=0;
 if (aLinkIndex>=0) and (aLinkIndex<RNL_TEST_BOTTLENECK_MAXIMUM_LINKS) then begin
  fLock.Acquire;
  try
   result:=EffectiveDrainRate(aLinkIndex);
  finally
   fLock.Release;
  end;
 end;
end;

function TRNLTestNetworkBottleneck.TotalQueuedDatagrams:TRNLUInt64;
var Index:TRNLSizeInt;
begin
 result:=0;
 fLock.Acquire;
 try
  for Index:=0 to RNL_TEST_BOTTLENECK_MAXIMUM_LINKS-1 do begin
   inc(result,fLinks[Index].CountQueuedDatagrams);
  end;
 finally
  fLock.Release;
 end;
end;

function TRNLTestNetworkBottleneck.TotalDroppedDatagrams:TRNLUInt64;
var Index:TRNLSizeInt;
begin
 result:=0;
 fLock.Acquire;
 try
  for Index:=0 to RNL_TEST_BOTTLENECK_MAXIMUM_LINKS-1 do begin
   inc(result,fLinks[Index].CountDroppedDatagrams);
  end;
 finally
  fLock.Release;
 end;
end;

function TRNLTestNetworkBottleneck.TotalDeliveredDatagrams:TRNLUInt64;
var Index:TRNLSizeInt;
begin
 result:=0;
 fLock.Acquire;
 try
  for Index:=0 to RNL_TEST_BOTTLENECK_MAXIMUM_LINKS-1 do begin
   inc(result,fLinks[Index].CountDeliveredDatagrams);
  end;
 finally
  fLock.Release;
 end;
end;

// Everything below expects the lock to be held by the caller

function TRNLTestNetworkBottleneck.FindLink(const aAddress:PRNLAddress):TRNLSizeInt;
var Index:TRNLSizeInt;
begin
 result:=-1;
 if assigned(aAddress) then begin
  for Index:=0 to RNL_TEST_BOTTLENECK_MAXIMUM_LINKS-1 do begin
   if fLinks[Index].Used and
      (fLinks[Index].DrainRateBytesPerSecond>0) and
      aAddress^.Equals(fLinks[Index].Address) then begin
    result:=Index;
    break;
   end;
  end;
 end;
end;

function TRNLTestNetworkBottleneck.CurrentMicroseconds:TRNLInt64;
begin
 result:=TRNLInt64(Instance.Time.Value)*RNL_TEST_BOTTLENECK_MICROSECONDS_PER_MILLISECOND;
end;

function TRNLTestNetworkBottleneck.EffectiveDrainRate(const aLinkIndex:TRNLSizeInt):TRNLInt64;
begin
 result:=Max(RNL_TEST_BOTTLENECK_MINIMUM_EFFECTIVE_DRAIN_RATE,
             TRNLInt64(fLinks[aLinkIndex].DrainRateBytesPerSecond)-
             TRNLInt64(fLinks[aLinkIndex].CrossTrafficBytesPerSecond));
end;

procedure TRNLTestNetworkBottleneck.Update;
var Index,Kept,LinkIndex,DataLength:TRNLSizeInt;
    Now:TRNLInt64;
begin

 fLock.Acquire;
 try

  Now:=CurrentMicroseconds;

  Kept:=0;

  for Index:=0 to fCountQueue-1 do begin

   if fQueue[Index].DepartureMicroseconds>Now then begin

    // Not due yet, so it stays, and it is moved down over everything which has already left
    if Kept<>Index then begin
     fQueue[Kept]:=fQueue[Index];
    end;
    inc(Kept);

   end else begin

    DataLength:=length(fQueue[Index].Data);
    LinkIndex:=fQueue[Index].LinkIndex;

    if DataLength>0 then begin
     fNetwork.Send(fQueue[Index].Socket,
                   @fQueue[Index].Address,
                   fQueue[Index].Data[0],
                   DataLength,
                   fQueue[Index].Family);
    end;

    if (LinkIndex>=0) and (LinkIndex<RNL_TEST_BOTTLENECK_MAXIMUM_LINKS) then begin
     dec(fLinks[LinkIndex].QueueBytes,DataLength);
     inc(fLinks[LinkIndex].CountDeliveredDatagrams);
    end;

    fQueue[Index].Data:=nil;

   end;

  end;

  // The tail beyond Kept still holds copies of entries which were moved down, so the references have
  // to go, otherwise the byte arrays stay alive until the slot is overwritten
  for Index:=Kept to fCountQueue-1 do begin
   fQueue[Index].Data:=nil;
  end;

  fCountQueue:=Kept;

 finally
  fLock.Release;
 end;

end;

function TRNLTestNetworkBottleneck.ClampTimeout(const aTimeout:TRNLInt64):TRNLInt64;
var Index:TRNLSizeInt;
    Earliest,Now,Remaining:TRNLInt64;
begin
 result:=aTimeout;
 fLock.Acquire;
 try
  Earliest:=-1;
  for Index:=0 to fCountQueue-1 do begin
   if (Earliest<0) or (fQueue[Index].DepartureMicroseconds<Earliest) then begin
    Earliest:=fQueue[Index].DepartureMicroseconds;
   end;
  end;
  if Earliest>=0 then begin
   Now:=CurrentMicroseconds;
   // Rounded up, so that a wait never returns a hair before the datagram is actually due only to
   // have to be repeated
   Remaining:=(Max(0,Earliest-Now)+(RNL_TEST_BOTTLENECK_MICROSECONDS_PER_MILLISECOND-1)) div
              RNL_TEST_BOTTLENECK_MICROSECONDS_PER_MILLISECOND;
   result:=Max(1,Min(aTimeout,Remaining));
  end;
 finally
  fLock.Release;
 end;
end;

function TRNLTestNetworkBottleneck.Send(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aData;const aDataLength:TRNLSizeInt;const aFamily:TRNLAddressFamily):TRNLSizeInt;
var LinkIndex:TRNLSizeInt;
    Now,ServiceMicroseconds,Departure,DelayMilliseconds:TRNLInt64;
    Dropped,PassThrough:boolean;
begin

 Update;

 if aDataLength<=0 then begin
  result:=fNetwork.Send(aSocket,aAddress,aData,aDataLength,aFamily);
  exit;
 end;

 Dropped:=false;
 PassThrough:=false;

 fLock.Acquire;
 try

  LinkIndex:=FindLink(aAddress);

  if LinkIndex<0 then begin

   PassThrough:=true;

  end else begin

   Now:=CurrentMicroseconds;

   // The link is free again either right now or at the end of what it is still working on
   if fLinks[LinkIndex].NextDepartureMicroseconds<Now then begin
    fLinks[LinkIndex].NextDepartureMicroseconds:=Now;
   end;

   ServiceMicroseconds:=(TRNLInt64(aDataLength)*RNL_TEST_BOTTLENECK_MICROSECONDS_PER_SECOND) div
                        EffectiveDrainRate(LinkIndex);

   Departure:=fLinks[LinkIndex].NextDepartureMicroseconds+ServiceMicroseconds;

   DelayMilliseconds:=(Departure-Now) div RNL_TEST_BOTTLENECK_MICROSECONDS_PER_MILLISECOND;

   if (fLinks[LinkIndex].QueueDepthBytes>0) and
      ((fLinks[LinkIndex].QueueBytes+aDataLength)>TRNLInt64(fLinks[LinkIndex].QueueDepthBytes)) then begin
    Dropped:=true;
   end else if (fLinks[LinkIndex].QueueDepthMilliseconds>0) and
               (DelayMilliseconds>TRNLInt64(fLinks[LinkIndex].QueueDepthMilliseconds)) then begin
    Dropped:=true;
   end;

   if Dropped then begin

    inc(fLinks[LinkIndex].CountDroppedDatagrams);

   end else begin

    fLinks[LinkIndex].NextDepartureMicroseconds:=Departure;

    inc(fLinks[LinkIndex].QueueBytes,aDataLength);
    if fLinks[LinkIndex].QueueBytes>fLinks[LinkIndex].PeakQueueBytes then begin
     fLinks[LinkIndex].PeakQueueBytes:=fLinks[LinkIndex].QueueBytes;
    end;

    fLinks[LinkIndex].LastQueueDelayMilliseconds:=DelayMilliseconds;
    if DelayMilliseconds>fLinks[LinkIndex].PeakQueueDelayMilliseconds then begin
     fLinks[LinkIndex].PeakQueueDelayMilliseconds:=DelayMilliseconds;
    end;

    inc(fLinks[LinkIndex].CountQueuedDatagrams);

    if fCountQueue>=length(fQueue) then begin
     SetLength(fQueue,(fCountQueue+1)+((fCountQueue+1) shr 1));
    end;
    fQueue[fCountQueue].LinkIndex:=LinkIndex;
    fQueue[fCountQueue].DepartureMicroseconds:=Departure;
    fQueue[fCountQueue].Socket:=aSocket;
    fQueue[fCountQueue].Address:=aAddress^;
    SetLength(fQueue[fCountQueue].Data,aDataLength);
    Move(aData,fQueue[fCountQueue].Data[0],aDataLength);
    fQueue[fCountQueue].Family:=aFamily;
    inc(fCountQueue);

   end;

  end;

 finally
  fLock.Release;
 end;

 if PassThrough then begin
  result:=fNetwork.Send(aSocket,aAddress,aData,aDataLength,aFamily);
 end else begin
  // Successful either way, and deliberately so: a datagram which a bottleneck discards on the way is
  // indistinguishable from one which was handed over to the network. Reporting the drop back to the
  // sender would make this simulator model something no real bottleneck does
  result:=aDataLength;
 end;

end;

function TRNLTestNetworkBottleneck.Receive(const aSocket:TRNLSocket;const aAddress:PRNLAddress;out aData;const aDataLength:TRNLSizeInt;const aFamily:TRNLAddressFamily):TRNLSizeInt;
begin
 Update;
 result:=fNetwork.Receive(aSocket,aAddress,aData,aDataLength,aFamily);
end;

function TRNLTestNetworkBottleneck.SocketSelect(const aMaxSocket:TRNLSocket;var aReadSet,aWriteSet:TRNLSocketSet;const aTimeout:TRNLInt64;const aEvent:TRNLNetworkEvent=nil):TRNLInt32;
begin
 Update;
 result:=fNetwork.SocketSelect(aMaxSocket,aReadSet,aWriteSet,ClampTimeout(aTimeout),aEvent);
 Update;
end;

function TRNLTestNetworkBottleneck.SocketWait(const aSockets:array of TRNLSocket;var aConditions:TRNLSocketWaitConditions;const aTimeout:TRNLInt64;const aEvent:TRNLNetworkEvent=nil):boolean;
begin
 Update;
 result:=fNetwork.SocketWait(aSockets,aConditions,ClampTimeout(aTimeout),aEvent);
 Update;
end;

function TRNLTestNetworkBottleneck.AddressSetHost(var aAddress:TRNLAddress;const aName:TRNLRawByteString):boolean;
begin
 result:=fNetwork.AddressSetHost(aAddress,aName);
end;

function TRNLTestNetworkBottleneck.AddressGetHost(const aAddress:TRNLAddress;out aName;const aNameLength:TRNLInt32;const aFlags:TRNLInt32=0):boolean;
begin
 result:=fNetwork.AddressGetHost(aAddress,aName,aNameLength,aFlags);
end;

function TRNLTestNetworkBottleneck.AddressGetHostIP(const aAddress:TRNLAddress;out aName;const aNameLength:TRNLInt32):boolean;
begin
 result:=fNetwork.AddressGetHostIP(aAddress,aName,aNameLength);
end;

function TRNLTestNetworkBottleneck.SocketCreate(const aType:TRNLSocketType;const aFamily:TRNLAddressFamily):TRNLSocket;
begin
 result:=fNetwork.SocketCreate(aType,aFamily);
end;

procedure TRNLTestNetworkBottleneck.SocketDestroy(const aSocket:TRNLSocket);
begin
 fNetwork.SocketDestroy(aSocket);
end;

function TRNLTestNetworkBottleneck.SocketShutdown(const aSocket:TRNLSocket;const aHow:TRNLSocketShutdown=RNL_SOCKET_SHUTDOWN_READ_WRITE):boolean;
begin
 result:=fNetwork.SocketShutdown(aSocket,aHow);
end;

function TRNLTestNetworkBottleneck.SocketGetAddress(const aSocket:TRNLSocket;out aAddress:TRNLAddress;const aFamily:TRNLAddressFamily):boolean;
begin
 result:=fNetwork.SocketGetAddress(aSocket,aAddress,aFamily);
end;

function TRNLTestNetworkBottleneck.SocketSetOption(const aSocket:TRNLSocket;const aOption:TRNLSocketOption;const aValue:TRNLInt32):boolean;
begin
 result:=fNetwork.SocketSetOption(aSocket,aOption,aValue);
end;

function TRNLTestNetworkBottleneck.SocketGetOption(const aSocket:TRNLSocket;const aOption:TRNLSocketOption;out aValue:TRNLInt32):boolean;
begin
 result:=fNetwork.SocketGetOption(aSocket,aOption,aValue);
end;

function TRNLTestNetworkBottleneck.SocketBind(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aFamily:TRNLAddressFamily):boolean;
begin
 result:=fNetwork.SocketBind(aSocket,aAddress,aFamily);
end;

function TRNLTestNetworkBottleneck.SocketListen(const aSocket:TRNLSocket;const aBackLog:TRNLInt32):boolean;
begin
 result:=fNetwork.SocketListen(aSocket,aBackLog);
end;

function TRNLTestNetworkBottleneck.SocketConnect(const aSocket:TRNLSocket;const aAddress:TRNLAddress;const aFamily:TRNLAddressFamily):boolean;
begin
 result:=fNetwork.SocketConnect(aSocket,aAddress,aFamily);
end;

function TRNLTestNetworkBottleneck.SocketAccept(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aFamily:TRNLAddressFamily):TRNLSocket;
begin
 result:=fNetwork.SocketAccept(aSocket,aAddress,aFamily);
end;

end.
