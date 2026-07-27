(******************************************************************************
 *                          RNL REGRESSION TESTS                              *
 ******************************************************************************
 *                        Version 2026-07-27-00-00-0000                       *
 ******************************************************************************
 *                                                                            *
 * Regression tests around the robustness of the host service loop.            *
 *                                                                            *
 * They all share one theme: none of the situations tested here can occur at    *
 * all on TRNLVirtualNetwork, which has neither a MTU nor a send buffer which   *
 * could ever fill up, and whose Send basically always succeeds. On a real      *
 * network they happen routinely instead, which is why they need a dedicated    *
 * fault injecting network to be testable in the first place.                   *
 *                                                                            *
 ******************************************************************************)
unit RNLTestRegressions;
{$ifdef fpc}
 {$mode delphi}
{$endif}
{$h+}

interface

uses SysUtils,
     Classes,
     SyncObjs,
     RNL,
     RNLTestFramework,
     RNLTestNetworkFaultInjector,
     RNLTestHostPair,
     RNLTestSTUNServer,
     RNLTestNATNetwork;

procedure RunRegressionTests;

implementation

const PROBABILITY_ALWAYS=TRNLUInt32($ffffffff);
      PROBABILITY_TWENTY_FIVE_PERCENT=TRNLUInt32(TRNLUInt64($ffffffff)*25 div 100);
      PROBABILITY_THIRTY_PERCENT=TRNLUInt32(TRNLUInt64($ffffffff)*30 div 100);

      TEST_MESSAGE_PREFIX='RNLRegressionTestMessage';

{$if defined(Windows)}
// Declared locally rather than by pulling the whole Windows unit into this test unit.
// GetProcessHandleCount is not present in every version of the FreePascal and Delphi Windows
// units anyway, and wine implements it, which is what makes this measurable from a non Windows
// machine as well.
function GetCurrentProcess:THandle; stdcall;
         external 'kernel32.dll' name 'GetCurrentProcess';
function GetProcessHandleCount(hProcess:THandle;var pdwHandleCount:TRNLUInt32):LongBool; stdcall;
         external 'kernel32.dll' name 'GetProcessHandleCount';
{$ifend}

type TRNLTestInterrupterThread=class(TThread)
      private
       fHost:TRNLHost;
       fDelayMilliseconds:TRNLInt64;
      protected
       procedure Execute; override;
      public
       constructor Create(const aHost:TRNLHost;const aDelayMilliseconds:TRNLInt64); reintroduce;
     end;

constructor TRNLTestInterrupterThread.Create(const aHost:TRNLHost;const aDelayMilliseconds:TRNLInt64);
begin
 fHost:=aHost;
 fDelayMilliseconds:=aDelayMilliseconds;
 FreeOnTerminate:=false;
 inherited Create(false);
end;

procedure TRNLTestInterrupterThread.Execute;
begin
 Sleep(fDelayMilliseconds);
 if not Terminated then begin
  fHost.Interrupt;
 end;
end;

// A payload large enough that every single message needs its own datagram, so that a
// configured packet loss really does hit individual messages instead of a single datagram
// which happens to carry all of them at once
// The byte offset of a field inside its handshake packet, taken from the record itself rather
// than written out as a number, so that a change of the packet layout carries over on its own
function HandshakeFieldOffset(const aPacket;const aField):TRNLSizeUInt;
begin
 result:=TRNLSizeUInt(TRNLPtrUInt(TRNLPointer(@aField))-TRNLPtrUInt(TRNLPointer(@aPacket)));
end;

function HandshakePacketType(const aType:TRNLProtocolHandshakePacketType):TRNLUInt8;
begin
 result:=TRNLUInt8(TRNLInt32(aType));
end;

function TestMessageText(const aIndex:TRNLSizeInt;const aPaddingSize:TRNLSizeInt=0):TRNLRawByteString;
begin
 result:=TEST_MESSAGE_PREFIX+TRNLRawByteString(IntToStr(aIndex));
 if aPaddingSize>length(result) then begin
  result:=result+TRNLRawByteString(StringOfChar('.',aPaddingSize-length(result)));
 end;
end;

// ---------------------------------------------------------------------------------------
// Retransmission timeout configuration
// ---------------------------------------------------------------------------------------

// Every outgoing reliable block packet gets an initial retransmission timeout, derived from
// the smoothed round trip time, plus a ceiling for the exponential backoff. Both values are
// clamped by one of the two host constant pairs, and it matters a lot which pair clamps
// which value: if the ceiling ends up below the initial timeout, then the very first
// retransmission is delayed all the way up to the ceiling range, and the backoff can never
// grow either, because every doubling gets clamped straight back down again.
procedure TestRetransmissionTimeoutConfigurationIsConsistent;
var Instance:TRNLInstance;
    Network:TRNLNetwork;
    Host:TRNLHost;
begin

 TestBegin('retransmission timeout configuration is consistent');
 try

  Instance:=TRNLInstance.Create;
  try
   Network:=TRNLVirtualNetwork.Create(Instance);
   try
    Host:=TRNLHost.Create(Instance,Network);
    try

     Info('MinimumRetransmissionTimeout      = '+TRNLRawByteString(IntToStr(Host.MinimumRetransmissionTimeout)));
     Info('MaximumRetransmissionTimeout      = '+TRNLRawByteString(IntToStr(Host.MaximumRetransmissionTimeout)));
     Info('MinimumRetransmissionTimeoutLimit = '+TRNLRawByteString(IntToStr(Host.MinimumRetransmissionTimeoutLimit)));
     Info('MaximumRetransmissionTimeoutLimit = '+TRNLRawByteString(IntToStr(Host.MaximumRetransmissionTimeoutLimit)));

     Check(Host.MinimumRetransmissionTimeoutLimit<=Host.MaximumRetransmissionTimeoutLimit,
           'the initial retransmission timeout range must not be inverted');

     Check(Host.MinimumRetransmissionTimeout<=Host.MaximumRetransmissionTimeout,
           'the backoff ceiling range must not be inverted');

     Check(Host.MaximumRetransmissionTimeoutLimit<=Host.MinimumRetransmissionTimeout,
           'the whole initial retransmission timeout range must lie at or below the backoff ceiling range, '+
           'otherwise the first retransmission is delayed by the ceiling and the backoff can never grow');

     // A first retransmission must not take seconds, otherwise a single lost reliable block
     // packet burns most of the connection timeout, while the keep alive pings are
     // suppressed for exactly as long, because an unacknowledged block packet suppresses them
     CheckAtMostInt64(Host.MaximumRetransmissionTimeoutLimit,Host.ConnectionTimeout div 4,
                      'the initial retransmission timeout must stay well below the connection timeout');

    finally
     FreeAndNil(Host);
    end;
   finally
    FreeAndNil(Network);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  TestEnd;
 end;

end;

// ---------------------------------------------------------------------------------------
// Socket level error classification
// ---------------------------------------------------------------------------------------

// A socket which does not accept a datagram right now is an everyday occurrence on a real
// network, and from the protocol point of view indistinguishable from ordinary packet loss.
// It must therefore never terminate the host service loop, which would take down every
// other peer of that host along with it.
procedure TestSoftSendFailuresDoNotTerminateHost;
const COUNT_MESSAGES=10;
var Instance:TRNLInstance;
    VirtualNetwork:TRNLVirtualNetwork;
    FaultInjector:TRNLNetworkFaultInjector;
    HostPair:TRNLTestHostPair;
    Index:TRNLSizeInt;
    ElapsedMilliseconds:TRNLInt64;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('soft send failures do not terminate the host');
 Watchdog:=TRNLTestWatchdog.Create('soft send failures',120000);
 try

  Instance:=TRNLInstance.Create;
  try
   VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
   try
    FaultInjector:=TRNLNetworkFaultInjector.Create(Instance,VirtualNetwork);
    try

     FaultInjector.SoftSendFailureProbabilityFactor:=PROBABILITY_THIRTY_PERCENT;

     HostPair:=TRNLTestHostPair.Create(Instance,FaultInjector);
     try

      if not Check(HostPair.Connect(15000),'the handshake must survive 30 percent soft send failures') then begin
       exit;
      end;

      for Index:=1 to COUNT_MESSAGES do begin
       HostPair.ClientPeer.Channels[RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_ORDERED].SendMessageRawByteString(TestMessageText(Index,600));
      end;

      if not Check(HostPair.PumpUntilServerReceived(COUNT_MESSAGES,30000,ElapsedMilliseconds),
                   'the host service loop must not report an error because of soft send failures') then begin
       exit;
      end;

      Info('soft send failures injected: '+TRNLRawByteString(IntToStr(FaultInjector.CountSoftSendFailures)));
      Info('host counted soft send failures: '+TRNLRawByteString(IntToStr(HostPair.Client.TotalSoftSendFailures+HostPair.Server.TotalSoftSendFailures)));
      Info('elapsed: '+TRNLRawByteString(IntToStr(ElapsedMilliseconds))+' ms');

      CheckAtLeastInt64(FaultInjector.CountSoftSendFailures,1,
                        'the test must actually have injected soft send failures, otherwise it tests nothing');

      CheckEqualsInt64(HostPair.ServerReceivedMessages.Count,COUNT_MESSAGES,
                       'all reliable messages must arrive despite the soft send failures');

      CheckEqualsInt64(TRNLInt64(HostPair.Client.TotalHardSendFailures+HostPair.Server.TotalHardSendFailures),0,
                       'no soft send failure may be misreported as a hard one');

      CheckEqualsInt64(HostPair.CountServerDisconnectEvents,0,
                       'the connection must not drop because of soft send failures');

      if HostPair.ServerReceivedMessages.Count=COUNT_MESSAGES then begin
       for Index:=1 to COUNT_MESSAGES do begin
        CheckEqualsRawByteString(TRNLRawByteString(HostPair.ServerReceivedMessages[Index-1]),
                                 TestMessageText(Index,600),
                                 'reliable ordered message '+TRNLRawByteString(IntToStr(Index))+' must arrive in order and intact');
       end;
      end;

     finally
      FreeAndNil(HostPair);
     end;

    finally
     FreeAndNil(FaultInjector);
    end;
   finally
    FreeAndNil(VirtualNetwork);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

// A hard send failure really is unrecoverable and must still be reported, so that making
// the transient conditions non fatal does not end up swallowing everything
procedure TestHardSendFailureTerminatesHost;
var Instance:TRNLInstance;
    VirtualNetwork:TRNLVirtualNetwork;
    FaultInjector:TRNLNetworkFaultInjector;
    HostPair:TRNLTestHostPair;
    Index:TRNLSizeInt;
    SawError:boolean;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('a hard send failure is still reported as a host error');
 Watchdog:=TRNLTestWatchdog.Create('hard send failure',60000);
 try

  Instance:=TRNLInstance.Create;
  try
   VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
   try
    FaultInjector:=TRNLNetworkFaultInjector.Create(Instance,VirtualNetwork);
    try

     HostPair:=TRNLTestHostPair.Create(Instance,FaultInjector);
     try

      if not Check(HostPair.Connect(5000),'the handshake must succeed without any injected faults') then begin
       exit;
      end;

      // Only now, so that the handshake itself stays unaffected
      FaultInjector.HardSendFailureProbabilityFactor:=PROBABILITY_ALWAYS;

      for Index:=1 to 4 do begin
       HostPair.ClientPeer.Channels[RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_ORDERED].SendMessageRawByteString(TestMessageText(Index));
      end;

      SawError:=not HostPair.Pump(3000);

      Info('hard send failures injected: '+TRNLRawByteString(IntToStr(FaultInjector.CountHardSendFailures)));
      Info('host counted hard send failures: '+TRNLRawByteString(IntToStr(HostPair.Client.TotalHardSendFailures+HostPair.Server.TotalHardSendFailures)));

      Check(SawError,'a hard send failure must still terminate the host service loop with an error');

      CheckAtLeastInt64(TRNLInt64(HostPair.Client.TotalHardSendFailures+HostPair.Server.TotalHardSendFailures),1,
                        'the host must have counted the hard send failure');

     finally
      FreeAndNil(HostPair);
     end;

    finally
     FreeAndNil(FaultInjector);
    end;
   finally
    FreeAndNil(VirtualNetwork);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

// A datagram above the path MTU makes a real socket fail with EMSGSIZE, which is a soft
// failure. It must neither terminate the host nor permanently wedge the reliable channel,
// so that the transfer recovers on its own as soon as the datagram fits again.
procedure TestOversizedDatagramsDoNotTerminateHost;
var Instance:TRNLInstance;
    VirtualNetwork:TRNLVirtualNetwork;
    FaultInjector:TRNLNetworkFaultInjector;
    HostPair:TRNLTestHostPair;
    Payload:TRNLRawByteString;
    ElapsedMilliseconds:TRNLInt64;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('oversized datagrams do not terminate the host and recover afterwards');
 Watchdog:=TRNLTestWatchdog.Create('oversized datagrams',60000);
 try

  Instance:=TRNLInstance.Create;
  try
   VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
   try
    FaultInjector:=TRNLNetworkFaultInjector.Create(Instance,VirtualNetwork);
    try

     HostPair:=TRNLTestHostPair.Create(Instance,FaultInjector);
     try

      if not Check(HostPair.Connect(5000),'the handshake must succeed without any injected faults') then begin
       exit;
      end;

      // Small enough to reject the data carrying datagrams, but large enough to let the
      // keep alive traffic through, which is exactly the asymmetric situation a shrinking
      // path MTU produces
      FaultInjector.MaximumDatagramSize:=120;

      Payload:=TRNLRawByteString(StringOfChar('X',400));

      HostPair.ClientPeer.Channels[RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_ORDERED].SendMessageRawByteString(Payload);

      if not Check(HostPair.Pump(2000),'oversized datagrams must not terminate the host service loop') then begin
       exit;
      end;

      Info('oversized datagrams rejected: '+TRNLRawByteString(IntToStr(FaultInjector.CountOversizedDatagrams)));

      CheckAtLeastInt64(FaultInjector.CountOversizedDatagrams,1,
                        'the test must actually have rejected oversized datagrams');

      CheckEqualsInt64(HostPair.ServerReceivedMessages.Count,0,
                       'the oversized message can not have arrived while the limit is in place');

      // Now lift the limit again, the reliable layer has to recover all by itself
      FaultInjector.MaximumDatagramSize:=0;

      if not Check(HostPair.PumpUntilServerReceived(1,10000,ElapsedMilliseconds),
                   'the host service loop must stay alive while recovering') then begin
       exit;
      end;

      Info('recovery took '+TRNLRawByteString(IntToStr(ElapsedMilliseconds))+' ms');

      if CheckEqualsInt64(HostPair.ServerReceivedMessages.Count,1,
                          'the reliable message must arrive once the datagrams fit again') then begin
       CheckEqualsRawByteString(TRNLRawByteString(HostPair.ServerReceivedMessages[0]),Payload,
                                'the recovered message must be intact');
      end;

     finally
      FreeAndNil(HostPair);
     end;

    finally
     FreeAndNil(FaultInjector);
    end;
   finally
    FreeAndNil(VirtualNetwork);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

// A connectionless UDP socket reports a whole range of transient conditions on receive, from
// EWOULDBLOCK over EINTR up to the ICMP induced ECONNRESET, ECONNREFUSED and EHOSTUNREACH
// family, which gets queued onto the socket for a previously sent datagram. None of them
// justifies taking down the host.
procedure TestSoftReceiveFailuresDoNotTerminateHost;
const COUNT_MESSAGES=10;
var Instance:TRNLInstance;
    VirtualNetwork:TRNLVirtualNetwork;
    FaultInjector:TRNLNetworkFaultInjector;
    HostPair:TRNLTestHostPair;
    Index:TRNLSizeInt;
    ElapsedMilliseconds:TRNLInt64;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('soft receive failures do not terminate the host');
 Watchdog:=TRNLTestWatchdog.Create('soft receive failures',120000);
 try

  Instance:=TRNLInstance.Create;
  try
   VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
   try
    FaultInjector:=TRNLNetworkFaultInjector.Create(Instance,VirtualNetwork);
    try

     FaultInjector.SoftReceiveFailureProbabilityFactor:=PROBABILITY_THIRTY_PERCENT;

     HostPair:=TRNLTestHostPair.Create(Instance,FaultInjector);
     try

      if not Check(HostPair.Connect(15000),'the handshake must survive 30 percent soft receive failures') then begin
       exit;
      end;

      for Index:=1 to COUNT_MESSAGES do begin
       HostPair.ClientPeer.Channels[RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_ORDERED].SendMessageRawByteString(TestMessageText(Index,600));
      end;

      if not Check(HostPair.PumpUntilServerReceived(COUNT_MESSAGES,30000,ElapsedMilliseconds),
                   'the host service loop must not report an error because of soft receive failures') then begin
       exit;
      end;

      Info('soft receive failures injected: '+TRNLRawByteString(IntToStr(FaultInjector.CountSoftReceiveFailures)));
      Info('elapsed: '+TRNLRawByteString(IntToStr(ElapsedMilliseconds))+' ms');

      CheckAtLeastInt64(FaultInjector.CountSoftReceiveFailures,1,
                        'the test must actually have injected soft receive failures');

      CheckEqualsInt64(HostPair.ServerReceivedMessages.Count,COUNT_MESSAGES,
                       'all reliable messages must arrive despite the soft receive failures');

      CheckEqualsInt64(TRNLInt64(HostPair.Client.TotalHardReceiveFailures+HostPair.Server.TotalHardReceiveFailures),0,
                       'no soft receive failure may be misreported as a hard one');

     finally
      FreeAndNil(HostPair);
     end;

    finally
     FreeAndNil(FaultInjector);
    end;
   finally
    FreeAndNil(VirtualNetwork);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

// The two tests above drive the host through a fault injecting network, which means they
// assert the contract of the host towards its network implementation, but they can not
// assert the error classification inside TRNLRealNetwork itself, since that is exactly the
// layer they replace.
//
// This test therefore goes straight at TRNLRealNetwork with real sockets and provokes the
// two cases which actually matter and which really can be provoked deterministically:
//
//   A connected UDP socket whose counter port is closed gets an ICMP port unreachable, which
//   the kernel queues onto the socket and reports on the next receive. That is a transient
//   per destination condition, and it must not be reported as a broken socket.
//
//   An invalid socket handle in contrast really is unrecoverable and has to stay a hard
//   error, otherwise a host would spin on it forever instead of giving up.
procedure TestRealSocketReportsItsBoundAddress;
var Instance:TRNLInstance;
    Network:TRNLRealNetwork;
    Socket:TRNLSocket;
    Address,BoundAddress:TRNLAddress;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('a real socket reports the address it was bound to');
 Watchdog:=TRNLTestWatchdog.Create('real socket bound address',60000);
 try

  Instance:=TRNLInstance.Create;
  try
   Network:=TRNLRealNetwork.Create(Instance);
   try

    Socket:=Network.SocketCreate(RNL_SOCKET_TYPE_DATAGRAM,RNL_IPV4);
    if not Check(Socket<>RNL_SOCKET_NULL,'a datagram socket can be created') then begin
     exit;
    end;
    try

     // Port zero, so the system picks one. Asking afterwards which one it picked is the only way to
     // find out, and it is what a host bound to RNL_HOST_ANY does in Start and what gathering
     // candidates depends on entirely.
     FillChar(Address,SizeOf(TRNLAddress),#0);
     Address.Host:=RNL_HOST_ANY;
     Address.Port:=0;
     if not Check(Network.SocketBind(Socket,@Address,RNL_IPV4),'and bound to any address') then begin
      exit;
     end;

     FillChar(BoundAddress,SizeOf(TRNLAddress),#0);

     // This is the whole test. On Windows the call used to fill in the address and then report
     // failure anyway, so every caller threw the answer away: a host never learned its own port,
     // and candidate gathering came up empty. It cost nothing to find on Linux, because there the
     // very same function returned true all along.
     if not Check(Network.SocketGetAddress(Socket,BoundAddress,RNL_IPV4),
                  'and asking for the bound address has to succeed') then begin
      exit;
     end;

     Info('bound to port '+TRNLRawByteString(IntToStr(BoundAddress.Port)));

     CheckAtLeastInt64(BoundAddress.Port,1,
                       'and it has to report the port the system really handed out, not zero');

    finally
     Network.SocketDestroy(Socket);
    end;

   finally
    FreeAndNil(Network);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

procedure TestRealSocketReceiveErrorClassification;
const CLOSED_PORT=19387;
      COUNT_ATTEMPTS=200;
var Instance:TRNLInstance;
    Network:TRNLRealNetwork;
    Socket:TRNLSocket;
    Address:TRNLAddress;
    Payload:array[0..15] of TRNLUInt8;
    Buffer:array[0..1023] of TRNLUInt8;
    Index,ReceiveResult,CountNegativeResults:TRNLSizeInt;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('real socket receive errors are classified correctly');
 Watchdog:=TRNLTestWatchdog.Create('real socket receive errors',60000);
 try

  Instance:=TRNLInstance.Create;
  try
   Network:=TRNLRealNetwork.Create(Instance);
   try

    // An invalid socket handle has to stay a hard error
    ReceiveResult:=Network.Receive(TRNLSocket(High(TRNLInt32)),nil,Buffer,SizeOf(Buffer),RNL_IPV4);
    Info('receive on an invalid socket handle returned '+TRNLRawByteString(IntToStr(ReceiveResult)));
    CheckAtMostInt64(ReceiveResult,-1,
                     'a receive on an invalid socket handle must be reported as a hard error');

    Socket:=Network.SocketCreate(RNL_SOCKET_TYPE_DATAGRAM,RNL_IPV4);

    if not Check(Socket<>RNL_SOCKET_NULL,'a real UDP socket must be creatable') then begin
     exit;
    end;

    try

     Network.SocketSetOption(Socket,RNL_SOCKET_OPTION_NONBLOCK,1);

     Network.AddressSetHost(Address,'127.0.0.1');
     Address.Port:=CLOSED_PORT;

     // Connecting is what makes the kernel report ICMP errors of this destination back to
     // this socket in the first place
     if not Check(Network.SocketConnect(Socket,Address,RNL_IPV4),
                  'a real UDP socket must be connectable to a closed local port') then begin
      exit;
     end;

     FillChar(Payload,SizeOf(Payload),#$5a);

     CountNegativeResults:=0;

     for Index:=1 to COUNT_ATTEMPTS do begin

      Network.Send(Socket,nil,Payload,SizeOf(Payload),RNL_IPV4);

      ReceiveResult:=Network.Receive(Socket,nil,Buffer,SizeOf(Buffer),RNL_IPV4);

      if ReceiveResult<0 then begin
       inc(CountNegativeResults);
      end;

      Sleep(1);

     end;

     Info(TRNLRawByteString(IntToStr(CountNegativeResults))+' of '+
          TRNLRawByteString(IntToStr(COUNT_ATTEMPTS))+
          ' receive(s) on a connected socket with a closed counter port reported a hard error');

     CheckEqualsInt64(CountNegativeResults,0,
                      'an ICMP induced error of one destination must not be reported as a broken socket, '+
                      'because that would terminate the whole host service loop over a single unreachable peer');

    finally
     Network.SocketDestroy(Socket);
    end;

   finally
    FreeAndNil(Network);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

// ---------------------------------------------------------------------------------------
// Retransmission behaviour
// ---------------------------------------------------------------------------------------

// Exactly one datagram of exactly known content gets lost, so that the measured time is the
// cost of recovering from a single loss and nothing else.
//
// This is the sharpest available assertion on the initial retransmission timeout. Measuring
// the total duration of a bulk transfer under heavy loss would not do, because there the
// backoff dominates, and a configuration with a far too large initial timeout but no working
// backoff at all can easily come out faster than a correct one.
//
// The initial retransmission timeout also has a second, much less obvious job: an
// unacknowledged reliable block packet suppresses the keep alive pings for as long as it is
// outstanding. An initial timeout in the seconds range therefore does not just delay the
// payload, it also blinds the liveness detection of the connection for that whole time, and
// with a connection timeout of ten seconds that gets dangerous quickly.
procedure TestSingleLostReliablePacketIsRecoveredQuickly;
const MESSAGE_PADDING_SIZE=600;
      // Well above the small keep alive and acknowledgement datagrams, so that the drop
      // targets the payload carrying datagram
      DROP_MINIMUM_DATAGRAM_SIZE=400;
var Instance:TRNLInstance;
    VirtualNetwork:TRNLVirtualNetwork;
    FaultInjector:TRNLNetworkFaultInjector;
    HostPair:TRNLTestHostPair;
    Payload:TRNLRawByteString;
    ElapsedMilliseconds,TimeBudgetMilliseconds:TRNLInt64;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('a single lost reliable packet is recovered quickly');
 Watchdog:=TRNLTestWatchdog.Create('single lost reliable packet',60000);
 try

  Instance:=TRNLInstance.Create;
  try
   VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
   try
    FaultInjector:=TRNLNetworkFaultInjector.Create(Instance,VirtualNetwork);
    try

     HostPair:=TRNLTestHostPair.Create(Instance,FaultInjector);
     try

      if not Check(HostPair.Connect(5000),'the handshake must succeed without any injected faults') then begin
       exit;
      end;

      // The recovery may take at most the upper end of the initial retransmission timeout
      // range plus a generous allowance for the round trip and for the service loop
      // granularity of this test
      TimeBudgetMilliseconds:=HostPair.Client.MaximumRetransmissionTimeoutLimit+1000;

      Info('initial retransmission timeout range: '+
           TRNLRawByteString(IntToStr(HostPair.Client.MinimumRetransmissionTimeoutLimit))+' .. '+
           TRNLRawByteString(IntToStr(HostPair.Client.MaximumRetransmissionTimeoutLimit))+' ms');
      Info('time budget: '+TRNLRawByteString(IntToStr(TimeBudgetMilliseconds))+' ms');

      FaultInjector.DropNextOutgoingDatagrams(1,DROP_MINIMUM_DATAGRAM_SIZE);

      Payload:=TestMessageText(1,MESSAGE_PADDING_SIZE);

      HostPair.ClientPeer.Channels[RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_ORDERED].SendMessageRawByteString(Payload);

      if not Check(HostPair.PumpUntilServerReceived(1,30000,ElapsedMilliseconds),
                   'the host service loop must stay alive') then begin
       exit;
      end;

      Info('datagrams deterministically dropped: '+TRNLRawByteString(IntToStr(FaultInjector.CountDeterministicallyDroppedDatagrams)));
      Info('recovery of one lost reliable packet took '+TRNLRawByteString(IntToStr(ElapsedMilliseconds))+' ms');

      if not CheckEqualsInt64(FaultInjector.CountDeterministicallyDroppedDatagrams,1,
                              'the test must actually have dropped exactly one datagram') then begin
       exit;
      end;

      if not CheckEqualsInt64(HostPair.ServerReceivedMessages.Count,1,
                              'the lost reliable message must be retransmitted and arrive') then begin
       exit;
      end;

      CheckEqualsRawByteString(TRNLRawByteString(HostPair.ServerReceivedMessages[0]),Payload,
                               'the retransmitted message must be intact');

      CheckAtMostInt64(ElapsedMilliseconds,TimeBudgetMilliseconds,
                       'the initial retransmission timeout must come from the measured round trip time '+
                       'and not from the backoff ceiling');

      CheckEqualsInt64(HostPair.CountServerDisconnectEvents,0,
                       'a single lost packet must not drop the connection');

     finally
      FreeAndNil(HostPair);
     end;

    finally
     FreeAndNil(FaultInjector);
    end;
   finally
    FreeAndNil(VirtualNetwork);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

// The bulk counterpart: the payload size and the message count are chosen so that every
// message needs its own datagram, and losing several of them is a practical certainty at
// 25 percent loss in both directions.
//
// What this test asserts is that everything arrives, in order, intact, and without the
// connection dropping along the way. The time budget is deliberately generous and only
// catches a true collapse, for two reasons: under loss the exponential backoff dominates the
// total duration, so the spread between runs is naturally large, and a configuration with a
// far too large initial retransmission timeout but no working backoff at all can easily come
// out faster here than a correct one. Pinning down the initial retransmission timeout is the
// job of the single loss test above, which can do it deterministically.
procedure TestReliableTransferUnderPacketLossIsTimely;
const COUNT_MESSAGES=30;
      MESSAGE_PADDING_SIZE=600;
      TIME_BUDGET_MILLISECONDS=60000;
var Instance:TRNLInstance;
    VirtualNetwork:TRNLVirtualNetwork;
    Simulator:TRNLNetworkInterferenceSimulator;
    HostPair:TRNLTestHostPair;
    Index:TRNLSizeInt;
    ElapsedMilliseconds:TRNLInt64;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('reliable transfer under packet loss completes in time');
 Watchdog:=TRNLTestWatchdog.Create('reliable transfer under packet loss',240000);
 try

  Instance:=TRNLInstance.Create;
  try
   VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
   try
    Simulator:=TRNLNetworkInterferenceSimulator.Create(Instance,VirtualNetwork);
    try

     Simulator.SimulatedIncomingPacketLossProbabilityFactor:=PROBABILITY_TWENTY_FIVE_PERCENT;
     Simulator.SimulatedOutgoingPacketLossProbabilityFactor:=PROBABILITY_TWENTY_FIVE_PERCENT;

     HostPair:=TRNLTestHostPair.Create(Instance,Simulator);
     try

      if not Check(HostPair.Connect(20000),'the handshake must survive 25 percent packet loss') then begin
       exit;
      end;

      for Index:=1 to COUNT_MESSAGES do begin
       HostPair.ClientPeer.Channels[RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_ORDERED].SendMessageRawByteString(TestMessageText(Index,MESSAGE_PADDING_SIZE));
      end;

      if not Check(HostPair.PumpUntilServerReceived(COUNT_MESSAGES,120000,ElapsedMilliseconds),
                   'the host service loop must stay alive under packet loss') then begin
       exit;
      end;

      Info('transfer of '+TRNLRawByteString(IntToStr(COUNT_MESSAGES))+
           ' reliable messages of '+TRNLRawByteString(IntToStr(MESSAGE_PADDING_SIZE))+
           ' bytes each under 25 percent loss took '+
           TRNLRawByteString(IntToStr(ElapsedMilliseconds))+' ms');

      if not CheckEqualsInt64(HostPair.ServerReceivedMessages.Count,COUNT_MESSAGES,
                              'all reliable messages must arrive under packet loss') then begin
       exit;
      end;

      CheckAtMostInt64(ElapsedMilliseconds,TIME_BUDGET_MILLISECONDS,
                       'a bulk reliable transfer under heavy packet loss must still make steady progress');

      CheckEqualsInt64(HostPair.CountServerDisconnectEvents,0,
                       'the connection must not drop under 25 percent packet loss');

      CheckEqualsInt64(HostPair.CountClientDisconnectEvents,0,
                       'the connection must not drop under 25 percent packet loss');

      for Index:=1 to COUNT_MESSAGES do begin
       CheckEqualsRawByteString(TRNLRawByteString(HostPair.ServerReceivedMessages[Index-1]),
                                TestMessageText(Index,MESSAGE_PADDING_SIZE),
                                'reliable ordered message '+TRNLRawByteString(IntToStr(Index))+' must arrive in order and intact');
      end;

     finally
      FreeAndNil(HostPair);
     end;

    finally
     FreeAndNil(Simulator);
    end;
   finally
    FreeAndNil(VirtualNetwork);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

// ---------------------------------------------------------------------------------------
// Bandwidth limits
// ---------------------------------------------------------------------------------------

// A new bandwidth limit has to reach the counter side and has to be acknowledged there, so
// that the periodic resending stops again. If the announcement never goes out, then the
// acknowledgement never arrives either, the pending flag is never cleared, and a fresh block
// packet is produced over and over again for the whole lifetime of the peer.
procedure TestBandwidthLimitsReachCounterSide;
const SERVER_INCOMING_BANDWIDTH_LIMIT=8000000;
      SERVER_OUTGOING_BANDWIDTH_LIMIT=4000000;
var Instance:TRNLInstance;
    VirtualNetwork:TRNLVirtualNetwork;
    HostPair:TRNLTestHostPair;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('bandwidth limits reach the counter side and stop being resent');
 Watchdog:=TRNLTestWatchdog.Create('bandwidth limits',60000);
 try

  Instance:=TRNLInstance.Create;
  try
   VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
   try

    HostPair:=TRNLTestHostPair.Create(Instance,VirtualNetwork);
    try

     if not Check(HostPair.Connect(5000),'the handshake must succeed') then begin
      exit;
     end;

     CheckEqualsInt64(HostPair.CountClientBandwidthLimitsEvents,0,
                      'no bandwidth limits event may have arrived before any limit was set');

     HostPair.Server.IncomingBandwidthLimit:=SERVER_INCOMING_BANDWIDTH_LIMIT;
     HostPair.Server.OutgoingBandwidthLimit:=SERVER_OUTGOING_BANDWIDTH_LIMIT;

     if not Check(HostPair.Pump(2000),'the host service loop must stay alive') then begin
      exit;
     end;

     Info('client bandwidth limits events: '+TRNLRawByteString(IntToStr(HostPair.CountClientBandwidthLimitsEvents)));
     Info('client peer RemoteIncomingBandwidthLimit = '+TRNLRawByteString(IntToStr(HostPair.ClientPeer.RemoteIncomingBandwidthLimit)));
     Info('client peer RemoteOutgoingBandwidthLimit = '+TRNLRawByteString(IntToStr(HostPair.ClientPeer.RemoteOutgoingBandwidthLimit)));

     CheckAtLeastInt64(HostPair.CountClientBandwidthLimitsEvents,1,
                       'the client must be informed about the new bandwidth limits of the server');

     CheckEqualsInt64(HostPair.ClientPeer.RemoteIncomingBandwidthLimit,SERVER_INCOMING_BANDWIDTH_LIMIT,
                      'the incoming bandwidth limit of the server must arrive at the client');

     CheckEqualsInt64(HostPair.ClientPeer.RemoteOutgoingBandwidthLimit,SERVER_OUTGOING_BANDWIDTH_LIMIT,
                      'the outgoing bandwidth limit of the server must arrive at the client');

     // The resending has to stop once the acknowledgement arrived, otherwise a fresh block
     // packet would keep being produced every PendingSendNewBandwidthLimitsSendTimeout
     if not Check(HostPair.Pump(1000),'the host service loop must stay alive') then begin
      exit;
     end;

     CheckEqualsInt64(HostPair.CountClientBandwidthLimitsEvents,1,
                      'the bandwidth limits must be acknowledged and therefore announced exactly once');

    finally
     FreeAndNil(HostPair);
    end;

   finally
    FreeAndNil(VirtualNetwork);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

// ---------------------------------------------------------------------------------------
// MTU probing
// ---------------------------------------------------------------------------------------

// The datagram size limit of the fault injector makes the MTU probing actually walk down
// through the known common MTU sizes, which is what happens on a real network, but which no
// simulator based test could produce before, since TRNLVirtualNetwork has no MTU at all and
// would therefore let the very first and largest probe succeed right away.
//
// The watchdog is the important part of this test: the outgoing MTU probe dispatching peeks
// a block packet, and every code path through it has to either dequeue that block packet or
// leave the loop, otherwise the next peek hands out the very same block packet again and the
// service thread spins forever. Without a watchdog such a defect just hangs the test process
// and reports nothing at all.
procedure TestMTUProbingTerminatesAndReportsAMTU;
const SIMULATED_PATH_MTU=1500;
      // TRNLHost sends a datagram of the MTU minus the assumed IP and UDP header sizes
      SIMULATED_MAXIMUM_DATAGRAM_SIZE=SIMULATED_PATH_MTU-(60+8);
var Instance:TRNLInstance;
    VirtualNetwork:TRNLVirtualNetwork;
    FaultInjector:TRNLNetworkFaultInjector;
    HostPair:TRNLTestHostPair;
    ElapsedMilliseconds:TRNLInt64;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('MTU probing terminates and reports a MTU');
 Watchdog:=TRNLTestWatchdog.Create('MTU probing',60000);
 try

  Instance:=TRNLInstance.Create;
  try
   VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
   try
    FaultInjector:=TRNLNetworkFaultInjector.Create(Instance,VirtualNetwork);
    try

     HostPair:=TRNLTestHostPair.Create(Instance,FaultInjector);
     try

      if not Check(HostPair.Connect(5000),'the handshake must succeed') then begin
       exit;
      end;

      FaultInjector.MaximumDatagramSize:=SIMULATED_MAXIMUM_DATAGRAM_SIZE;

      HostPair.ClientPeer.MTUProbe(3,40);

      if not Check(HostPair.PumpUntilClientMTUEvent(1,20000,ElapsedMilliseconds),
                   'MTU probing must not terminate the host service loop') then begin
       exit;
      end;

      Info('MTU probing took '+TRNLRawByteString(IntToStr(ElapsedMilliseconds))+' ms');
      Info('oversized MTU probes rejected: '+TRNLRawByteString(IntToStr(FaultInjector.CountOversizedDatagrams)));
      Info('client MTU events: '+TRNLRawByteString(IntToStr(HostPair.CountClientMTUEvents)));
      Info('negotiated client MTU: '+TRNLRawByteString(IntToStr(HostPair.LastClientMTU)));
      Info('negotiated server MTU: '+TRNLRawByteString(IntToStr(HostPair.LastServerMTU)));

      CheckAtLeastInt64(FaultInjector.CountOversizedDatagrams,1,
                        'the probing must actually have run into the simulated path MTU');

      CheckAtLeastInt64(HostPair.CountClientMTUEvents,1,
                        'the MTU probing must terminate and report a MTU');

      CheckAtMostInt64(HostPair.LastClientMTU,SIMULATED_PATH_MTU,
                       'the negotiated MTU must not exceed the simulated path MTU');

      CheckAtLeastInt64(HostPair.LastClientMTU,RNL_MINIMUM_MTU,
                        'the negotiated MTU must not fall below the minimum MTU');

      // The counter side has to end up with the very same MTU, otherwise one of the two
      // sides would keep building datagrams which the other side can never receive
      CheckEqualsInt64(HostPair.LastServerMTU,HostPair.LastClientMTU,
                       'both sides must agree on the negotiated MTU');

      CheckEqualsInt64(HostPair.CountClientDisconnectEvents,0,
                       'MTU probing must not drop the connection');

      // And the connection has to still work afterwards with the new MTU
      HostPair.ClientPeer.Channels[RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_ORDERED].SendMessageRawByteString(TestMessageText(1,600));

      if not Check(HostPair.PumpUntilServerReceived(1,10000,ElapsedMilliseconds),
                   'the host service loop must stay alive after MTU probing') then begin
       exit;
      end;

      CheckEqualsInt64(HostPair.ServerReceivedMessages.Count,1,
                       'reliable messages must still get through after MTU probing');

     finally
      FreeAndNil(HostPair);
     end;

    finally
     FreeAndNil(FaultInjector);
    end;
   finally
    FreeAndNil(VirtualNetwork);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

// ---------------------------------------------------------------------------------------
// Interruptible hosts
// ---------------------------------------------------------------------------------------

// An interruptible host waits on its sockets and on an additional event object at the same
// time. If the readiness of that event object is not actually checked, then every single
// wait, including every plain timeout, reports a service interrupt, so that Service returns
// RNL_HOST_SERVICE_STATUS_INTERRUPT on every single call and the application loop just
// busy-spins at full CPU load.
//
// This deliberately uses TRNLRealNetwork, because that is the only network implementation
// which goes through the platform specific poll and select code paths at all.
procedure TestInterruptibleHostBlocksUntilItsTimeout;
const SERVICE_TIMEOUT_MILLISECONDS=200;
      COUNT_ITERATIONS=5;
var Instance:TRNLInstance;
    Network:TRNLRealNetwork;
    Host:TRNLHost;
    Event:TRNLHostEvent;
    Status:TRNLHostServiceStatus;
    Index,CountInterrupts,CountTimeouts:TRNLSizeInt;
    StartTime:TRNLTime;
    ElapsedMilliseconds:TRNLInt64;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('an interruptible host blocks until its timeout');
 Watchdog:=TRNLTestWatchdog.Create('interruptible blocking',60000);
 try

  Instance:=TRNLInstance.Create;
  try
   Network:=TRNLRealNetwork.Create(Instance);
   try
    Host:=TRNLHost.Create(Instance,Network);
    try

     Host.Address.Host:=RNL_HOST_ANY;
     // An ephemeral port, so that this test can never collide with anything
     Host.Address.Port:=0;
     Host.Interruptible:=true;
     Host.Start(RNL_HOST_ADDRESS_FAMILY_WORK_MODE_IPV4_ONLY);

     if not Check(Host.Interruptible,'the host must be interruptible for this test') then begin
      exit;
     end;

     CountInterrupts:=0;
     CountTimeouts:=0;

     Event.Initialize;
     try

      StartTime:=Instance.Time;

      for Index:=1 to COUNT_ITERATIONS do begin
       Status:=Host.Service(Event,SERVICE_TIMEOUT_MILLISECONDS);
       Event.Free;
       case Status of
        RNL_HOST_SERVICE_STATUS_INTERRUPT:begin
         inc(CountInterrupts);
        end;
        RNL_HOST_SERVICE_STATUS_TIMEOUT:begin
         inc(CountTimeouts);
        end;
        else begin
         // An idle host must produce neither events nor errors here
        end;
       end;
      end;

      ElapsedMilliseconds:=TRNLTime.RelativeDifference(Instance.Time,StartTime);

     finally
      Event.Free;
     end;

     Info(TRNLRawByteString(IntToStr(COUNT_ITERATIONS))+' x Service(Event,'+
          TRNLRawByteString(IntToStr(SERVICE_TIMEOUT_MILLISECONDS))+') took '+
          TRNLRawByteString(IntToStr(ElapsedMilliseconds))+' ms, '+
          TRNLRawByteString(IntToStr(CountTimeouts))+' timeout(s), '+
          TRNLRawByteString(IntToStr(CountInterrupts))+' interrupt(s)');

     CheckEqualsInt64(CountInterrupts,0,
                      'an idle interruptible host must not report a service interrupt without an actual Interrupt call');

     CheckEqualsInt64(CountTimeouts,COUNT_ITERATIONS,
                      'an idle interruptible host must report a timeout');

     // Proves that it really did block instead of returning immediately, with a generous
     // lower bound, so that a coarse system timer resolution can not make this flaky
     CheckAtLeastInt64(ElapsedMilliseconds,(SERVICE_TIMEOUT_MILLISECONDS*COUNT_ITERATIONS*3) div 4,
                       'the host must actually have blocked for its timeout instead of busy-spinning');

    finally
     FreeAndNil(Host);
    end;
   finally
    FreeAndNil(Network);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

// The counterpart of the test above: checking the readiness of the event object must not
// break the interrupt feature itself
procedure TestInterruptibleHostWakesUpOnInterrupt;
const SERVICE_TIMEOUT_MILLISECONDS=5000;
      INTERRUPT_DELAY_MILLISECONDS=150;
var Instance:TRNLInstance;
    Network:TRNLRealNetwork;
    Host:TRNLHost;
    Event:TRNLHostEvent;
    Status:TRNLHostServiceStatus;
    StartTime:TRNLTime;
    ElapsedMilliseconds:TRNLInt64;
    Interrupter:TRNLTestInterrupterThread;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('an interruptible host wakes up on Interrupt');
 Watchdog:=TRNLTestWatchdog.Create('interruptible wake up',60000);
 try

  Instance:=TRNLInstance.Create;
  try
   Network:=TRNLRealNetwork.Create(Instance);
   try
    Host:=TRNLHost.Create(Instance,Network);
    try

     Host.Address.Host:=RNL_HOST_ANY;
     Host.Address.Port:=0;
     Host.Interruptible:=true;
     Host.Start(RNL_HOST_ADDRESS_FAMILY_WORK_MODE_IPV4_ONLY);

     Interrupter:=TRNLTestInterrupterThread.Create(Host,INTERRUPT_DELAY_MILLISECONDS);
     try

      Event.Initialize;
      try
       StartTime:=Instance.Time;
       Status:=Host.Service(Event,SERVICE_TIMEOUT_MILLISECONDS);
       ElapsedMilliseconds:=TRNLTime.RelativeDifference(Instance.Time,StartTime);
      finally
       Event.Free;
      end;

      Info('Service returned after '+TRNLRawByteString(IntToStr(ElapsedMilliseconds))+' ms');

      Check(Status=RNL_HOST_SERVICE_STATUS_INTERRUPT,
            'Service must report a service interrupt after an Interrupt call');

      CheckAtMostInt64(ElapsedMilliseconds,SERVICE_TIMEOUT_MILLISECONDS div 2,
                       'Service must wake up on the Interrupt call well before its timeout');

     finally
      Interrupter.WaitFor;
      FreeAndNil(Interrupter);
     end;

    finally
     FreeAndNil(Host);
    end;
   finally
    FreeAndNil(Network);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

// ---------------------------------------------------------------------------------------
// Test tooling correctness
// ---------------------------------------------------------------------------------------

// Every test which believes it exercises corrupted outgoing packets relies on this actually
// working, so it is worth an explicit test of its own
procedure TestOutgoingBitFlippingSimulationActuallyFlipsBits;
const COUNT_ROUNDS=20;
      PAYLOAD_SIZE=256;
var Instance:TRNLInstance;
    VirtualNetwork:TRNLVirtualNetwork;
    Simulator:TRNLNetworkInterferenceSimulator;
    SenderSocket,ReceiverSocket:TRNLSocket;
    SenderAddress,ReceiverAddress,FromAddress:TRNLAddress;
    SentPayload,ReceivedPayload:array[0..PAYLOAD_SIZE-1] of TRNLUInt8;
    Index,Round,CountFlipped,CountReceived,ReceivedLength:TRNLSizeInt;
begin

 TestBegin('the outgoing bit flipping simulation actually flips bits');
 try

  Instance:=TRNLInstance.Create;
  try
   VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
   try
    Simulator:=TRNLNetworkInterferenceSimulator.Create(Instance,VirtualNetwork);
    try

     Simulator.SimulatedOutgoingBitFlippingProbabilityFactor:=PROBABILITY_ALWAYS;
     Simulator.SimulatedOutgoingMinimumFlippingBits:=1;
     Simulator.SimulatedOutgoingMaximumFlippingBits:=4;

     SenderSocket:=Simulator.SocketCreate(RNL_SOCKET_TYPE_DATAGRAM,RNL_IPV4);
     ReceiverSocket:=Simulator.SocketCreate(RNL_SOCKET_TYPE_DATAGRAM,RNL_IPV4);

     if not Check((SenderSocket<>RNL_SOCKET_NULL) and (ReceiverSocket<>RNL_SOCKET_NULL),
                  'both virtual sockets must be creatable') then begin
      exit;
     end;

     Simulator.AddressSetHost(SenderAddress,'127.0.0.1');
     SenderAddress.Port:=19001;

     Simulator.AddressSetHost(ReceiverAddress,'127.0.0.1');
     ReceiverAddress.Port:=19002;

     if not Check(Simulator.SocketBind(SenderSocket,@SenderAddress,RNL_IPV4) and
                  Simulator.SocketBind(ReceiverSocket,@ReceiverAddress,RNL_IPV4),
                  'both virtual sockets must be bindable') then begin
      exit;
     end;

     for Index:=0 to PAYLOAD_SIZE-1 do begin
      SentPayload[Index]:=TRNLUInt8(Index and $ff);
     end;

     CountFlipped:=0;
     CountReceived:=0;

     for Round:=1 to COUNT_ROUNDS do begin

      if Simulator.Send(SenderSocket,@ReceiverAddress,SentPayload,PAYLOAD_SIZE,RNL_IPV4)<>PAYLOAD_SIZE then begin
       continue;
      end;

      FillChar(ReceivedPayload,SizeOf(ReceivedPayload),#0);

      ReceivedLength:=Simulator.Receive(ReceiverSocket,@FromAddress,ReceivedPayload,PAYLOAD_SIZE,RNL_IPV4);

      if ReceivedLength<>PAYLOAD_SIZE then begin
       continue;
      end;

      inc(CountReceived);

      if not CompareMem(@SentPayload,@ReceivedPayload,PAYLOAD_SIZE) then begin
       inc(CountFlipped);
      end;

     end;

     Info(TRNLRawByteString(IntToStr(CountReceived))+' of '+TRNLRawByteString(IntToStr(COUNT_ROUNDS))+
          ' datagram(s) received, '+TRNLRawByteString(IntToStr(CountFlipped))+' of them corrupted');

     if not CheckEqualsInt64(CountReceived,COUNT_ROUNDS,
                             'every datagram must arrive, since no packet loss is configured') then begin
      exit;
     end;

     // Flipping one to four bits can in principle cancel itself out, so this deliberately
     // does not demand every single round
     CheckAtLeastInt64(CountFlipped,COUNT_ROUNDS-2,
                       'the configured outgoing bit flipping must actually corrupt the datagrams');

    finally
     FreeAndNil(Simulator);
    end;
   finally
    FreeAndNil(VirtualNetwork);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  TestEnd;
 end;

end;


// ---------------------------------------------------------------------------------------
// Message size constraints
// ---------------------------------------------------------------------------------------

// A reliable message is split into block packets in one single dispatching round, so it has
// to fit into the send window as a whole. A message needing more block packets than the window
// has slots can therefore never be sent, no matter how long one waits.
//
// Such a message must not be allowed to sit at the head of the outgoing message queue, because
// it would take every later message on that channel down with it, and the result looks exactly
// like one dead channel on an otherwise perfectly healthy connection: no error, no event, no
// disconnect, the pings keep flowing, and the payload silently stops.
procedure TestOversizedReliableMessageDoesNotStallTheChannel;
var Instance:TRNLInstance;
    VirtualNetwork:TRNLVirtualNetwork;
    HostPair:TRNLTestHostPair;
    Channel:TRNLPeerReliableChannel;
    MaximumMessageSize:TRNLSizeUInt;
    Oversized,Payload:TRNLRawByteString;
    ElapsedMilliseconds:TRNLInt64;
    DroppedBefore:TRNLUInt64;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('an oversized reliable message does not stall its channel');
 Watchdog:=TRNLTestWatchdog.Create('oversized reliable message',60000);
 try

  Instance:=TRNLInstance.Create;
  try
   VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
   try

    HostPair:=TRNLTestHostPair.Create(Instance,VirtualNetwork);
    try

     if not Check(HostPair.Connect(5000),'the handshake must succeed') then begin
      exit;
     end;

     Channel:=TRNLPeerReliableChannel(HostPair.ClientPeer.Channels[RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_ORDERED]);

     MaximumMessageSize:=Channel.MaximumMessageSize;

     Info('peer MTU: '+TRNLRawByteString(IntToStr(HostPair.ClientPeer.MTU)));
     Info('reliable channel window size: '+TRNLRawByteString(IntToStr(HostPair.Client.ReliableChannelBlockPacketWindowSize)));
     Info('reliable channel MaximumMessageSize: '+TRNLRawByteString(IntToStr(MaximumMessageSize)));
     Info('host MaximumMessageSize: '+TRNLRawByteString(IntToStr(HostPair.Client.MaximumMessageSize)));

     if not Check(MaximumMessageSize>0,'the channel must report a usable maximum message size') then begin
      exit;
     end;

     // The library wide limit is deliberately far above what a single window can carry, so an
     // application can ask for a message which is accepted by the one and impossible for the
     // other. That gap is exactly where the stall used to happen.
     Check(HostPair.Client.MaximumMessageSize>MaximumMessageSize,
           'this test only makes sense while the host wide message size limit is the larger one');

     DroppedBefore:=HostPair.Client.TotalDroppedOutgoingMessages;

     Oversized:=TRNLRawByteString(StringOfChar('O',MaximumMessageSize+1));
     Payload:=TestMessageText(1,600);

     // The oversized one first, so that it would be the head of the queue blocking the other
     Channel.SendMessageRawByteString(Oversized);
     Channel.SendMessageRawByteString(Payload);

     if not Check(HostPair.PumpUntilServerReceived(1,10000,ElapsedMilliseconds),
                  'the host service loop must stay alive') then begin
      exit;
     end;

     Info('messages dropped by the client: '+
          TRNLRawByteString(IntToStr(HostPair.Client.TotalDroppedOutgoingMessages-DroppedBefore)));
     Info('elapsed: '+TRNLRawByteString(IntToStr(ElapsedMilliseconds))+' ms');

     CheckEqualsInt64(TRNLInt64(HostPair.Client.TotalDroppedOutgoingMessages-DroppedBefore),1,
                      'the oversized message must be dropped, and exactly once');

     if not CheckEqualsInt64(HostPair.ServerReceivedMessages.Count,1,
                             'the message queued behind the oversized one must still get through') then begin
      exit;
     end;

     CheckEqualsRawByteString(TRNLRawByteString(HostPair.ServerReceivedMessages[0]),Payload,
                              'and it must arrive intact');

     // A message of exactly the reported maximum size has to be accepted, otherwise the
     // reported limit would be off by one and applications could not rely on it
     DroppedBefore:=HostPair.Client.TotalDroppedOutgoingMessages;

     Payload:=TRNLRawByteString(StringOfChar('M',MaximumMessageSize));

     Channel.SendMessageRawByteString(Payload);

     if not Check(HostPair.PumpUntilServerReceived(2,30000,ElapsedMilliseconds),
                  'the host service loop must stay alive') then begin
      exit;
     end;

     Info('a message of exactly MaximumMessageSize took '+TRNLRawByteString(IntToStr(ElapsedMilliseconds))+' ms');

     CheckEqualsInt64(TRNLInt64(HostPair.Client.TotalDroppedOutgoingMessages-DroppedBefore),0,
                      'a message of exactly the reported maximum size must not be dropped');

     if CheckEqualsInt64(HostPair.ServerReceivedMessages.Count,2,
                         'a message of exactly the reported maximum size must arrive') then begin
      CheckEqualsInt64(length(HostPair.ServerReceivedMessages[1]),TRNLInt64(MaximumMessageSize),
                       'and it must arrive complete');
     end;

    finally
     FreeAndNil(HostPair);
    end;

   finally
    FreeAndNil(VirtualNetwork);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

// ---------------------------------------------------------------------------------------
// Keep alive independence
// ---------------------------------------------------------------------------------------

// The keep alive pings are the only liveness signal of an otherwise idle connection. If they
// are suppressed while any other traffic is pending, then their delivery depends on the
// correctness of the outgoing queues and of the unacknowledged block packet accounting, and any
// block packet stuck in a queue silently switches the liveness detection off.
//
// This reproduces exactly that situation: both sides have an unacknowledged reliable block
// packet outstanding, and the datagrams carrying it are too large for the simulated path, so
// its retransmissions never arrive either. Only the small ping and acknowledgement datagrams
// still fit. If the pings are gated on the pending traffic, then no datagram of any kind is
// exchanged any more and both sides run into their connection timeout.
procedure TestKeepAliveSurvivesOutstandingReliableBlockPackets;
const SMALL_DATAGRAM_LIMIT=400;
      MESSAGE_PADDING_SIZE=600;
var Instance:TRNLInstance;
    VirtualNetwork:TRNLVirtualNetwork;
    FaultInjector:TRNLNetworkFaultInjector;
    HostPair:TRNLTestHostPair;
    IdleMilliseconds,ElapsedMilliseconds:TRNLInt64;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('keep alive survives outstanding reliable block packets');
 Watchdog:=TRNLTestWatchdog.Create('keep alive with pending traffic',180000);
 try

  Instance:=TRNLInstance.Create;
  try
   VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
   try
    FaultInjector:=TRNLNetworkFaultInjector.Create(Instance,VirtualNetwork);
    try

     HostPair:=TRNLTestHostPair.Create(Instance,FaultInjector);
     try

      if not Check(HostPair.Connect(5000),'the handshake must succeed without any injected faults') then begin
       exit;
      end;

      if not Check(assigned(HostPair.ServerPeer),'the server side peer must be known') then begin
       exit;
      end;

      // Well beyond the connection timeout, so that a suppressed keep alive really does show up
      IdleMilliseconds:=TRNLInt64(HostPair.Client.ConnectionTimeout)+(TRNLInt64(HostPair.Client.ConnectionTimeout) div 2);

      Info('connection timeout: '+TRNLRawByteString(IntToStr(HostPair.Client.ConnectionTimeout))+' ms');
      Info('idle period under test: '+TRNLRawByteString(IntToStr(IdleMilliseconds))+' ms');

      // Only the small keep alive and acknowledgement datagrams still fit through
      FaultInjector.MaximumDatagramSize:=SMALL_DATAGRAM_LIMIT;

      // Both directions, so that neither side can keep the other one warm with its own pings
      HostPair.ClientPeer.Channels[RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_ORDERED].SendMessageRawByteString(TestMessageText(1,MESSAGE_PADDING_SIZE));
      HostPair.ServerPeer.Channels[RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_ORDERED].SendMessageRawByteString(TestMessageText(2,MESSAGE_PADDING_SIZE));

      if not Check(HostPair.Pump(IdleMilliseconds),'the host service loop must stay alive') then begin
       exit;
      end;

      Info('oversized datagrams rejected: '+TRNLRawByteString(IntToStr(FaultInjector.CountOversizedDatagrams)));

      CheckAtLeastInt64(FaultInjector.CountOversizedDatagrams,1,
                        'the test must actually have blocked the payload carrying datagrams');

      CheckEqualsInt64(HostPair.ServerReceivedMessages.Count,0,
                       'no payload can have arrived while its datagrams do not fit');

      CheckEqualsInt64(HostPair.ClientReceivedMessages.Count,0,
                       'no payload can have arrived while its datagrams do not fit');

      CheckEqualsInt64(HostPair.CountServerDisconnectEvents,0,
                       'the server must not drop the connection, the keep alive pings still fit through');

      CheckEqualsInt64(HostPair.CountClientDisconnectEvents,0,
                       'the client must not drop the connection, the keep alive pings still fit through');

      // And once the datagrams fit again, both pending messages have to arrive on their own
      FaultInjector.MaximumDatagramSize:=0;

      if not Check(HostPair.PumpUntilServerReceived(1,20000,ElapsedMilliseconds),
                   'the host service loop must stay alive while recovering') then begin
       exit;
      end;

      if not Check(HostPair.PumpUntilClientReceived(1,20000,ElapsedMilliseconds),
                   'the host service loop must stay alive while recovering') then begin
       exit;
      end;

      CheckEqualsInt64(HostPair.ServerReceivedMessages.Count,1,
                       'the pending message towards the server must arrive after the recovery');

      CheckEqualsInt64(HostPair.ClientReceivedMessages.Count,1,
                       'the pending message towards the client must arrive after the recovery');

     finally
      FreeAndNil(HostPair);
     end;

    finally
     FreeAndNil(FaultInjector);
    end;
   finally
    FreeAndNil(VirtualNetwork);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

// ---------------------------------------------------------------------------------------
// MTU limits
// ---------------------------------------------------------------------------------------

// TRNLVirtualNetwork has no MTU whatsoever, so probing over it succeeds with the very first and
// largest probe size it is offered. That makes it the ideal way to check that the probing can
// not talk either side into an MTU outside of the range the library declares to support, no
// matter what the path would technically carry.
procedure TestMTUProbingStaysWithinTheDeclaredLimits;
var Instance:TRNLInstance;
    VirtualNetwork:TRNLVirtualNetwork;
    HostPair:TRNLTestHostPair;
    ElapsedMilliseconds:TRNLInt64;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('MTU probing stays within the declared limits');
 Watchdog:=TRNLTestWatchdog.Create('MTU probing limits',60000);
 try

  Instance:=TRNLInstance.Create;
  try
   VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
   try

    HostPair:=TRNLTestHostPair.Create(Instance,VirtualNetwork);
    try

     if not Check(HostPair.Connect(5000),'the handshake must succeed') then begin
      exit;
     end;

     Info('MTU before probing: '+TRNLRawByteString(IntToStr(HostPair.ClientPeer.MTU)));

     HostPair.ClientPeer.MTUProbe(3,20);

     if not Check(HostPair.PumpUntilClientMTUEvent(1,20000,ElapsedMilliseconds),
                  'MTU probing must terminate') then begin
      exit;
     end;

     Info('MTU probing took '+TRNLRawByteString(IntToStr(ElapsedMilliseconds))+' ms');
     Info('client peer MTU after probing: '+TRNLRawByteString(IntToStr(HostPair.ClientPeer.MTU)));
     Info('server peer MTU after probing: '+TRNLRawByteString(IntToStr(HostPair.ServerPeer.MTU)));
     Info('RNL_MINIMUM_MTU = '+TRNLRawByteString(IntToStr(RNL_MINIMUM_MTU))+
          ', RNL_MAXIMUM_MTU = '+TRNLRawByteString(IntToStr(RNL_MAXIMUM_MTU)));

     CheckAtLeastInt64(HostPair.ClientPeer.MTU,RNL_MINIMUM_MTU,
                       'the negotiated MTU must not fall below the declared minimum');

     CheckAtMostInt64(HostPair.ClientPeer.MTU,RNL_MAXIMUM_MTU,
                      'the negotiated MTU must not exceed the declared maximum, not even on a network without any MTU at all');

     CheckAtLeastInt64(HostPair.ServerPeer.MTU,RNL_MINIMUM_MTU,
                       'the negotiated MTU must not fall below the declared minimum on the responding side either');

     CheckAtMostInt64(HostPair.ServerPeer.MTU,RNL_MAXIMUM_MTU,
                      'the negotiated MTU must not exceed the declared maximum on the responding side either');

     CheckEqualsInt64(HostPair.ServerPeer.MTU,HostPair.ClientPeer.MTU,
                      'both sides must agree on the negotiated MTU');

     // And the connection has to still work with whatever was negotiated
     HostPair.ClientPeer.Channels[RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_ORDERED].SendMessageRawByteString(TestMessageText(1,600));

     if not Check(HostPair.PumpUntilServerReceived(1,10000,ElapsedMilliseconds),
                  'the host service loop must stay alive after probing') then begin
      exit;
     end;

     CheckEqualsInt64(HostPair.ServerReceivedMessages.Count,1,
                      'reliable messages must still get through after probing');

    finally
     FreeAndNil(HostPair);
    end;

   finally
    FreeAndNil(VirtualNetwork);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

// A block packet is built for the MTU which was current at the time, and the MTU can shrink
// afterwards, for example because a second probing run found a smaller path. From that moment
// on such a block packet no longer fits into a datagram of the new MTU.
//
// It must not be allowed to block the outgoing queue of its peer, because that queue carries
// everything: the acknowledgements, the pongs and the disconnect blocks of that peer. One stuck
// block packet in there silences the whole connection without reporting anything anywhere.
procedure TestShrinkingMTUDoesNotBlockTheOutgoingQueue;
const LARGE_PATH_MTU=RNL_MAXIMUM_MTU;
      SMALL_PATH_MTU=RNL_MINIMUM_MTU;
      HEADER_ALLOWANCE=60+8;
var Instance:TRNLInstance;
    VirtualNetwork:TRNLVirtualNetwork;
    FaultInjector:TRNLNetworkFaultInjector;
    HostPair:TRNLTestHostPair;
    LargeMessage:TRNLRawByteString;
    ElapsedMilliseconds:TRNLInt64;
    MTUAfterGrowing:TRNLSizeUInt;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('a shrinking MTU does not block the outgoing queue');
 Watchdog:=TRNLTestWatchdog.Create('shrinking MTU',180000);
 try

  Instance:=TRNLInstance.Create;
  try
   VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
   try
    FaultInjector:=TRNLNetworkFaultInjector.Create(Instance,VirtualNetwork);
    try

     HostPair:=TRNLTestHostPair.Create(Instance,FaultInjector);
     try

      if not Check(HostPair.Connect(5000),'the handshake must succeed without any injected faults') then begin
       exit;
      end;

      // First negotiate the largest MTU this library supports
      FaultInjector.MaximumDatagramSize:=LARGE_PATH_MTU-HEADER_ALLOWANCE;

      HostPair.ClientPeer.MTUProbe(3,20);

      if not Check(HostPair.PumpUntilClientMTUEvent(1,20000,ElapsedMilliseconds),
                   'the first MTU probing must terminate') then begin
       exit;
      end;

      MTUAfterGrowing:=HostPair.ClientPeer.MTU;

      Info('MTU after the first probing: '+TRNLRawByteString(IntToStr(MTUAfterGrowing)));

      if not Check(MTUAfterGrowing>SMALL_PATH_MTU,
                   'the first probing must have negotiated an MTU which can then actually shrink') then begin
       exit;
      end;

      // Now queue a message whose fragments are built for the large MTU, and make sure they
      // can not leave, so that they are still outstanding when the MTU shrinks
      FaultInjector.MaximumDatagramSize:=SMALL_PATH_MTU-HEADER_ALLOWANCE;

      LargeMessage:=TRNLRawByteString(StringOfChar('L',MTUAfterGrowing*3));

      HostPair.ClientPeer.Channels[RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_ORDERED].SendMessageRawByteString(LargeMessage);

      if not Check(HostPair.Pump(500),'the host service loop must stay alive') then begin
       exit;
      end;

      // And shrink the MTU underneath those already constructed block packets
      HostPair.ClientPeer.MTUProbe(3,20);

      if not Check(HostPair.Pump(5000),'the second MTU probing must not terminate the host service loop') then begin
       exit;
      end;

      Info('MTU after the second probing: '+TRNLRawByteString(IntToStr(HostPair.ClientPeer.MTU)));
      Info('oversized datagrams rejected: '+TRNLRawByteString(IntToStr(FaultInjector.CountOversizedDatagrams)));

      CheckAtMostInt64(HostPair.ClientPeer.MTU,MTUAfterGrowing,
                       'the second probing must not have grown the MTU');

      // The decisive part: the queue must still be flowing. The keep alive of this connection
      // travels through the very same outgoing queue as the stuck block packets, so surviving
      // well past the connection timeout proves that nothing is blocking it.
      if not Check(HostPair.Pump(TRNLInt64(HostPair.Client.ConnectionTimeout)+
                                 (TRNLInt64(HostPair.Client.ConnectionTimeout) div 2)),
                   'the host service loop must stay alive') then begin
       exit;
      end;

      CheckEqualsInt64(HostPair.CountClientDisconnectEvents,0,
                       'the client must not drop the connection because of a block packet which no longer fits');

      CheckEqualsInt64(HostPair.CountServerDisconnectEvents,0,
                       'the server must not drop the connection because of a block packet which no longer fits');

      // And once the path carries the built fragments again, the message has to arrive
      FaultInjector.MaximumDatagramSize:=0;

      if not Check(HostPair.PumpUntilServerReceived(1,30000,ElapsedMilliseconds),
                   'the host service loop must stay alive while recovering') then begin
       exit;
      end;

      Info('recovery took '+TRNLRawByteString(IntToStr(ElapsedMilliseconds))+' ms');

      if CheckEqualsInt64(HostPair.ServerReceivedMessages.Count,1,
                          'the pending message must arrive once its datagrams fit again') then begin
       CheckEqualsInt64(length(HostPair.ServerReceivedMessages[0]),TRNLInt64(length(LargeMessage)),
                        'and it must arrive complete');
      end;

     finally
      FreeAndNil(HostPair);
     end;

    finally
     FreeAndNil(FaultInjector);
    end;
   finally
    FreeAndNil(VirtualNetwork);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;


// ---------------------------------------------------------------------------------------
// Container behaviour
// ---------------------------------------------------------------------------------------

// The queues of RNL back up in exactly the situations which matter most: a peer which stops
// acknowledging, a burst which the socket does not accept right now, an application which does
// not drain its events fast enough. Growing such a queue by a single element per enqueue makes
// growing it to n elements cost O(n^2) element copies, all of it while holding the queue lock,
// which turns into a multi second freeze of the service thread and is indistinguishable from a
// deadlock when looked at in a debugger.
//
// This goes straight at the container rather than through a host, because the quadratic term
// only becomes unmistakable at element counts which no host level test would ever produce.
procedure TestQueueGrowthIsNotQuadratic;
const COUNT_ITEMS=200000;
      TIME_BUDGET_MILLISECONDS=2000;
var Instance:TRNLInstance;
    Queue:TRNLQueue<TRNLSizeInt>;
    Index,Value:TRNLSizeInt;
    StartTime:TRNLTime;
    ElapsedMilliseconds:TRNLInt64;
    Ordered:boolean;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('queue growth is not quadratic');
 Watchdog:=TRNLTestWatchdog.Create('queue growth',120000);
 try

  Instance:=TRNLInstance.Create;
  try

   Queue:=TRNLQueue<TRNLSizeInt>.Create;
   try

    StartTime:=Instance.Time;

    for Index:=1 to COUNT_ITEMS do begin
     Queue.Enqueue(Index);
    end;

    ElapsedMilliseconds:=TRNLTime.RelativeDifference(Instance.Time,StartTime);

    Info('enqueueing '+TRNLRawByteString(IntToStr(COUNT_ITEMS))+' items took '+
         TRNLRawByteString(IntToStr(ElapsedMilliseconds))+' ms');

    CheckEqualsInt64(Queue.Count,COUNT_ITEMS,'every item must be in the queue');

    CheckAtMostInt64(ElapsedMilliseconds,TIME_BUDGET_MILLISECONDS,
                     'enqueueing must not degrade into a quadratic number of element copies');

    // And the queue has to still be a queue afterwards, in order and complete
    Ordered:=true;
    for Index:=1 to COUNT_ITEMS do begin
     if not Queue.Dequeue(Value) then begin
      Ordered:=false;
      break;
     end;
     if Value<>Index then begin
      Ordered:=false;
      break;
     end;
    end;

    Check(Ordered,'the geometric growth must not disturb the order or completeness of the queue');

    CheckEqualsInt64(Queue.Count,0,'the queue must be empty again afterwards');

   finally
    FreeAndNil(Queue);
   end;

  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

// ---------------------------------------------------------------------------------------
// Address changes
// ---------------------------------------------------------------------------------------

// The source address of a peer does change in practice, through a NAT rebinding after an idle
// period, through a carrier grade NAT reassigning its ports, or through a handover between
// networks. A host has to follow such a change, and it may only do so for a datagram which
// authenticated correctly and passed the replay window, so that an address can not be moved by
// anyone who merely knows a peer ID.
//
// Not following it does not produce a clean failure either. Since the peer lookup goes by peer
// ID, the receiving side keeps receiving and therefore keeps considering the connection alive,
// while everything it sends goes to an address which no longer exists. The result is a half open
// connection which the connection timeout can not clean up, because incoming traffic keeps
// refreshing it.
procedure TestPeerFollowsAnAuthenticatedAddressChange;
const SERVER_PORT=18244;
      CLIENT_PORT=18245;
      CLIENT_PORT_AFTER_REBINDING=18246;
var Instance:TRNLInstance;
    VirtualNetwork:TRNLVirtualNetwork;
    FaultInjector:TRNLNetworkFaultInjector;
    HostPair:TRNLTestHostPair;
    OldClientAddress,NewClientAddress:TRNLAddress;
    ElapsedMilliseconds:TRNLInt64;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('a peer follows an authenticated address change');
 Watchdog:=TRNLTestWatchdog.Create('address change',120000);
 try

  Instance:=TRNLInstance.Create;
  try
   VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
   try
    FaultInjector:=TRNLNetworkFaultInjector.Create(Instance,VirtualNetwork);
    try

     HostPair:=TRNLTestHostPair.Create(Instance,FaultInjector,SERVER_PORT,CLIENT_PORT);
     try

      if not Check(HostPair.Connect(5000),'the handshake must succeed') then begin
       exit;
      end;

      // Both directions have to work before anything is changed, so that a later failure can
      // not be blamed on the setup
      HostPair.ClientPeer.Channels[RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_ORDERED].SendMessageRawByteString(TestMessageText(1));
      HostPair.ServerPeer.Channels[RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_ORDERED].SendMessageRawByteString(TestMessageText(2));

      if not Check(HostPair.PumpUntilServerReceived(1,10000,ElapsedMilliseconds) and
                   HostPair.PumpUntilClientReceived(1,10000,ElapsedMilliseconds),
                   'the host service loop must stay alive') then begin
       exit;
      end;

      if not (CheckEqualsInt64(HostPair.ServerReceivedMessages.Count,1,'the setup must deliver towards the server') and
              CheckEqualsInt64(HostPair.ClientReceivedMessages.Count,1,'the setup must deliver towards the client')) then begin
       exit;
      end;

      Info('server sees the client at port '+TRNLRawByteString(IntToStr(HostPair.ServerPeer.Address^.Port)));

      FaultInjector.AddressSetHost(OldClientAddress,'127.0.0.1');
      OldClientAddress.Port:=CLIENT_PORT;

      FaultInjector.AddressSetHost(NewClientAddress,'127.0.0.1');
      NewClientAddress.Port:=CLIENT_PORT_AFTER_REBINDING;

      // And now the address of the client changes underneath the running connection
      FaultInjector.RebindSourceAddress(OldClientAddress,NewClientAddress);

      HostPair.ClientPeer.Channels[RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_ORDERED].SendMessageRawByteString(TestMessageText(3));
      HostPair.ServerPeer.Channels[RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_ORDERED].SendMessageRawByteString(TestMessageText(4));

      if not Check(HostPair.PumpUntilServerReceived(2,20000,ElapsedMilliseconds),
                   'the host service loop must stay alive') then begin
       exit;
      end;

      if not Check(HostPair.PumpUntilClientReceived(2,20000,ElapsedMilliseconds),
                   'the host service loop must stay alive') then begin
       exit;
      end;

      Info('server sees the client at port '+TRNLRawByteString(IntToStr(HostPair.ServerPeer.Address^.Port))+' now');
      Info('rebound source addresses: '+TRNLRawByteString(IntToStr(FaultInjector.CountRebindenSourceAddresses)));
      Info('datagrams towards the stale address: '+TRNLRawByteString(IntToStr(FaultInjector.CountDatagramsToStaleAddress)));
      Info('server counted peer address changes: '+TRNLRawByteString(IntToStr(HostPair.Server.TotalPeerAddressChanges)));

      CheckAtLeastInt64(FaultInjector.CountRebindenSourceAddresses,1,
                        'the test must actually have changed the source address of the client');

      CheckAtLeastInt64(HostPair.Server.TotalPeerAddressChanges,1,
                        'the server must have followed the address change');

      CheckEqualsInt64(HostPair.ServerPeer.Address^.Port,CLIENT_PORT_AFTER_REBINDING,
                       'the server must have adopted the new address of its peer');

      CheckEqualsInt64(HostPair.ServerReceivedMessages.Count,2,
                       'traffic towards the server must continue across the address change');

      CheckEqualsInt64(HostPair.ClientReceivedMessages.Count,2,
                       'traffic towards the client must continue across the address change, '+
                       'which it only can if the server followed the address');

      CheckEqualsInt64(HostPair.CountClientDisconnectEvents,0,
                       'the client must not drop the connection over an address change');

      CheckEqualsInt64(HostPair.CountServerDisconnectEvents,0,
                       'the server must not drop the connection over an address change');

     finally
      FreeAndNil(HostPair);
     end;

    finally
     FreeAndNil(FaultInjector);
    end;
   finally
    FreeAndNil(VirtualNetwork);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

// ---------------------------------------------------------------------------------------
// Disconnecting
// ---------------------------------------------------------------------------------------

// A delayed disconnect waits for everything still outgoing to be delivered. That wait needs an
// upper bound of its own, because otherwise one single item which can not be delivered any more
// keeps the peer in that state, and the disconnect then only ever happens through the connection
// timeout, which is a completely different and much longer period.
procedure TestDelayedDisconnectAlwaysTerminates;
const SMALL_DATAGRAM_LIMIT=400;
      MESSAGE_PADDING_SIZE=600;
      PENDING_DISCONNECTION_TIMEOUT=1000;
      CONNECTION_TIMEOUT=30000;
var Instance:TRNLInstance;
    VirtualNetwork:TRNLVirtualNetwork;
    FaultInjector:TRNLNetworkFaultInjector;
    HostPair:TRNLTestHostPair;
    StartTime:TRNLTime;
    ElapsedMilliseconds,TimeBudgetMilliseconds:TRNLInt64;
    HostServiceLoopAlive:boolean;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('a delayed disconnect always terminates');
 Watchdog:=TRNLTestWatchdog.Create('delayed disconnect',120000);
 try

  Instance:=TRNLInstance.Create;
  try
   VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
   try
    FaultInjector:=TRNLNetworkFaultInjector.Create(Instance,VirtualNetwork);
    try

     HostPair:=TRNLTestHostPair.Create(Instance,FaultInjector);
     try

      // A short disconnection timeout against a long connection timeout, so that it is
      // unambiguous which of the two ended the wait
      HostPair.Client.PendingDisconnectionTimeout:=PENDING_DISCONNECTION_TIMEOUT;
      HostPair.Client.ConnectionTimeout:=CONNECTION_TIMEOUT;
      HostPair.Server.ConnectionTimeout:=CONNECTION_TIMEOUT;

      if not Check(HostPair.Connect(5000),'the handshake must succeed') then begin
       exit;
      end;

      // Undeliverable from here on
      FaultInjector.MaximumDatagramSize:=SMALL_DATAGRAM_LIMIT;

      HostPair.ClientPeer.Channels[RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_ORDERED].SendMessageRawByteString(TestMessageText(1,MESSAGE_PADDING_SIZE));

      if not Check(HostPair.Pump(300),'the host service loop must stay alive') then begin
       exit;
      end;

      HostPair.ClientPeer.Disconnect(0,true);

      // Generous enough for the disconnection handshake itself, and still far below the
      // connection timeout
      TimeBudgetMilliseconds:=(PENDING_DISCONNECTION_TIMEOUT*4)+2000;

      Info('pending disconnection timeout: '+TRNLRawByteString(IntToStr(PENDING_DISCONNECTION_TIMEOUT))+' ms');
      Info('connection timeout: '+TRNLRawByteString(IntToStr(CONNECTION_TIMEOUT))+' ms');
      Info('time budget: '+TRNLRawByteString(IntToStr(TimeBudgetMilliseconds))+' ms');

      StartTime:=Instance.Time;

      // The assertion deliberately sits outside of this loop, so that the number of checks of
      // this test does not depend on how many iterations the loop happened to need
      HostServiceLoopAlive:=true;

      repeat
       if not HostPair.Pump(100) then begin
        HostServiceLoopAlive:=false;
        break;
       end;
       ElapsedMilliseconds:=TRNLTime.RelativeDifference(Instance.Time,StartTime);
      until (HostPair.CountClientDisconnectEvents>0) or
            (ElapsedMilliseconds>=CONNECTION_TIMEOUT);

      Info('the delayed disconnect completed after '+TRNLRawByteString(IntToStr(ElapsedMilliseconds))+' ms');

      if not Check(HostServiceLoopAlive,'the host service loop must stay alive') then begin
       exit;
      end;

      if not CheckAtLeastInt64(HostPair.CountClientDisconnectEvents,1,
                               'the delayed disconnect must complete at all') then begin
       exit;
      end;

      CheckAtMostInt64(ElapsedMilliseconds,TimeBudgetMilliseconds,
                       'the delayed disconnect must be bounded by the disconnection timeout '+
                       'and not by the connection timeout');

     finally
      FreeAndNil(HostPair);
     end;

    finally
     FreeAndNil(FaultInjector);
    end;
   finally
    FreeAndNil(VirtualNetwork);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

// A reliable block packet whose acknowledgement is lost for good used to be retransmitted until
// the end of time. The connection timeout does cover the ordinary case, but not the one where
// other traffic keeps arriving and therefore keeps the connection looking alive while one
// channel is permanently stuck, so the retransmission itself needs a bound.
procedure TestUndeliverableReliablePacketGivesUpOnThePeer;
const SMALL_DATAGRAM_LIMIT=400;
      MESSAGE_PADDING_SIZE=600;
      MAXIMUM_SEND_ATTEMPTS=4;
      CONNECTION_TIMEOUT=60000;
var Instance:TRNLInstance;
    VirtualNetwork:TRNLVirtualNetwork;
    FaultInjector:TRNLNetworkFaultInjector;
    HostPair:TRNLTestHostPair;
    StartTime:TRNLTime;
    ElapsedMilliseconds:TRNLInt64;
    HostServiceLoopAlive:boolean;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('an undeliverable reliable packet leads to giving up on the peer');
 Watchdog:=TRNLTestWatchdog.Create('give up on peer',180000);
 try

  Instance:=TRNLInstance.Create;
  try
   VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
   try
    FaultInjector:=TRNLNetworkFaultInjector.Create(Instance,VirtualNetwork);
    try

     HostPair:=TRNLTestHostPair.Create(Instance,FaultInjector);
     try

      // A connection timeout far beyond the test, so that giving up is unambiguously what ended
      // this connection, and a low attempt limit, so that it happens quickly
      HostPair.Client.ConnectionTimeout:=CONNECTION_TIMEOUT;
      HostPair.Server.ConnectionTimeout:=CONNECTION_TIMEOUT;
      HostPair.Client.MaximumReliableBlockPacketSendAttempts:=MAXIMUM_SEND_ATTEMPTS;

      if not Check(HostPair.Connect(5000),'the handshake must succeed') then begin
       exit;
      end;

      Info('maximum send attempts: '+TRNLRawByteString(IntToStr(MAXIMUM_SEND_ATTEMPTS)));
      Info('connection timeout: '+TRNLRawByteString(IntToStr(CONNECTION_TIMEOUT))+' ms');

      // The payload can not get through from here on, while the keep alive still can, so the
      // connection keeps looking perfectly alive
      FaultInjector.MaximumDatagramSize:=SMALL_DATAGRAM_LIMIT;

      HostPair.ClientPeer.Channels[RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_ORDERED].SendMessageRawByteString(TestMessageText(1,MESSAGE_PADDING_SIZE));

      StartTime:=Instance.Time;

      // The assertion deliberately sits outside of this loop, so that the number of checks of
      // this test does not depend on how many iterations the loop happened to need
      HostServiceLoopAlive:=true;

      repeat
       if not HostPair.Pump(100) then begin
        HostServiceLoopAlive:=false;
        break;
       end;
       ElapsedMilliseconds:=TRNLTime.RelativeDifference(Instance.Time,StartTime);
      until (HostPair.Client.TotalPeersGivenUpOn>0) or
            (ElapsedMilliseconds>=40000);

      Info('gave up after '+TRNLRawByteString(IntToStr(ElapsedMilliseconds))+' ms');

      if not Check(HostServiceLoopAlive,'the host service loop must stay alive') then begin
       exit;
      end;
      Info('peers given up on: '+TRNLRawByteString(IntToStr(HostPair.Client.TotalPeersGivenUpOn)));

      CheckAtLeastInt64(HostPair.Client.TotalPeersGivenUpOn,1,
                        'an endlessly undeliverable reliable block packet must lead to giving up');

      CheckAtMostInt64(ElapsedMilliseconds,TRNLInt64(CONNECTION_TIMEOUT) div 2,
                       'giving up must happen well before the connection timeout would, '+
                       'because the connection timeout is exactly what does not fire here');

      // And it has to actually result in a disconnect, not just in a counter
      if not Check(HostPair.Pump(5000),'the host service loop must stay alive') then begin
       exit;
      end;

      CheckAtLeastInt64(HostPair.CountClientDisconnectEvents,1,
                        'giving up on a peer must surface as a disconnect event');

     finally
      FreeAndNil(HostPair);
     end;

    finally
     FreeAndNil(FaultInjector);
    end;
   finally
    FreeAndNil(VirtualNetwork);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

// ---------------------------------------------------------------------------------------
// Exactly once delivery
// ---------------------------------------------------------------------------------------

// A reliable channel promises every message exactly once. On an unordered one the payload is
// handed to the application as soon as it arrives, rather than in sequence, so a retransmission
// which arrives while the original is still inside the receive window has to be recognised as
// the duplicate it is. The replay window one layer below does not help here, because a
// retransmission carries a fresh encrypted packet sequence number and is therefore no replay.
//
// Reaching that state needs three things at once, which is why plain random packet loss is a
// poor way to ask for it: the loss has to hit the right things, and if it hits the payload
// instead of only the acknowledgement, then the retransmission is not a duplicate at all.
//
//   1. an earlier block packet has to be missing, so that the receive window can not advance and
//      therefore keeps the later one in its slot
//   2. a later block packet has to arrive and be delivered
//   3. the acknowledgement of that later one has to get lost, so that it is retransmitted
//
// All three are arranged deterministically here. The first message is made permanently
// undeliverable through its size, which parks the window base in front of it for good, and the
// acknowledgements towards the client are then dropped for a while, which is what forces the
// retransmission of the second message.
procedure TestReliableUnorderedChannelDeliversEachMessageOnce;
const SERVER_PORT=18254;
      CLIENT_PORT=18255;
      // Everything above this never leaves, everything below it passes
      DATAGRAM_LIMIT=400;
      // Large enough for two separate purposes at once. Its datagram has to end up above the
      // limit, so that its block packet can never be delivered and the window base stays parked
      // in front of it. And it has to leave so little room in a datagram of the default MTU that
      // the second message can not be appended alongside it, because otherwise both block
      // packets travel in one single datagram, that one datagram is over the limit as a whole,
      // and then neither of the two arrives.
      BLOCKING_MESSAGE_PADDING_SIZE=780;
      // Small enough to fit into a datagram below the limit all by itself
      DELIVERED_MESSAGE_PADDING_SIZE=64;
      // Effectively everything towards the client for the duration of the interesting window.
      // It has to be set up before the payload is even sent, because an acknowledgement is small
      // enough to slip below the datagram limit, and once the client has seen it, it has no
      // reason left to retransmit anything.
      COUNT_ACKNOWLEDGEMENT_DATAGRAMS_TO_DROP=1000;
      // Long enough for several retransmission timeouts of the second message, and short enough
      // to stay well below the connection timeout, since the client hears nothing at all here
      BLACKOUT_MILLISECONDS=2500;
var Instance:TRNLInstance;
    VirtualNetwork:TRNLVirtualNetwork;
    FaultInjector:TRNLNetworkFaultInjector;
    HostPair:TRNLTestHostPair;
    ClientAddress:TRNLAddress;
    BlockingMessage,DeliveredMessage:TRNLRawByteString;
    ElapsedMilliseconds:TRNLInt64;
    Index,CountDeliveries:TRNLSizeInt;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('a reliable unordered channel delivers each message exactly once');
 Watchdog:=TRNLTestWatchdog.Create('exactly once delivery',120000);
 try

  Instance:=TRNLInstance.Create;
  try
   VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
   try
    FaultInjector:=TRNLNetworkFaultInjector.Create(Instance,VirtualNetwork);
    try

     HostPair:=TRNLTestHostPair.Create(Instance,FaultInjector,SERVER_PORT,CLIENT_PORT);
     try

      if not Check(HostPair.Connect(5000),'the handshake must succeed without any injected faults') then begin
       exit;
      end;

      FaultInjector.AddressSetHost(ClientAddress,'127.0.0.1');
      ClientAddress.Port:=CLIENT_PORT;

      BlockingMessage:=TestMessageText(1,BLOCKING_MESSAGE_PADDING_SIZE);
      DeliveredMessage:=TestMessageText(2,DELIVERED_MESSAGE_PADDING_SIZE);

      Info('peer MTU: '+TRNLRawByteString(IntToStr(HostPair.ClientPeer.MTU))+
           ', blocking message: '+TRNLRawByteString(IntToStr(length(BlockingMessage)))+
           ' bytes, delivered message: '+TRNLRawByteString(IntToStr(length(DeliveredMessage)))+
           ' bytes, datagram limit: '+TRNLRawByteString(IntToStr(DATAGRAM_LIMIT))+' bytes');

      FaultInjector.MaximumDatagramSize:=DATAGRAM_LIMIT;

      // Both of these have to be in place before anything is sent
      FaultInjector.DropNextOutgoingDatagramsToAddress(ClientAddress,COUNT_ACKNOWLEDGEMENT_DATAGRAMS_TO_DROP);

      // The blocking one first, so that it takes the lower block packet sequence number
      HostPair.ClientPeer.Channels[RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_UNORDERED].SendMessageRawByteString(BlockingMessage);
      HostPair.ClientPeer.Channels[RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_UNORDERED].SendMessageRawByteString(DeliveredMessage);

      if not Check(HostPair.PumpUntilServerReceived(1,10000,ElapsedMilliseconds),
                   'the host service loop must stay alive') then begin
       exit;
      end;

      Info('oversized datagrams rejected: '+TRNLRawByteString(IntToStr(FaultInjector.CountOversizedDatagrams)));
      Info('messages delivered so far: '+TRNLRawByteString(IntToStr(HostPair.ServerReceivedMessages.Count)));

      CheckAtLeastInt64(FaultInjector.CountOversizedDatagrams,1,
                        'the blocking message must actually have been kept from being delivered');

      if not CheckEqualsInt64(HostPair.ServerReceivedMessages.Count,1,
                              'the second message must have been delivered while the first one is still missing') then begin
       exit;
      end;

      // The client hears nothing at all during this window, so it retransmits the block packet
      // which the server has already delivered
      if not Check(HostPair.Pump(BLACKOUT_MILLISECONDS),'the host service loop must stay alive') then begin
       exit;
      end;

      Info('datagrams dropped towards the client: '+TRNLRawByteString(IntToStr(FaultInjector.CountDeterministicallyDroppedDatagrams)));
      Info('messages delivered in total: '+TRNLRawByteString(IntToStr(HostPair.ServerReceivedMessages.Count)));

      CheckAtLeastInt64(FaultInjector.CountDeterministicallyDroppedDatagrams,1,
                        'the test must actually have dropped the acknowledgements it intended to drop');

      CountDeliveries:=0;
      for Index:=0 to HostPair.ServerReceivedMessages.Count-1 do begin
       if TRNLRawByteString(HostPair.ServerReceivedMessages[Index])=DeliveredMessage then begin
        inc(CountDeliveries);
       end;
      end;

      Info('deliveries of the retransmitted message: '+TRNLRawByteString(IntToStr(CountDeliveries)));

      CheckEqualsInt64(CountDeliveries,1,
                       'a retransmission of a block packet which is still inside the receive window '+
                       'must not hand the very same message to the application a second time');

      CheckEqualsInt64(HostPair.ServerReceivedMessages.Count,1,
                       'and nothing else may have been delivered either, since the first message '+
                       'still can not get through');

      // Once the datagrams fit again and the client can hear again, the blocked message has to
      // arrive as well, exactly once
      FaultInjector.MaximumDatagramSize:=0;
      FaultInjector.DropNextOutgoingDatagramsToAddress(ClientAddress,0);

      if not Check(HostPair.PumpUntilServerReceived(2,20000,ElapsedMilliseconds),
                   'the host service loop must stay alive while recovering') then begin
       exit;
      end;

      if not Check(HostPair.Pump(1500),'the host service loop must stay alive') then begin
       exit;
      end;

      Info('messages delivered after the recovery: '+TRNLRawByteString(IntToStr(HostPair.ServerReceivedMessages.Count)));

      CheckEqualsInt64(HostPair.ServerReceivedMessages.Count,2,
                       'both messages must have arrived exactly once each after the recovery');

      CountDeliveries:=0;
      for Index:=0 to HostPair.ServerReceivedMessages.Count-1 do begin
       if TRNLRawByteString(HostPair.ServerReceivedMessages[Index])=BlockingMessage then begin
        inc(CountDeliveries);
       end;
      end;

      CheckEqualsInt64(CountDeliveries,1,
                       'the formerly blocked message must have arrived exactly once as well');

      CheckEqualsInt64(HostPair.CountServerDisconnectEvents,0,
                       'none of this may drop the connection');

     finally
      FreeAndNil(HostPair);
     end;

    finally
     FreeAndNil(FaultInjector);
    end;
   finally
    FreeAndNil(VirtualNetwork);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

procedure TestCompressedTransferStaysIntact;
const COUNT_MESSAGES=20;
var Instance:TRNLInstance;
    VirtualNetwork:TRNLVirtualNetwork;
    HostPair:TRNLTestHostPair;
    Index:TRNLSizeInt;
    ElapsedMilliseconds:TRNLInt64;
    Expected:TRNLRawByteString;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('a compressed transfer stays intact');
 Watchdog:=TRNLTestWatchdog.Create('compressed transfer',120000);
 try

  Instance:=TRNLInstance.Create;
  try
   VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
   try

    HostPair:=TRNLTestHostPair.Create(Instance,VirtualNetwork);
    try

     HostPair.Client.Compressor:=TRNLCompressorLZBRRC.Create;
     HostPair.Server.Compressor:=TRNLCompressorLZBRRC.Create;

     if not Check(HostPair.Connect(5000),'the handshake must succeed with a compressor in place') then begin
      exit;
     end;

     for Index:=1 to COUNT_MESSAGES do begin
      // Highly repetitive, so that the compressor really does kick in and the compressed
      // receive path is the one being taken
      HostPair.ClientPeer.Channels[RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_ORDERED].SendMessageRawByteString(TestMessageText(Index,700));
     end;

     if not Check(HostPair.PumpUntilServerReceived(COUNT_MESSAGES,30000,ElapsedMilliseconds),
                  'the host service loop must stay alive with a compressor in place') then begin
      exit;
     end;

     Info('transferred '+TRNLRawByteString(IntToStr(COUNT_MESSAGES))+
          ' compressible messages in '+TRNLRawByteString(IntToStr(ElapsedMilliseconds))+' ms');

     if not CheckEqualsInt64(HostPair.ServerReceivedMessages.Count,COUNT_MESSAGES,
                             'every message must arrive through the compressed path') then begin
      exit;
     end;

     for Index:=1 to COUNT_MESSAGES do begin
      Expected:=TestMessageText(Index,700);
      CheckEqualsRawByteString(TRNLRawByteString(HostPair.ServerReceivedMessages[Index-1]),Expected,
                               'compressed message '+TRNLRawByteString(IntToStr(Index))+' must arrive intact and in order');
     end;

     CheckEqualsInt64(HostPair.CountServerDisconnectEvents,0,
                      'compression must not drop the connection');

    finally
     FreeAndNil(HostPair);
    end;

   finally
    FreeAndNil(VirtualNetwork);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;


// ---------------------------------------------------------------------------------------
// Kernel object usage
// ---------------------------------------------------------------------------------------

// On Windows the socket wait is emulated on top of WSAEventSelect and
// WSAWaitForMultipleEvents, and that emulation used to create one event object per socket per
// call and destroy it again at the end of the same call. A host running a thousand service
// iterations per second, which is nothing unusual for a game server, therefore created and
// destroyed a couple of thousand kernel objects per second.
//
// Besides being wasteful, that is a failure path: under handle pressure WSACreateEvent returns
// WSA_INVALID_EVENT, the emulation reports an error, and the host service loop terminates over
// it. So the handle count has to stay flat no matter how often the host is serviced.
//
// Everywhere except Windows this test has nothing to measure, since those platforms call poll
// or select directly and allocate nothing per call.
procedure TestSocketWaitDoesNotChurnKernelObjects;
const COUNT_ITERATIONS=1000;
      // Must not be zero. With a timeout of zero DispatchIteration returns before it ever gets to
      // the socket wait, and then this test measures nothing at all.
      SERVICE_TIMEOUT_MILLISECONDS=1;
      // One host, one address family, so one socket, and therefore one event object. The bound is
      // a little above that, so that this asserts "proportional to the sockets" rather than an
      // exact number.
      TOLERATED_EVENTS=4;
var Instance:TRNLInstance;
    Network:TRNLRealNetwork;
    Host:TRNLHost;
    Event:TRNLHostEvent;
    Index:TRNLSizeInt;
    EventsAfterWarmup,EventsAtEnd:TRNLUInt64;
{$if defined(Windows)}
    HandlesBefore,HandlesAfter:TRNLUInt32;
{$ifend}
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('the socket wait does not churn kernel objects');
 Watchdog:=TRNLTestWatchdog.Create('kernel object churn',120000);
 try

  Instance:=TRNLInstance.Create;
  try
   Network:=TRNLRealNetwork.Create(Instance);
   try
    Host:=TRNLHost.Create(Instance,Network);
    try

     Host.Address.Host:=RNL_HOST_ANY;
     Host.Address.Port:=0;
     Host.Interruptible:=true;
     Host.Start(RNL_HOST_ADDRESS_FAMILY_WORK_MODE_IPV4_ONLY);

{$if defined(Windows)}
     HandlesBefore:=0;
     HandlesAfter:=0;
{$ifend}

     Event.Initialize;
     try

      // A few rounds up front, so that whatever is allocated once and then kept is already in
      // place when the baseline is taken
      for Index:=1 to 32 do begin
       Host.Service(Event,SERVICE_TIMEOUT_MILLISECONDS);
       Event.Free;
      end;

      EventsAfterWarmup:=Network.TotalCreatedSocketWaitEvents;

{$if defined(Windows)}
      GetProcessHandleCount(GetCurrentProcess,HandlesBefore);
{$ifend}

      for Index:=1 to COUNT_ITERATIONS do begin
       Host.Service(Event,SERVICE_TIMEOUT_MILLISECONDS);
       Event.Free;
      end;

      EventsAtEnd:=Network.TotalCreatedSocketWaitEvents;

{$if defined(Windows)}
      GetProcessHandleCount(GetCurrentProcess,HandlesAfter);
{$ifend}

     finally
      Event.Free;
     end;

     Info('socket wait event objects created: '+TRNLRawByteString(IntToStr(EventsAtEnd))+
          ' in total, '+TRNLRawByteString(IntToStr(EventsAtEnd-EventsAfterWarmup))+
          ' of them during '+TRNLRawByteString(IntToStr(COUNT_ITERATIONS))+' service iterations');

     // Both branches assert the correct expectation of their platform, and both count as one
     // check, so that the total number of checks stays the same everywhere. On Windows this also
     // guards against the test quietly measuring nothing, which is what happens with a service
     // timeout of zero, since the socket wait is then never reached at all.
{$if defined(Windows)}
     CheckAtLeastInt64(TRNLInt64(EventsAtEnd),1,
                       'the socket wait must actually have been reached, otherwise this test '+
                       'measures nothing');
{$else}
     CheckEqualsInt64(TRNLInt64(EventsAtEnd),0,
                      'no event objects may be created where the socket wait uses poll or '+
                      'select directly');
{$ifend}

{$if defined(Windows)}
     // Only an extra observation, because wine reports zero here, which makes it useless as the
     // actual measure
     Info('process handle count: '+TRNLRawByteString(IntToStr(HandlesBefore))+
          ' before, '+TRNLRawByteString(IntToStr(HandlesAfter))+' after');
{$ifend}

     // The decisive one. Before the event objects were cached per socket, this grew by one per
     // socket per service iteration, so by two thousand over this loop.
     CheckEqualsInt64(TRNLInt64(EventsAtEnd-EventsAfterWarmup),0,
                      'servicing a host must not create further kernel objects per call');

     CheckAtMostInt64(TRNLInt64(EventsAtEnd),TOLERATED_EVENTS,
                      'the number of event objects must stay proportional to the number of '+
                      'sockets and not to the number of calls');

     // And the host has to still work afterwards, so that the caching did not simply break the
     // socket wait
     CheckEqualsInt64(TRNLInt64(Host.TotalHardReceiveFailures+Host.TotalHardSendFailures),0,
                      'the cached event objects must not break the socket wait');

    finally
     FreeAndNil(Host);
    end;
   finally
    FreeAndNil(Network);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

// ---------------------------------------------------------------------------------------
// Unreliable channels
// ---------------------------------------------------------------------------------------

// Both unreliable channels share one fragmentation implementation and differ only in the size and
// the content of their two packet headers, so both of them have to be exercised, and both of them
// with a payload small enough for a single block packet and with one large enough to be split
// across several. A wrong header size would corrupt the payload offset within the block packet, a
// wrong header content would break the reassembly, and neither would show up on the short path
// alone.
//
// No loss is injected here. These channels do not retransmit, so the point of this test is that
// what does arrive arrives intact, complete and, on the ordered channel, in order.
procedure TestUnreliableChannelsTransportShortAndLongMessages;
const COUNT_MESSAGES=8;
      SHORT_PAYLOAD_SIZE=64;
      // Several times the default MTU, so that this really is split into several block packets
      LONG_PAYLOAD_SIZE=3000;
var Instance:TRNLInstance;
    VirtualNetwork:TRNLVirtualNetwork;
    HostPair:TRNLTestHostPair;
    Index,Channel,CountFound:TRNLSizeInt;
    Expected:TRNLRawByteString;
    ElapsedMilliseconds:TRNLInt64;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('the unreliable channels transport short and long messages');
 Watchdog:=TRNLTestWatchdog.Create('unreliable channels',120000);
 try

  Instance:=TRNLInstance.Create;
  try
   VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
   try

    HostPair:=TRNLTestHostPair.Create(Instance,VirtualNetwork);
    try

     if not Check(HostPair.Connect(5000),'the handshake must succeed') then begin
      exit;
     end;

     for Channel:=RNL_TEST_HOST_PAIR_CHANNEL_UNRELIABLE_ORDERED to RNL_TEST_HOST_PAIR_CHANNEL_UNRELIABLE_UNORDERED do begin

      HostPair.ServerReceivedMessages.Clear;

      // Alternating short and long, so that both block packet shapes of this channel are used and
      // a wrong header size shows up as a corrupted or missing payload
      for Index:=1 to COUNT_MESSAGES do begin
       if (Index and 1)<>0 then begin
        HostPair.ClientPeer.Channels[Channel].SendMessageRawByteString(TestMessageText(Index,SHORT_PAYLOAD_SIZE));
       end else begin
        HostPair.ClientPeer.Channels[Channel].SendMessageRawByteString(TestMessageText(Index,LONG_PAYLOAD_SIZE));
       end;
      end;

      if not Check(HostPair.PumpUntilServerReceived(COUNT_MESSAGES,20000,ElapsedMilliseconds),
                   'the host service loop must stay alive') then begin
       exit;
      end;

      Info('channel '+TRNLRawByteString(IntToStr(Channel))+': '+
           TRNLRawByteString(IntToStr(HostPair.ServerReceivedMessages.Count))+' of '+
           TRNLRawByteString(IntToStr(COUNT_MESSAGES))+' message(s) in '+
           TRNLRawByteString(IntToStr(ElapsedMilliseconds))+' ms');

      // Nothing is lost on a virtual network without any injected interference, so everything
      // which was sent has to be here
      if not CheckEqualsInt64(HostPair.ServerReceivedMessages.Count,COUNT_MESSAGES,
                              'every message must arrive on channel '+TRNLRawByteString(IntToStr(Channel))) then begin
       exit;
      end;

      CountFound:=0;
      for Index:=1 to COUNT_MESSAGES do begin
       if (Index and 1)<>0 then begin
        Expected:=TestMessageText(Index,SHORT_PAYLOAD_SIZE);
       end else begin
        Expected:=TestMessageText(Index,LONG_PAYLOAD_SIZE);
       end;
       if HostPair.ServerReceivedMessages.IndexOf(String(Expected))>=0 then begin
        inc(CountFound);
       end;
      end;

      CheckEqualsInt64(CountFound,COUNT_MESSAGES,
                       'every message must arrive intact and complete on channel '+
                       TRNLRawByteString(IntToStr(Channel)));

      // The ordered channel additionally has to preserve the order it was given
      if Channel=RNL_TEST_HOST_PAIR_CHANNEL_UNRELIABLE_ORDERED then begin
       CountFound:=0;
       for Index:=1 to COUNT_MESSAGES do begin
        if (Index and 1)<>0 then begin
         Expected:=TestMessageText(Index,SHORT_PAYLOAD_SIZE);
        end else begin
         Expected:=TestMessageText(Index,LONG_PAYLOAD_SIZE);
        end;
        if TRNLRawByteString(HostPair.ServerReceivedMessages[Index-1])=Expected then begin
         inc(CountFound);
        end;
       end;
       CheckEqualsInt64(CountFound,COUNT_MESSAGES,
                        'the unreliable ordered channel must preserve the order of its messages');
      end;

     end;

     CheckEqualsInt64(HostPair.CountServerDisconnectEvents,0,
                      'none of this may drop the connection');

    finally
     FreeAndNil(HostPair);
    end;

   finally
    FreeAndNil(VirtualNetwork);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

// ---------------------------------------------------------------------------------------
// A handshake in progress and the flooding limit
// ---------------------------------------------------------------------------------------

// The per address flooding limit exists to keep an unknown address from opening connection
// attempts faster than the host can carry them. It used to count every arriving connection
// request, including the repetitions of a handshake which is already under way, and those are
// not attempts at all: an initiator repeats its request every fPendingConnectionSendTimeout
// until it hears back, and one which fans out over several candidates sends one per candidate
// per repetition. So the very thing the limit is meant to protect, a connection that is trying
// to come up, was what ran into it first.
//
// What separates the two cases is the salt: every repetition of one handshake carries the same
// one and therefore means the same connection candidate, while a flood has to invent a new salt
// per request to look like a new attempt, and each of those still meets the limit.
//
// The construction below is the smallest one in which the difference is visible. The answers of
// the server are dropped for a while, which is exactly what makes the client repeat, and the
// budget is set to a single request with a period far longer than the test, so that a limit
// which counts repetitions has nothing left to give for the rest of the run.
procedure TestRepeatedHandshakeRequestsDoNotEatTheFloodingBudget;
const COUNT_DROPPED_ANSWERS=4;
      CLIENT_PORT=18235;
var Instance:TRNLInstance;
    VirtualNetwork:TRNLVirtualNetwork;
    FaultInjector:TRNLNetworkFaultInjector;
    HostPair:TRNLTestHostPair;
    ClientAddress:TRNLAddress;
    Connected:boolean;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('the repetitions of one handshake do not eat the flooding budget');
 Watchdog:=TRNLTestWatchdog.Create('handshake repetitions and flooding limit',120000);
 try

  Instance:=TRNLInstance.Create;
  try
   VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
   try
    FaultInjector:=TRNLNetworkFaultInjector.Create(Instance,VirtualNetwork);
    try

     HostPair:=TRNLTestHostPair.Create(Instance,FaultInjector);
     try

      // One single request per address, and a period which outlasts the whole test, so that a
      // budget once spent stays spent. Without that the period would simply refill and the
      // connection would come up a second later, which would prove nothing.
      HostPair.Server.RateLimiterHostAddressBurst:=1;
      HostPair.Server.RateLimiterHostAddressPeriod:=60000;

      FillChar(ClientAddress,SizeOf(TRNLAddress),#0);
      FaultInjector.AddressSetHost(ClientAddress,'127.0.0.1');
      ClientAddress.Port:=CLIENT_PORT;

      // The answers of the server, and only those, get lost for a while. The client keeps its
      // request going meanwhile, which is what puts several of them in front of the limit.
      FaultInjector.DropNextOutgoingDatagramsToAddress(ClientAddress,COUNT_DROPPED_ANSWERS);

      Connected:=HostPair.Connect(5000);

      Info('dropped answers: '+TRNLRawByteString(IntToStr(FaultInjector.CountDeterministicallyDroppedDatagrams))+
           ', flooding budget: '+TRNLRawByteString(IntToStr(HostPair.Server.RateLimiterHostAddressBurst))+
           ' request(s) per '+TRNLRawByteString(IntToStr(HostPair.Server.RateLimiterHostAddressPeriod))+' ms');
      Info('rate limited connection requests: '+
           TRNLRawByteString(IntToStr(HostPair.Server.TotalRateLimitedConnectionRequests)));

      // A precondition rather than a result: at least the first answer has to have gone missing,
      // because that is what makes the client repeat at all. It stays deliberately at one, since
      // the later drops only happen if the server is still answering, which is exactly the thing
      // under test here.
      CheckAtLeastInt64(FaultInjector.CountDeterministicallyDroppedDatagrams,1,
                        'the client has to have been left without an answer at least once');

      Check(Connected,'a handshake which only has to repeat itself must still come up');

      CheckEqualsInt64(HostPair.Server.TotalRateLimitedConnectionRequests,0,
                       'and none of its repetitions may be turned away as flooding');

     finally
      FreeAndNil(HostPair);
     end;

    finally
     FreeAndNil(FaultInjector);
    end;
   finally
    FreeAndNil(VirtualNetwork);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

// ---------------------------------------------------------------------------------------
// What kind of NAT is in the way
// ---------------------------------------------------------------------------------------

// A server reflexive candidate is only worth something if the address a STUN server saw is also
// the address a peer will see. That holds for a NAT which keeps one mapping per socket and fails
// for one which picks a new one per destination, and the difference is not visible from a single
// binding request: one answer is just an address, and every NAT produces one.
//
// Two servers on different hosts make it visible. Same answer twice means the mapping does not
// depend on who is being written to; two different answers mean it does. A third server, on the
// host already asked but on another port, then says whether the port is part of it too.
//
// All four simulated NAT kinds are put through it, which is what makes the result meaningful: the
// three restricting ones differ in their filtering and share their mapping, so a detection which
// confused the two halves would have to get at least one of them wrong.
procedure TestNATMappingBehaviourIsDetectedForEveryNATKind;
const INSIDE_HOST='127.0.0.1';
      INSIDE_PORT=18530;
      EXTERNAL_HOST='198.51.100.9';
      STUN_HOST_A='203.0.113.1';
      STUN_HOST_B='203.0.113.2';
      STUN_PORT_A=3478;
      STUN_PORT_B=3479;
var Watchdog:TRNLTestWatchdog;
    Behaviour:TRNLNATMappingBehaviour;

 function NameOf(const aBehaviour:TRNLNATMappingBehaviour):TRNLRawByteString;
 begin
  case aBehaviour of
   RNL_NAT_MAPPING_BEHAVIOUR_NONE:begin
    result:='none';
   end;
   RNL_NAT_MAPPING_BEHAVIOUR_ENDPOINT_INDEPENDENT:begin
    result:='endpoint independent';
   end;
   RNL_NAT_MAPPING_BEHAVIOUR_DESTINATION_DEPENDENT:begin
    result:='destination dependent';
   end;
   RNL_NAT_MAPPING_BEHAVIOUR_ADDRESS_DEPENDENT:begin
    result:='address dependent';
   end;
   RNL_NAT_MAPPING_BEHAVIOUR_ADDRESS_AND_PORT_DEPENDENT:begin
    result:='address and port dependent';
   end;
   else begin
    result:='unknown';
   end;
  end;
 end;

 // aBehindNAT false runs the very same thing on the bare virtual network, which is the reference
 // point: whatever the detection reports there is what no NAT looks like.
 function Detect(const aBehindNAT:boolean;
                 const aKind:TRNLTestNATKind;
                 out aResult:TRNLNATDetectionResult):boolean;
 var Instance:TRNLInstance;
     VirtualNetwork:TRNLVirtualNetwork;
     NAT:TRNLTestNATNetwork;
     Network:TRNLNetwork;
     ServerA,ServerB,ServerC:TRNLTestSTUNServer;
     Host:TRNLHost;
     Inside,Unused:TRNLAddress;
     Servers:array[0..2] of TRNLAddress;
     ExternalHost:TRNLHostAddress;

  function AddressOf(const aHost:TRNLRawByteString;const aPort:TRNLUInt16):TRNLAddress;
  begin
   FillChar(result,SizeOf(TRNLAddress),#0);
   VirtualNetwork.AddressSetHost(result,aHost);
   result.Port:=aPort;
  end;

 begin

  result:=false;
  FillChar(aResult,SizeOf(TRNLNATDetectionResult),#0);

  Instance:=TRNLInstance.Create;
  try
   VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
   try

    Inside:=AddressOf(INSIDE_HOST,INSIDE_PORT);
    ExternalHost:=AddressOf(EXTERNAL_HOST,0).Host;
    Servers[0]:=AddressOf(STUN_HOST_A,STUN_PORT_A);
    Servers[1]:=AddressOf(STUN_HOST_B,STUN_PORT_A);
    Servers[2]:=AddressOf(STUN_HOST_A,STUN_PORT_B);

    NAT:=nil;
    try

     if aBehindNAT then begin
      NAT:=TRNLTestNATNetwork.Create(Instance,VirtualNetwork,aKind,ExternalHost,Inside.Host);
      NAT.AddInside(Inside);
      Network:=NAT;
     end else begin
      Network:=VirtualNetwork;
     end;

     // The servers report what they actually see, which behind a NAT is the translated address and
     // in front of one is the sender itself. Nothing else about them differs.
     FillChar(Unused,SizeOf(TRNLAddress),#0);
     ServerA:=TRNLTestSTUNServer.Create(Instance,Network,STUN_PORT_A,
                                        RNL_TEST_STUN_SERVER_REPORTING_SENDER,Unused,
                                        Servers[0].Host);
     try
      ServerB:=TRNLTestSTUNServer.Create(Instance,Network,STUN_PORT_A,
                                         RNL_TEST_STUN_SERVER_REPORTING_SENDER,Unused,
                                         Servers[1].Host);
      try
       ServerC:=TRNLTestSTUNServer.Create(Instance,Network,STUN_PORT_B,
                                          RNL_TEST_STUN_SERVER_REPORTING_SENDER,Unused,
                                          Servers[2].Host);
       try

        Host:=TRNLHost.Create(Instance,Network);
        try
         Host.Address.Host:=Inside.Host;
         Host.Address.Port:=Inside.Port;
         Host.Start(RNL_HOST_ADDRESS_FAMILY_WORK_MODE_IPV4_ONLY);

         result:=Host.DetectNATMappingBehaviour(Servers,aResult,1000);

        finally
         FreeAndNil(Host);
        end;

       finally
        FreeAndNil(ServerC);
       end;
      finally
       FreeAndNil(ServerB);
      end;
     finally
      FreeAndNil(ServerA);
     end;

    finally
     FreeAndNil(NAT);
    end;

   finally
    FreeAndNil(VirtualNetwork);
   end;
  finally
   FreeAndNil(Instance);
  end;

 end;

 procedure CheckKind(const aBehindNAT:boolean;
                     const aKind:TRNLTestNATKind;
                     const aExpected:TRNLNATMappingBehaviour;
                     const aWhat:TRNLRawByteString);
 var DetectionResult:TRNLNATDetectionResult;
 begin
  if not Check(Detect(aBehindNAT,aKind,DetectionResult),aWhat+': a server answers at all') then begin
   exit;
  end;
  Info(aWhat+': seen as '+TRNLRawByteString(DetectionResult.MappedAddress.ToString)+
       ' while bound to '+TRNLRawByteString(DetectionResult.LocalAddress.ToString)+
       ', '+TRNLRawByteString(IntToStr(DetectionResult.CountAnsweringServers))+
       ' server(s) answered, mapping is '+NameOf(DetectionResult.Behaviour));
  Check(DetectionResult.Behaviour=aExpected,
        aWhat+': mapping has to come out as '+NameOf(aExpected)+
        ', not as '+NameOf(DetectionResult.Behaviour));
 end;

begin

 TestBegin('the nat mapping behaviour is detected for every simulated nat kind');
 Watchdog:=TRNLTestWatchdog.Create('nat mapping detection',180000);
 try

  // No NAT at all: the socket is seen under the address it is bound to, and nothing else in the
  // detection may claim otherwise
  CheckKind(false,RNL_TEST_NAT_FULL_CONE,RNL_NAT_MAPPING_BEHAVIOUR_NONE,'without a nat');

  // The three restricting kinds differ in what they let back in, not in how they map, so all three
  // have to come out the same here. That is the point of running all of them.
  CheckKind(true,RNL_TEST_NAT_FULL_CONE,
            RNL_NAT_MAPPING_BEHAVIOUR_ENDPOINT_INDEPENDENT,'full cone');
  CheckKind(true,RNL_TEST_NAT_ADDRESS_RESTRICTED,
            RNL_NAT_MAPPING_BEHAVIOUR_ENDPOINT_INDEPENDENT,'address restricted');
  CheckKind(true,RNL_TEST_NAT_PORT_RESTRICTED,
            RNL_NAT_MAPPING_BEHAVIOUR_ENDPOINT_INDEPENDENT,'port restricted');

  // The symmetric one hands out a fresh external port per destination host and port, so the third
  // server is what separates it from a merely address dependent one
  CheckKind(true,RNL_TEST_NAT_SYMMETRIC,
            RNL_NAT_MAPPING_BEHAVIOUR_ADDRESS_AND_PORT_DEPENDENT,'symmetric');

  // And what all of that is for: saying beforehand whether a direct connection is worth trying
  Check(TRNLNATUtils.PredictHolePunchingViability(RNL_NAT_MAPPING_BEHAVIOUR_ENDPOINT_INDEPENDENT,
                                                  RNL_NAT_MAPPING_BEHAVIOUR_ENDPOINT_INDEPENDENT)=
        RNL_HOLE_PUNCHING_VIABILITY_GOOD,
        'two nats which keep one mapping per socket are the good case');

  Check(TRNLNATUtils.PredictHolePunchingViability(RNL_NAT_MAPPING_BEHAVIOUR_ADDRESS_AND_PORT_DEPENDENT,
                                                  RNL_NAT_MAPPING_BEHAVIOUR_ADDRESS_AND_PORT_DEPENDENT)=
        RNL_HOLE_PUNCHING_VIABILITY_HOPELESS,
        'two which do not are the case a relay exists for');

  Check(TRNLNATUtils.PredictHolePunchingViability(RNL_NAT_MAPPING_BEHAVIOUR_ADDRESS_AND_PORT_DEPENDENT,
                                                  RNL_NAT_MAPPING_BEHAVIOUR_ENDPOINT_INDEPENDENT)=
        RNL_HOLE_PUNCHING_VIABILITY_POOR,
        'one of each is worth a try, but only from the right side');

  Check(TRNLNATUtils.PredictHolePunchingViability(RNL_NAT_MAPPING_BEHAVIOUR_NONE,
                                                  RNL_NAT_MAPPING_BEHAVIOUR_ADDRESS_AND_PORT_DEPENDENT)=
        RNL_HOLE_PUNCHING_VIABILITY_DIRECT,
        'and a side without a nat is reachable whatever the other one does');

  Check(TRNLNATUtils.PredictHolePunchingViability(RNL_NAT_MAPPING_BEHAVIOUR_UNKNOWN,
                                                  RNL_NAT_MAPPING_BEHAVIOUR_ENDPOINT_INDEPENDENT)=
        RNL_HOLE_PUNCHING_VIABILITY_UNKNOWN,
        'while one unknown side makes the whole prediction unknown');

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

// ---------------------------------------------------------------------------------------
// What a candidate list costs
// ---------------------------------------------------------------------------------------

// The candidate list of a connection attempt is not this host's to choose: it arrives over
// whatever signalling brought the two sides together, and the counter side decides what is in it.
// Every entry is an address this host then sends a full handshake packet to, once per repetition
// round, ten times a second, and a handshake packet is padded to 508 bytes so that RNL itself can
// not be used as an amplifier. Fanning out over a list without a bound gives that padding right
// back: a list of addresses which never answer costs this host 508 bytes per entry per round and
// hands every one of those addresses a steady stream it never asked for, for as long as the
// attempt runs, at no cost at all to whoever wrote the list.
//
// So the round serves at most a fixed number of candidates and continues where it left off next
// time. This measures both ends of that: the traffic which leaves this host, and the share of it
// which reaches any single address in the list.
//
// None of the candidates here answers, which is what keeps the fan out running for the whole
// measurement window instead of stopping at the first reply, and is at the same time exactly the
// case worth bounding.
procedure TestCandidateFanOutStaysBoundedForALongCandidateList;
const COUNT_BYSTANDERS=16;
      MAXIMUM_PER_ROUND=4;
      FIRST_BYSTANDER_PORT=18490;
      CLIENT_PORT=18489;
      FAN_OUT_MILLISECONDS=1000;
      // Anything but the one the client uses, so that a bystander counts what arrives and
      // answers none of it
      BYSTANDER_PROTOCOL_ID=TRNLUInt64($1234567890abcdef);
var UnboundedTotal,UnboundedMaximum,BoundedTotal,BoundedMaximum:TRNLUInt64;
    Watchdog:TRNLTestWatchdog;

 procedure Run(const aMaximumPerRound:TRNLSizeInt;
               out aTotal,aMaximum:TRNLUInt64);
 var Instance:TRNLInstance;
     Network:TRNLVirtualNetwork;
     Client:TRNLHost;
     Bystanders:array of TRNLHost;
     Candidates:TRNLCandidates;
     Address:TRNLAddress;
     Peer:TRNLPeer;
     Event:TRNLHostEvent;
     StartTime:TRNLTime;
     Index:TRNLSizeInt;
 begin

  aTotal:=0;
  aMaximum:=0;

  Bystanders:=nil;
  Candidates:=nil;

  Instance:=TRNLInstance.Create;
  try
   Network:=TRNLVirtualNetwork.Create(Instance);
   try

    SetLength(Bystanders,COUNT_BYSTANDERS);
    for Index:=0 to COUNT_BYSTANDERS-1 do begin
     Bystanders[Index]:=nil;
    end;
    try

     FillChar(Address,SizeOf(TRNLAddress),#0);
     Network.AddressSetHost(Address,'127.0.0.1');

     SetLength(Candidates,COUNT_BYSTANDERS);
     for Index:=0 to COUNT_BYSTANDERS-1 do begin
      Bystanders[Index]:=TRNLHost.Create(Instance,Network);
      Bystanders[Index].Address.Host:=Address.Host;
      Bystanders[Index].Address.Port:=FIRST_BYSTANDER_PORT+Index;
      Bystanders[Index].ProtocolID:=BYSTANDER_PROTOCOL_ID;
      Bystanders[Index].Start(RNL_HOST_ADDRESS_FAMILY_WORK_MODE_IPV4_ONLY);
      FillChar(Candidates[Index],SizeOf(TRNLCandidate),#0);
      Candidates[Index].Address:=Address;
      Candidates[Index].Address.Port:=FIRST_BYSTANDER_PORT+Index;
      Candidates[Index].Kind:=RNL_CANDIDATE_KIND_HOST;
      Candidates[Index].Priority:=TRNLCandidateUtils.Priority(RNL_CANDIDATE_KIND_HOST,Index);
     end;

     Client:=TRNLHost.Create(Instance,Network);
     try

      Client.Address.Host:=Address.Host;
      Client.Address.Port:=CLIENT_PORT;
      Client.MaximumCandidatesPerHandshakeRound:=aMaximumPerRound;
      Client.Start(RNL_HOST_ADDRESS_FAMILY_WORK_MODE_IPV4_ONLY);

      Peer:=Client.ConnectViaCandidates(Candidates);
      if assigned(Peer) then begin
       Peer.IncRef;
       try

        StartTime:=Instance.Time;
        Event.Initialize;
        try
         repeat
          while Client.Service(Event,0)=RNL_HOST_SERVICE_STATUS_EVENT do begin
           Event.Free;
          end;
          for Index:=0 to COUNT_BYSTANDERS-1 do begin
           while Bystanders[Index].Service(Event,0)=RNL_HOST_SERVICE_STATUS_EVENT do begin
            Event.Free;
           end;
          end;
          Sleep(1);
         until TRNLTime.RelativeDifference(Instance.Time,StartTime)>=FAN_OUT_MILLISECONDS;
        finally
         Event.Free;
        end;

       finally
        Peer.DecRef;
       end;
      end;

      for Index:=0 to COUNT_BYSTANDERS-1 do begin
       inc(aTotal,Bystanders[Index].TotalReceivedData);
       if aMaximum<Bystanders[Index].TotalReceivedData then begin
        aMaximum:=Bystanders[Index].TotalReceivedData;
       end;
      end;

     finally
      FreeAndNil(Client);
     end;

    finally
     for Index:=0 to COUNT_BYSTANDERS-1 do begin
      FreeAndNil(Bystanders[Index]);
     end;
     Bystanders:=nil;
     Candidates:=nil;
    end;

   finally
    FreeAndNil(Network);
   end;
  finally
   FreeAndNil(Instance);
  end;

 end;

begin

 TestBegin('fanning out over a long candidate list stays bounded');
 Watchdog:=TRNLTestWatchdog.Create('candidate fan out cost',120000);
 try

  Run(0,UnboundedTotal,UnboundedMaximum);
  Run(MAXIMUM_PER_ROUND,BoundedTotal,BoundedMaximum);

  Info('candidates: '+TRNLRawByteString(IntToStr(COUNT_BYSTANDERS))+
       ', none of them answering, over '+TRNLRawByteString(IntToStr(FAN_OUT_MILLISECONDS))+' ms');
  Info('without a bound: '+TRNLRawByteString(IntToStr(UnboundedTotal))+
       ' bytes in total, at most '+TRNLRawByteString(IntToStr(UnboundedMaximum))+
       ' bytes at a single address');
  Info('at most '+TRNLRawByteString(IntToStr(MAXIMUM_PER_ROUND))+
       ' per round: '+TRNLRawByteString(IntToStr(BoundedTotal))+
       ' bytes in total, at most '+TRNLRawByteString(IntToStr(BoundedMaximum))+
       ' bytes at a single address');

  if not Check(UnboundedTotal>0,'the unbounded run has to have produced traffic at all') then begin
   exit;
  end;

  // Four out of sixteen per round, so a quarter is what is expected; halved is the assertion, which
  // leaves room for a round more or less on either side without turning this into a timing test
  CheckAtMostInt64(BoundedTotal,UnboundedTotal div 2,
                   'the bound has to show in what leaves the host');

  CheckAtMostInt64(BoundedMaximum,UnboundedMaximum div 2,
                   'and in what any single address in the list gets to see');

  // Every entry still has to be reached, just spread over rounds, because one of them may well be
  // the address the connection is actually going to come up on
  CheckAtLeastInt64(BoundedTotal,TRNLInt64(COUNT_BYSTANDERS)*RNL_TEST_HANDSHAKE_PACKET_SIZE,
                    'and every candidate still has to have been served at least once');

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

// ---------------------------------------------------------------------------------------
// Streaming a hash and the key length boundary of HMAC
// ---------------------------------------------------------------------------------------

// The self tests of the hashes check digests against the published vectors, all of them in one
// Update call. That leaves the two places where such an implementation actually breaks untouched.
//
// The first is the block boundary. Update takes a message in three phases - bytes until the word
// boundary, then whole words, then the remainder - and each phase has to hand a full block over to
// the compression function at exactly the right moment. Fed in one lump that logic is barely
// exercised; fed in chunks of one, three or sixty five bytes it is exercised in every state it can
// be in. Since the digest must not depend on how the message was cut up, the one shot digest is the
// reference and no external vector is needed.
//
// The second is the key handling of HMAC. RFC 2104 replaces a key longer than one block by its own
// digest and zero pads a shorter one, so at exactly the block size the behaviour changes. Both
// sides of that are checked without an external vector too: a key of 65 bytes has to give the same
// result as its digest used as the key, and a key of 64 bytes must not.
procedure TestHashesStreamInChunksAndHMACHandlesKeyLengths;
const MESSAGE_SIZE=1000;
      CHUNK_SIZES:array[0..5] of TRNLSizeInt=(1,3,7,63,64,65);
var Watchdog:TRNLTestWatchdog;
    Message_:array[0..MESSAGE_SIZE-1] of TRNLUInt8;
    Index:TRNLSizeInt;

 // Whatever the chunk size, the digest has to be the one of the whole message
 procedure CheckSHA256Streaming;
 var OneShot,Streamed:TRNLSHA256Hash;
     Context:TRNLSHA256Context;
     ChunkIndex,Position,Chunk:TRNLSizeInt;
     AllMatched:boolean;
 begin
  TRNLSHA256.Process(OneShot,Message_,SizeOf(Message_));
  AllMatched:=true;
  for ChunkIndex:=Low(CHUNK_SIZES) to High(CHUNK_SIZES) do begin
   Context.Initialize;
   Position:=0;
   while Position<SizeOf(Message_) do begin
    Chunk:=CHUNK_SIZES[ChunkIndex];
    if Chunk>(TRNLSizeInt(SizeOf(Message_))-Position) then begin
     Chunk:=TRNLSizeInt(SizeOf(Message_))-Position;
    end;
    Context.Update(Message_[Position],Chunk);
    inc(Position,Chunk);
   end;
   Context.Finalize(Streamed);
   if not TRNLMemory.SecureIsEqual(Streamed,OneShot,SizeOf(TRNLSHA256Hash)) then begin
    AllMatched:=false;
    Info('sha256 differs at a chunk size of '+TRNLRawByteString(IntToStr(CHUNK_SIZES[ChunkIndex])));
   end;
  end;
  Check(AllMatched,'sha256 has to give the same digest however the message is cut up');
 end;

 procedure CheckSHA1Streaming;
 var OneShot,Streamed:TRNLSHA1Hash;
     Context:TRNLSHA1Context;
     ChunkIndex,Position,Chunk:TRNLSizeInt;
     AllMatched:boolean;
 begin
  TRNLSHA1.Process(OneShot,Message_,SizeOf(Message_));
  AllMatched:=true;
  for ChunkIndex:=Low(CHUNK_SIZES) to High(CHUNK_SIZES) do begin
   Context.Initialize;
   Position:=0;
   while Position<SizeOf(Message_) do begin
    Chunk:=CHUNK_SIZES[ChunkIndex];
    if Chunk>(TRNLSizeInt(SizeOf(Message_))-Position) then begin
     Chunk:=TRNLSizeInt(SizeOf(Message_))-Position;
    end;
    Context.Update(Message_[Position],Chunk);
    inc(Position,Chunk);
   end;
   Context.Finalize(Streamed);
   if not TRNLMemory.SecureIsEqual(Streamed,OneShot,SizeOf(TRNLSHA1Hash)) then begin
    AllMatched:=false;
    Info('sha1 differs at a chunk size of '+TRNLRawByteString(IntToStr(CHUNK_SIZES[ChunkIndex])));
   end;
  end;
  Check(AllMatched,'and so does sha1');
 end;

 procedure CheckMD5Streaming;
 var OneShot,Streamed:TRNLMD5Hash;
     Context:TRNLMD5Context;
     ChunkIndex,Position,Chunk:TRNLSizeInt;
     AllMatched:boolean;
 begin
  TRNLMD5.Process(OneShot,Message_,SizeOf(Message_));
  AllMatched:=true;
  for ChunkIndex:=Low(CHUNK_SIZES) to High(CHUNK_SIZES) do begin
   Context.Initialize;
   Position:=0;
   while Position<SizeOf(Message_) do begin
    Chunk:=CHUNK_SIZES[ChunkIndex];
    if Chunk>(TRNLSizeInt(SizeOf(Message_))-Position) then begin
     Chunk:=TRNLSizeInt(SizeOf(Message_))-Position;
    end;
    Context.Update(Message_[Position],Chunk);
    inc(Position,Chunk);
   end;
   Context.Finalize(Streamed);
   if not TRNLMemory.SecureIsEqual(Streamed,OneShot,SizeOf(TRNLMD5Hash)) then begin
    AllMatched:=false;
    Info('md5 differs at a chunk size of '+TRNLRawByteString(IntToStr(CHUNK_SIZES[ChunkIndex])));
   end;
  end;
  Check(AllMatched,'and md5, which is the one reading its words the other way round');
 end;

 procedure CheckHMACKeyLengthBoundary;
 var ShortKey:array[0..63] of TRNLUInt8;
     LongKey:array[0..64] of TRNLUInt8;
     DigestOfLongKey,DigestOfShortKey:TRNLSHA256Hash;
     WithLongKey,WithItsDigest,WithShortKey,WithShortKeyDigest:TRNLSHA256Hash;
     KeyIndex:TRNLSizeInt;
 begin

  // Two keys which differ in length by one, right across the block size
  for KeyIndex:=0 to SizeOf(LongKey)-1 do begin
   LongKey[KeyIndex]:=TRNLUInt8($a0+(KeyIndex and $0f));
  end;
  Move(LongKey[0],ShortKey[0],SizeOf(ShortKey));

  TRNLSHA256.Process(DigestOfLongKey,LongKey,SizeOf(LongKey));
  TRNLSHA256.Process(DigestOfShortKey,ShortKey,SizeOf(ShortKey));

  TRNLHMACSHA256.Process(WithLongKey,LongKey,SizeOf(LongKey),Message_,SizeOf(Message_));
  TRNLHMACSHA256.Process(WithItsDigest,DigestOfLongKey,SizeOf(DigestOfLongKey),Message_,SizeOf(Message_));
  TRNLHMACSHA256.Process(WithShortKey,ShortKey,SizeOf(ShortKey),Message_,SizeOf(Message_));
  TRNLHMACSHA256.Process(WithShortKeyDigest,DigestOfShortKey,SizeOf(DigestOfShortKey),Message_,SizeOf(Message_));

  Check(TRNLMemory.SecureIsEqual(WithLongKey,WithItsDigest,SizeOf(TRNLSHA256Hash)),
        'a key of 65 bytes has to stand in for its own digest, since that is what rfc 2104 says '+
        'happens to a key longer than one block');

  Check(not TRNLMemory.SecureIsEqual(WithShortKey,WithShortKeyDigest,SizeOf(TRNLSHA256Hash)),
        'while a key of 64 bytes is used as it is, so the boundary really sits at the block size '+
        'and not one byte to either side of it');

 end;

begin

 TestBegin('the hashes stream in chunks and hmac handles every key length');
 Watchdog:=TRNLTestWatchdog.Create('hash streaming',60000);
 try

  // Something that is not all the same byte, so that a chunk landing in the wrong place shows
  for Index:=0 to SizeOf(Message_)-1 do begin
   Message_[Index]:=TRNLUInt8((Index*7) xor (Index shr 3));
  end;

  Info('message of '+TRNLRawByteString(IntToStr(MESSAGE_SIZE))+
       ' bytes, fed in chunks of 1, 3, 7, 63, 64 and 65 bytes');

  CheckSHA256Streaming;
  CheckSHA1Streaming;
  CheckMD5Streaming;
  CheckHMACKeyLengthBoundary;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

// ---------------------------------------------------------------------------------------
// Peer capacity
// ---------------------------------------------------------------------------------------

// A host has to accept exactly as many incoming connections as MaximumCountPeers says, and the
// incoming path has to agree with the outgoing one about that number. The two are separate pieces
// of code, so they can and did drift apart: the incoming side asked whether the count would still
// be strictly below the maximum after adding the peer, which admitted one fewer, while the
// outgoing side admits while the current count is below the maximum.
//
// A capacity which is off by one is easy to miss, because it only shows up once a host is actually
// full, and it then looks like an ordinary rejection rather than like a defect.
procedure TestHostAcceptsExactlyItsConfiguredPeerCapacity;
const SERVER_PORT=18264;
      FIRST_CLIENT_PORT=18265;
      MAXIMUM_COUNT_PEERS=3;
var Instance:TRNLInstance;
    Network:TRNLVirtualNetwork;
    Server:TRNLHost;
    Clients:array of TRNLHost;
    Peers:array of TRNLPeer;
    ServerAddress:TRNLAddress;
    Event:TRNLHostEvent;
    Index,CountConnected,CountDenied:TRNLSizeInt;
    StartTime:TRNLTime;
    Watchdog:TRNLTestWatchdog;

 procedure PumpAll;
 var HostIndex:TRNLSizeInt;
 begin
  Event.Initialize;
  try
   while Server.Service(Event,0)=RNL_HOST_SERVICE_STATUS_EVENT do begin
    Event.Free;
   end;
   Event.Free;
   for HostIndex:=0 to length(Clients)-1 do begin
    while Clients[HostIndex].Service(Event,0)=RNL_HOST_SERVICE_STATUS_EVENT do begin
     case Event.Type_ of
      RNL_HOST_EVENT_TYPE_PEER_APPROVAL:begin
       inc(CountConnected);
      end;
      RNL_HOST_EVENT_TYPE_PEER_DENIAL:begin
       inc(CountDenied);
      end;
      else begin
      end;
     end;
     Event.Free;
    end;
    Event.Free;
   end;
  finally
   Event.Free;
  end;
 end;

begin

 TestBegin('a host accepts exactly its configured peer capacity');
 Watchdog:=TRNLTestWatchdog.Create('peer capacity',120000);
 try

  CountConnected:=0;
  CountDenied:=0;
  Clients:=nil;
  Peers:=nil;

  Instance:=TRNLInstance.Create;
  try
   Network:=TRNLVirtualNetwork.Create(Instance);
   try

    Server:=TRNLHost.Create(Instance,Network);
    try

     Server.Address.Host:=RNL_HOST_ANY;
     Server.Address.Port:=SERVER_PORT;
     Server.MaximumCountPeers:=MAXIMUM_COUNT_PEERS;
     Server.Start(RNL_HOST_ADDRESS_FAMILY_WORK_MODE_IPV4_ONLY);

     Network.AddressSetHost(ServerAddress,'127.0.0.1');
     ServerAddress.Port:=SERVER_PORT;

     // One more client than the server may accept, so that the last one has to be turned away and
     // the boundary is exercised from both sides
     SetLength(Clients,MAXIMUM_COUNT_PEERS+1);
     SetLength(Peers,MAXIMUM_COUNT_PEERS+1);

     try

      for Index:=0 to length(Clients)-1 do begin
       Clients[Index]:=TRNLHost.Create(Instance,Network);
       Clients[Index].Address.Host:=RNL_HOST_ANY;
       Clients[Index].Address.Port:=FIRST_CLIENT_PORT+Index;
       Clients[Index].Start(RNL_HOST_ADDRESS_FAMILY_WORK_MODE_IPV4_ONLY);
       Peers[Index]:=Clients[Index].Connect(ServerAddress,1,0);
       if assigned(Peers[Index]) then begin
        Peers[Index].IncRef;
       end;
      end;

      StartTime:=Instance.Time;
      repeat
       PumpAll;
       Sleep(1);
      until ((CountConnected+CountDenied)>=length(Clients)) or
            (TRNLTime.RelativeDifference(Instance.Time,StartTime)>=15000);

      Info('MaximumCountPeers: '+TRNLRawByteString(IntToStr(MAXIMUM_COUNT_PEERS))+
           ', clients attempting: '+TRNLRawByteString(IntToStr(length(Clients))));
      Info('connected: '+TRNLRawByteString(IntToStr(CountConnected))+
           ', denied: '+TRNLRawByteString(IntToStr(CountDenied))+
           ', server CountPeers: '+TRNLRawByteString(IntToStr(Server.CountPeers)));

      CheckEqualsInt64(CountConnected,MAXIMUM_COUNT_PEERS,
                       'the server must accept exactly as many peers as it was configured for, '+
                       'no fewer');

      CheckEqualsInt64(Server.CountPeers,MAXIMUM_COUNT_PEERS,
                       'and it must actually be holding that many peers');

      CheckAtLeastInt64(CountDenied,1,
                        'the one client beyond the capacity has to be turned away, so the limit '+
                        'is not simply ignored either');

     finally
      for Index:=0 to length(Peers)-1 do begin
       if assigned(Peers[Index]) then begin
        Peers[Index].DecRef;
       end;
      end;
      for Index:=0 to length(Clients)-1 do begin
       FreeAndNil(Clients[Index]);
      end;
     end;

    finally
     FreeAndNil(Server);
    end;

   finally
    FreeAndNil(Network);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

function EitherText(const aCondition:boolean;const aWhenTrue,aWhenFalse:TRNLRawByteString):TRNLRawByteString;
begin
 if aCondition then begin
  result:=aWhenTrue;
 end else begin
  result:=aWhenFalse;
 end;
end;

procedure TestTranscriptBindingCoversTheCleartextHandshakeFields;
const FIRST_PORT=18320;
      THROTTLED_TO_BITS_PER_SECOND=1;
var PortOffset:TRNLSizeInt;
    Watchdog:TRNLTestWatchdog;

 // Runs one handshake in one mode while one field of the connection request is being overwritten,
 // and reports whether it came up and what the server ended up believing about the client's limit
 procedure RunScenario(const aMode:TRNLProtocolTranscriptBindingMode;
                       const aOffset:TRNLSizeUInt;
                       const aValue;
                       const aValueLength:TRNLSizeUInt;
                       out aConnected:boolean;
                       out aServerSeenIncomingBandwidthLimit:TRNLUInt32);
 var Instance:TRNLInstance;
     VirtualNetwork:TRNLVirtualNetwork;
     FaultInjector:TRNLNetworkFaultInjector;
     HostPair:TRNLTestHostPair;
 begin
  aConnected:=false;
  aServerSeenIncomingBandwidthLimit:=0;
  Instance:=TRNLInstance.Create;
  try
   VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
   try
    FaultInjector:=TRNLNetworkFaultInjector.Create(Instance,VirtualNetwork);
    try
     FaultInjector.RewriteOutgoingHandshakeField(HandshakePacketType(RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_REQUEST),
                                                 aOffset,
                                                 aValue,
                                                 aValueLength);
     HostPair:=TRNLTestHostPair.Create(Instance,
                                       FaultInjector,
                                       FIRST_PORT+(PortOffset*2),
                                       FIRST_PORT+(PortOffset*2)+1);
     try
      HostPair.Client.TranscriptBindingMode:=aMode;
      HostPair.Server.TranscriptBindingMode:=aMode;
      if aMode=RNL_PROTOCOL_TRANSCRIPT_BINDING_OFF then begin
       aConnected:=HostPair.Connect(5000);
      end else begin
       // Nothing to wait for once the signature check has turned it down
       aConnected:=HostPair.Connect(2000);
      end;
      if aConnected and assigned(HostPair.ServerPeer) then begin
       aServerSeenIncomingBandwidthLimit:=HostPair.ServerPeer.RemoteIncomingBandwidthLimit;
      end;
     finally
      FreeAndNil(HostPair);
     end;
    finally
     FreeAndNil(FaultInjector);
    end;
   finally
    FreeAndNil(VirtualNetwork);
   end;
  finally
   FreeAndNil(Instance);
  end;
  inc(PortOffset);
 end;

var Probe:TRNLProtocolHandshakePacketConnectionRequest;
    ThrottleValue:TRNLUInt32;
    TokenFiller:array[0..15] of TRNLUInt8;
    Index:TRNLSizeInt;
    Connected:boolean;
    SeenLimit:TRNLUInt32;
begin

 TestBegin('the transcript binding covers the cleartext handshake fields');
 Watchdog:=TRNLTestWatchdog.Create('transcript binding coverage',180000);
 try

  PortOffset:=0;
  ThrottleValue:=TRNLEndianness.HostToLittleEndian32(THROTTLED_TO_BITS_PER_SECOND);
  for Index:=Low(TokenFiller) to High(TokenFiller) do begin
   TokenFiller[Index]:=TRNLUInt8($5a);
  end;

  // The bandwidth limit, which is the field that makes this more than a formality. It is not
  // decoration: the server hands it straight to the rate limiter which paces everything it sends
  // to that peer, so whoever can rewrite it decides how fast the connection may go.

  RunScenario(RNL_PROTOCOL_TRANSCRIPT_BINDING_OFF,
              HandshakeFieldOffset(Probe,Probe.IncomingBandwidthLimit),
              ThrottleValue,SizeOf(ThrottleValue),Connected,SeenLimit);

  Info('bandwidth limit rewritten, binding off: connected '+
       TRNLRawByteString(BoolToStr(Connected,true))+
       ', server believes the limit is '+TRNLRawByteString(IntToStr(SeenLimit))+' bit/s');

  Check(Connected,'without the binding the handshake completes although the request was altered');

  CheckEqualsInt64(SeenLimit,THROTTLED_TO_BITS_PER_SECOND,
                   'and the altered value is what the server ends up pacing that peer by, which '+
                   'is a connection throttled to nothing without a single check complaining');

  RunScenario(RNL_PROTOCOL_TRANSCRIPT_BINDING_REQUIRED,
              HandshakeFieldOffset(Probe,Probe.IncomingBandwidthLimit),
              ThrottleValue,SizeOf(ThrottleValue),Connected,SeenLimit);

  Info('bandwidth limit rewritten, binding required: connected '+
       TRNLRawByteString(BoolToStr(Connected,true)));

  Check(not Connected,'with the binding required the same alteration breaks the signature check '+
                      'and the handshake fails instead of quietly degrading');

  // The connection token, which nothing looks at while token checking is off. That makes it the
  // clean measure of coverage on its own: with the binding off nothing at all notices the change,
  // so a failure with the binding on can only come from the transcript.

  RunScenario(RNL_PROTOCOL_TRANSCRIPT_BINDING_OFF,
              HandshakeFieldOffset(Probe,Probe.ConnectionToken),
              TokenFiller,SizeOf(TokenFiller),Connected,SeenLimit);

  Info('connection token rewritten, binding off: connected '+
       TRNLRawByteString(BoolToStr(Connected,true)));

  Check(Connected,'an unchecked connection token can be rewritten freely without the binding');

  RunScenario(RNL_PROTOCOL_TRANSCRIPT_BINDING_REQUIRED,
              HandshakeFieldOffset(Probe,Probe.ConnectionToken),
              TokenFiller,SizeOf(TokenFiller),Connected,SeenLimit);

  Info('connection token rewritten, binding required: connected '+
       TRNLRawByteString(BoolToStr(Connected,true)));

  Check(not Connected,'and with the binding it cannot, which shows the transcript really covers '+
                      'the field and not merely something else that happens to change with it');

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

procedure TestGatherCandidatesFindsHostAndServerReflexive;
const HOST_PORT=18440;
      STUN_PORT=18441;
      REFLEXIVE_HOST='203.0.113.7';
      REFLEXIVE_PORT=51234;
var Instance:TRNLInstance;
    Network:TRNLVirtualNetwork;
    STUNServer:TRNLTestSTUNServer;
    Host:TRNLHost;
    STUNServerAddress,ReportedAddress:TRNLAddress;
    STUNServers:array[0..0] of TRNLAddress;
    Candidates:TRNLCandidates;
    Index,CountHost,CountReflexive:TRNLSizeInt;
    ReflexiveCorrect:boolean;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('gathering candidates finds the host and the server reflexive one');
 Watchdog:=TRNLTestWatchdog.Create('gather candidates',60000);
 try

  Instance:=TRNLInstance.Create;
  try
   Network:=TRNLVirtualNetwork.Create(Instance);
   try

    FillChar(ReportedAddress,SizeOf(TRNLAddress),#0);
    Network.AddressSetHost(ReportedAddress,REFLEXIVE_HOST);
    ReportedAddress.Port:=REFLEXIVE_PORT;

    STUNServer:=TRNLTestSTUNServer.Create(Instance,Network,STUN_PORT,
                                          RNL_TEST_STUN_SERVER_CORRECT,ReportedAddress);
    try

     Host:=TRNLHost.Create(Instance,Network);
     try

      Host.Address.Host:=RNL_HOST_ANY;
      Host.Address.Port:=HOST_PORT;
      Host.Start(RNL_HOST_ADDRESS_FAMILY_WORK_MODE_IPV4_ONLY);

      FillChar(STUNServerAddress,SizeOf(TRNLAddress),#0);
      Network.AddressSetHost(STUNServerAddress,'127.0.0.1');
      STUNServerAddress.Port:=STUN_PORT;
      STUNServers[0]:=STUNServerAddress;

      // Between Start and the first Service, which is the only place this belongs: it reads from the
      // host's own socket while it waits for the answer
      if not Check(Host.GatherCandidates(STUNServers,Candidates,1000),
                   'gathering has to come up with something') then begin
       exit;
      end;

      CountHost:=0;
      CountReflexive:=0;
      ReflexiveCorrect:=false;
      for Index:=0 to length(Candidates)-1 do begin
       case Candidates[Index].Kind of
        RNL_CANDIDATE_KIND_HOST:begin
         inc(CountHost);
        end;
        RNL_CANDIDATE_KIND_SERVER_REFLEXIVE:begin
         inc(CountReflexive);
         ReflexiveCorrect:=Candidates[Index].Address.Host.Equals(ReportedAddress.Host) and
                           (Candidates[Index].Address.Port=REFLEXIVE_PORT);
        end;
        else begin
        end;
       end;
       Info('candidate '+TRNLRawByteString(IntToStr(Index))+': kind '+
            TRNLRawByteString(IntToStr(TRNLInt32(Candidates[Index].Kind)))+
            ', socket '+TRNLRawByteString(IntToStr(Candidates[Index].SocketIndex))+
            ', priority '+TRNLRawByteString(IntToStr(Candidates[Index].Priority))+
            ', address '+TRNLRawByteString(Candidates[Index].Address.ToString));
      end;

      CheckAtLeastInt64(CountHost,1,
                        'there has to be at least one host candidate. The virtual network has no '+
                        'interfaces to enumerate, so what the socket is bound to is the only one, '+
                        'and it is a true one');

      CheckEqualsInt64(CountReflexive,1,
                       'and exactly one server reflexive candidate, since one stun server answered');

      Check(ReflexiveCorrect,
            'which carries the address the stun server reported and not the local one');

      // Host beats server reflexive, always, which is what makes the direct path get tried first
      Check((length(Candidates)>1) and
            (Candidates[0].Kind=RNL_CANDIDATE_KIND_HOST),
            'and the list comes back with a host candidate in front');

      CheckEqualsInt64(length(Host.LocalCandidates),length(Candidates),
                       'the host remembers what was gathered');

     finally
      FreeAndNil(Host);
     end;

    finally
     FreeAndNil(STUNServer);
    end;

   finally
    FreeAndNil(Network);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

procedure TestSimultaneousConnectResolvesToOneConnection;
const HOST_A_PORT=18470;
      HOST_B_PORT=18471;
var Instance:TRNLInstance;
    Network:TRNLVirtualNetwork;
    HostA,HostB:TRNLHost;
    AddressA,AddressB:TRNLAddress;
    PeerA,PeerB:TRNLPeer;
    Event:TRNLHostEvent;
    StartTime:TRNLTime;
    CountApprovalsA,CountIncomingA,CountApprovalsB,CountIncomingB:TRNLSizeInt;
    Watchdog:TRNLTestWatchdog;

 function CandidateOf(const aAddress:TRNLAddress):TRNLCandidates;
 begin
  result:=nil;
  SetLength(result,1);
  FillChar(result[0],SizeOf(TRNLCandidate),#0);
  result[0].Address:=aAddress;
  result[0].Kind:=RNL_CANDIDATE_KIND_HOST;
  result[0].Priority:=TRNLCandidateUtils.Priority(RNL_CANDIDATE_KIND_HOST,0);
 end;

 procedure Pump(const aHost:TRNLHost;var aCountApprovals,aCountIncoming:TRNLSizeInt);
 begin
  while aHost.Service(Event,0)=RNL_HOST_SERVICE_STATUS_EVENT do begin
   case Event.Type_ of
    RNL_HOST_EVENT_TYPE_PEER_APPROVAL:begin
     inc(aCountApprovals);
    end;
    RNL_HOST_EVENT_TYPE_PEER_CONNECT:begin
     inc(aCountIncoming);
    end;
    else begin
    end;
   end;
   Event.Free;
  end;
  Event.Free;
 end;

begin

 TestBegin('two hosts connecting to each other at once end up with one connection');
 Watchdog:=TRNLTestWatchdog.Create('simultaneous connect',120000);
 try

  CountApprovalsA:=0;
  CountIncomingA:=0;
  CountApprovalsB:=0;
  CountIncomingB:=0;

  Instance:=TRNLInstance.Create;
  try
   Network:=TRNLVirtualNetwork.Create(Instance);
   try

    FillChar(AddressA,SizeOf(TRNLAddress),#0);
    Network.AddressSetHost(AddressA,'127.0.0.1');
    AddressB:=AddressA;
    AddressA.Port:=HOST_A_PORT;
    AddressB.Port:=HOST_B_PORT;

    HostA:=TRNLHost.Create(Instance,Network);
    try
     HostA.Address.Host:=AddressA.Host;
     HostA.Address.Port:=HOST_A_PORT;
     HostA.Start(RNL_HOST_ADDRESS_FAMILY_WORK_MODE_IPV4_ONLY);

     HostB:=TRNLHost.Create(Instance,Network);
     try
      HostB.Address.Host:=AddressB.Host;
      HostB.Address.Port:=HOST_B_PORT;
      HostB.Start(RNL_HOST_ADDRESS_FAMILY_WORK_MODE_IPV4_ONLY);

      // Both at once, which is what two peers that punched at each other would do
      PeerA:=HostA.ConnectViaCandidates(CandidateOf(AddressB));
      PeerB:=HostB.ConnectViaCandidates(CandidateOf(AddressA));

      if not Check(assigned(PeerA) and assigned(PeerB),
                   'both sides can start an attempt') then begin
       exit;
      end;
      PeerA.IncRef;
      PeerB.IncRef;
      try

       StartTime:=Instance.Time;
       Event.Initialize;
       try
        repeat
         Pump(HostA,CountApprovalsA,CountIncomingA);
         Pump(HostB,CountApprovalsB,CountIncomingB);
         Sleep(1);
        until TRNLTime.RelativeDifference(Instance.Time,StartTime)>=3000;
       finally
        Event.Free;
       end;

       Info('host A: '+TRNLRawByteString(IntToStr(CountApprovalsA))+' approval(s), '+
            TRNLRawByteString(IntToStr(CountIncomingA))+' incoming connect(s); host B: '+
            TRNLRawByteString(IntToStr(CountApprovalsB))+' approval(s), '+
            TRNLRawByteString(IntToStr(CountIncomingB))+' incoming connect(s)');
       Info('resolution: A won '+TRNLRawByteString(IntToStr(HostA.TotalSimultaneousConnectsWon))+
            ' and gave up '+TRNLRawByteString(IntToStr(HostA.TotalSimultaneousConnectsGivenUp))+
            ', B won '+TRNLRawByteString(IntToStr(HostB.TotalSimultaneousConnectsWon))+
            ' and gave up '+TRNLRawByteString(IntToStr(HostB.TotalSimultaneousConnectsGivenUp)));

       // Exactly one of the two has to give way, because the salt comparison is antisymmetric
       CheckEqualsInt64(HostA.TotalSimultaneousConnectsGivenUp+HostB.TotalSimultaneousConnectsGivenUp,1,
                        'exactly one of the two gives way');

       CheckAtLeastInt64(HostA.TotalSimultaneousConnectsWon+HostB.TotalSimultaneousConnectsWon,1,
                         'and the other one keeps its own attempt');

       // The point of the whole thing: one connection, not two. One side ends up as the initiator
       // and sees an approval, the other one as the responder and sees an incoming connect. Without
       // the tie breaker both handshakes run to completion and every one of these is two.
       CheckEqualsInt64(CountApprovalsA+CountApprovalsB,1,'exactly one connection is approved');

       CheckEqualsInt64(CountIncomingA+CountIncomingB,1,'and exactly one is taken as incoming');

       // And the two are the two ends of the same connection, not two connections of which each
       // side happens to see one
       CheckEqualsInt64(CountApprovalsA+CountIncomingA,1,'host A holds exactly one end of it');

       CheckEqualsInt64(CountApprovalsB+CountIncomingB,1,'and host B the other one');

      finally
       PeerA.DecRef;
       PeerB.DecRef;
      end;

     finally
      FreeAndNil(HostB);
     end;

    finally
     FreeAndNil(HostA);
    end;

   finally
    FreeAndNil(Network);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

procedure TestHolePunchingOpensTheWayForAnIncomingConnection;
const INSIDE_HOST='10.0.0.2';
      EXTERNAL_HOST='198.51.100.1';
      CLIENT_HOST='203.0.113.10';
      STRANGER_HOST='203.0.113.99';
      SERVER_PORT=18460;
      CLIENT_PORT=18461;
      STRANGER_PORT=18462;
var Instance:TRNLInstance;
    VirtualNetwork:TRNLVirtualNetwork;
    NAT:TRNLTestNATNetwork;
    Server,Client:TRNLHost;
    ServerInside,ClientAddress,StrangerAddress,ExternalOfServer:TRNLAddress;
    ExternalHost,InsideHost:TRNLHostAddress;
    ServerCandidates,ClientCandidates:TRNLCandidates;
    StrangerSocket:TRNLSocket;
    Peer:TRNLPeer;
    Event:TRNLHostEvent;
    StartTime:TRNLTime;
    ConnectedWithoutPermission,ConnectedAfterPunching:boolean;
    CountPunched:TRNLSizeInt;
    Watchdog:TRNLTestWatchdog;

 function AddressOf(const aHost:TRNLRawByteString;const aPort:TRNLUInt16):TRNLAddress;
 begin
  FillChar(result,SizeOf(TRNLAddress),#0);
  VirtualNetwork.AddressSetHost(result,aHost);
  result.Port:=aPort;
 end;

 function CandidateOf(const aAddress:TRNLAddress):TRNLCandidates;
 begin
  result:=nil;
  SetLength(result,1);
  FillChar(result[0],SizeOf(TRNLCandidate),#0);
  result[0].Address:=aAddress;
  result[0].Kind:=RNL_CANDIDATE_KIND_SERVER_REFLEXIVE;
  result[0].Priority:=TRNLCandidateUtils.Priority(RNL_CANDIDATE_KIND_SERVER_REFLEXIVE,0);
 end;

 // Drives both hosts and keeps punching from the inside, the way an application waiting to be
 // reached would have to: a mapping is not permanent
 function PumpUntilConnected(const aMilliseconds:TRNLInt64;
                             const aKeepPunchingAt:TRNLCandidates):boolean;
 begin
  result:=false;
  StartTime:=Instance.Time;
  Event.Initialize;
  try
   repeat
    if length(aKeepPunchingAt)>0 then begin
     Server.PunchCandidates(aKeepPunchingAt);
    end;
    while Server.Service(Event,0)=RNL_HOST_SERVICE_STATUS_EVENT do begin
     Event.Free;
    end;
    Event.Free;
    while Client.Service(Event,0)=RNL_HOST_SERVICE_STATUS_EVENT do begin
     if Event.Type_=RNL_HOST_EVENT_TYPE_PEER_APPROVAL then begin
      result:=true;
     end;
     Event.Free;
    end;
    Event.Free;
    Sleep(1);
   until result or (TRNLTime.RelativeDifference(Instance.Time,StartTime)>=aMilliseconds);
  finally
   Event.Free;
  end;
 end;

begin

 TestBegin('hole punching opens the way for an incoming connection');
 Watchdog:=TRNLTestWatchdog.Create('hole punching',120000);
 try

  ConnectedWithoutPermission:=false;
  ConnectedAfterPunching:=false;

  Instance:=TRNLInstance.Create;
  try
   VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
   try

    ServerInside:=AddressOf(INSIDE_HOST,SERVER_PORT);
    ClientAddress:=AddressOf(CLIENT_HOST,CLIENT_PORT);
    StrangerAddress:=AddressOf(STRANGER_HOST,STRANGER_PORT);
    ExternalHost:=AddressOf(EXTERNAL_HOST,0).Host;
    InsideHost:=ServerInside.Host;

    // Port restricted, which is the common case and the one where punching is both necessary and
    // sufficient. Only a sender the inside has written to gets back in.
    NAT:=TRNLTestNATNetwork.Create(Instance,VirtualNetwork,RNL_TEST_NAT_PORT_RESTRICTED,
                                   ExternalHost,InsideHost);
    try

     NAT.AddInside(ServerInside);

     // Somebody has to be listening at the third party, because the virtual network only delivers
     // to an address a socket is bound to and reports a send to anywhere else as having sent
     // nothing. A real network swallows a datagram to a black hole and calls it sent; this one
     // cannot, so the third party gets a socket even though it never says anything.
     StrangerSocket:=NAT.SocketCreate(RNL_SOCKET_TYPE_DATAGRAM,RNL_IPV4);
     NAT.SocketBind(StrangerSocket,@StrangerAddress,RNL_IPV4);
     try

     Server:=TRNLHost.Create(Instance,NAT);
     try
      Server.Address.Host:=ServerInside.Host;
      Server.Address.ScopeID:=ServerInside.ScopeID;
      Server.Address.Port:=ServerInside.Port;
      Server.Start(RNL_HOST_ADDRESS_FAMILY_WORK_MODE_IPV4_ONLY);

      Client:=TRNLHost.Create(Instance,NAT);
      try
       Client.Address.Host:=ClientAddress.Host;
       Client.Address.ScopeID:=ClientAddress.ScopeID;
       Client.Address.Port:=ClientAddress.Port;
       Client.Start(RNL_HOST_ADDRESS_FAMILY_WORK_MODE_IPV4_ONLY);

       // The server knocks at a third party. That creates its mapping, so it now has an external
       // address to be told about, but it grants the client nothing.
       CountPunched:=Server.PunchCandidates(CandidateOf(StrangerAddress));
       if not CheckEqualsInt64(CountPunched,1,'punching at a third party sends one datagram') then begin
        exit;
       end;

       if not Check(NAT.ExternalAddressOf(ServerInside,StrangerAddress,ExternalOfServer),
                    'and gives the server an external address to be reached at') then begin
        exit;
       end;

       Info('server is externally at '+TRNLRawByteString(ExternalOfServer.ToString));

       ServerCandidates:=CandidateOf(ExternalOfServer);
       ClientCandidates:=CandidateOf(ClientAddress);

       // The client is told that address, exactly as a signalling channel would carry it, and tries
       // it. The mapping exists, but the client has never been written to, so the filter drops it.
       Peer:=Client.ConnectViaCandidates(ServerCandidates);
       if not Check(assigned(Peer),'the client can start a connection attempt') then begin
        exit;
       end;
       Peer.IncRef;
       try
        ConnectedWithoutPermission:=PumpUntilConnected(1500,nil);
       finally
        Peer.Disconnect;
        Peer.DecRef;
       end;

       Info('without the server punching back: connected '+
            TRNLRawByteString(BoolToStr(ConnectedWithoutPermission,true))+
            ', filtered by the nat '+TRNLRawByteString(IntToStr(NAT.CountFilteredInbound)));

       Check(not ConnectedWithoutPermission,
             'knowing the external address is not enough on its own: a restricting nat drops a '+
             'sender its inside has never written to');

       CheckAtLeastInt64(NAT.CountFilteredInbound,1,
                         'and the nat really is what dropped it, rather than nothing having been sent');

       // Now the server knocks at the client as well, which is the punch. Same external address,
       // same everything, only the permission is new.
       Peer:=Client.ConnectViaCandidates(ServerCandidates);
       if not Check(assigned(Peer),'a second attempt can be started') then begin
        exit;
       end;
       Peer.IncRef;
       try
        ConnectedAfterPunching:=PumpUntilConnected(5000,ClientCandidates);
       finally
        Peer.DecRef;
       end;

       Info('with the server punching back: connected '+
            TRNLRawByteString(BoolToStr(ConnectedAfterPunching,true))+
            ', delivered through the nat '+TRNLRawByteString(IntToStr(NAT.CountDeliveredInbound)));

       Check(ConnectedAfterPunching,
             'once the server has written towards the client the very same attempt gets through, '+
             'which is the whole of hole punching');

      finally
       FreeAndNil(Client);
      end;

     finally
      FreeAndNil(Server);
     end;

     finally
      NAT.SocketDestroy(StrangerSocket);
     end;

    finally
     FreeAndNil(NAT);
    end;

   finally
    FreeAndNil(VirtualNetwork);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

procedure TestCandidatePriorityOrderAndSerialisation;
var Candidates,Restored:TRNLCandidates;
    Bytes:TBytes;
    Index:TRNLSizeInt;
    HostPriority,ReflexivePriority,RelayedPriority:TRNLUInt32;
    BaseA,BaseB,ServerA,ServerB:TRNLHostAddress;
    Truncated,Overlong,Tampered:TBytes;
begin

 TestBegin('candidate priority, order and serialisation');
 try

  // The type has to dominate the priority, otherwise a local preference could push a relayed
  // candidate ahead of a host one and every path would be tried in the wrong order
  HostPriority:=TRNLCandidateUtils.Priority(RNL_CANDIDATE_KIND_HOST,0);
  ReflexivePriority:=TRNLCandidateUtils.Priority(RNL_CANDIDATE_KIND_SERVER_REFLEXIVE,65535);
  RelayedPriority:=TRNLCandidateUtils.Priority(RNL_CANDIDATE_KIND_RELAYED,65535);

  Check(HostPriority>ReflexivePriority,
        'a host candidate outranks a server reflexive one even at the lowest local preference');

  Check(ReflexivePriority>RelayedPriority,
        'and a server reflexive one outranks a relayed one');

  Check(TRNLCandidateUtils.Priority(RNL_CANDIDATE_KIND_HOST,1)>
        TRNLCandidateUtils.Priority(RNL_CANDIDATE_KIND_HOST,0),
        'within one type the local preference is what orders them');

  // The foundation groups candidates which share a fate, so it has to depend on all three of kind,
  // base and server, and on nothing else
  FillChar(BaseA,SizeOf(TRNLHostAddress),#0);
  FillChar(BaseB,SizeOf(TRNLHostAddress),#0);
  FillChar(ServerA,SizeOf(TRNLHostAddress),#0);
  FillChar(ServerB,SizeOf(TRNLHostAddress),#0);
  BaseA.Addr[15]:=1;
  BaseB.Addr[15]:=2;
  ServerA.Addr[15]:=10;
  ServerB.Addr[15]:=11;

  CheckEqualsInt64(TRNLCandidateUtils.Foundation(RNL_CANDIDATE_KIND_HOST,BaseA,ServerA),
                   TRNLCandidateUtils.Foundation(RNL_CANDIDATE_KIND_HOST,BaseA,ServerA),
                   'the same kind, base and server always give the same foundation');

  Check(TRNLCandidateUtils.Foundation(RNL_CANDIDATE_KIND_HOST,BaseA,ServerA)<>
        TRNLCandidateUtils.Foundation(RNL_CANDIDATE_KIND_HOST,BaseB,ServerA),
        'a different base gives a different one');

  Check(TRNLCandidateUtils.Foundation(RNL_CANDIDATE_KIND_HOST,BaseA,ServerA)<>
        TRNLCandidateUtils.Foundation(RNL_CANDIDATE_KIND_HOST,BaseA,ServerB),
        'and so does a different server');

  Check(TRNLCandidateUtils.Foundation(RNL_CANDIDATE_KIND_HOST,BaseA,ServerA)<>
        TRNLCandidateUtils.Foundation(RNL_CANDIDATE_KIND_SERVER_REFLEXIVE,BaseA,ServerA),
        'and so does a different kind');

  // Deliberately built in the wrong order, so that sorting has something to do
  SetLength(Candidates,3);
  FillChar(Candidates[0],SizeOf(TRNLCandidate)*3,#0);
  Candidates[0].Kind:=RNL_CANDIDATE_KIND_RELAYED;
  Candidates[0].SocketIndex:=2;
  Candidates[0].Address.Port:=3000;
  Candidates[0].Priority:=RelayedPriority;
  Candidates[0].Foundation:=1;
  Candidates[1].Kind:=RNL_CANDIDATE_KIND_HOST;
  Candidates[1].SocketIndex:=0;
  Candidates[1].Address.Port:=3001;
  Candidates[1].Priority:=HostPriority;
  Candidates[1].Foundation:=2;
  Candidates[2].Kind:=RNL_CANDIDATE_KIND_SERVER_REFLEXIVE;
  Candidates[2].SocketIndex:=1;
  Candidates[2].Address.Port:=3002;
  Candidates[2].Priority:=ReflexivePriority;
  Candidates[2].Foundation:=3;

  TRNLCandidateUtils.SortByPriority(Candidates);

  Check((Candidates[0].Kind=RNL_CANDIDATE_KIND_HOST) and
        (Candidates[1].Kind=RNL_CANDIDATE_KIND_SERVER_REFLEXIVE) and
        (Candidates[2].Kind=RNL_CANDIDATE_KIND_RELAYED),
        'sorting puts the highest priority first, which is the order they are meant to be tried in');

  // Round trip
  Bytes:=TRNLCandidateUtils.Serialize(Candidates);

  if not Check(TRNLCandidateUtils.Deserialize(Bytes,Restored),
               'a serialised candidate list can be read back') then begin
   exit;
  end;

  if not CheckEqualsInt64(length(Restored),length(Candidates),
                          'with the same number of entries') then begin
   exit;
  end;

  for Index:=0 to length(Candidates)-1 do begin
   Check((Restored[Index].Kind=Candidates[Index].Kind) and
         (Restored[Index].SocketIndex=Candidates[Index].SocketIndex) and
         (Restored[Index].Priority=Candidates[Index].Priority) and
         (Restored[Index].Foundation=Candidates[Index].Foundation) and
         (Restored[Index].Address.Port=Candidates[Index].Address.Port) and
         Restored[Index].Address.Host.Equals(Candidates[Index].Address.Host),
         'and every field of entry '+TRNLRawByteString(IntToStr(Index))+' survives unchanged');
  end;

  // And the part that matters: this comes in over whatever channel the application chose, so it is
  // untrusted, and a length field must never be believed further than the buffer goes
  Truncated:=Copy(Bytes,0,length(Bytes)-1);
  Check(not TRNLCandidateUtils.Deserialize(Truncated,Restored),
        'a buffer one byte short of what its count announces is refused');

  SetLength(Overlong,length(Bytes)+1);
  Move(Bytes[0],Overlong[0],length(Bytes));
  Overlong[length(Bytes)]:=0;
  Check(not TRNLCandidateUtils.Deserialize(Overlong,Restored),
        'and so is one byte too many, since then it is not the message it claims to be');

  SetLength(Tampered,length(Bytes));
  Move(Bytes[0],Tampered[0],length(Bytes));
  Tampered[0]:=Tampered[0] xor $ff;
  Check(not TRNLCandidateUtils.Deserialize(Tampered,Restored),
        'a wrong signature is refused rather than read as candidates');

  SetLength(Tampered,length(Bytes));
  Move(Bytes[0],Tampered[0],length(Bytes));
  Tampered[4]:=99;
  Check(not TRNLCandidateUtils.Deserialize(Tampered,Restored),
        'and so is a version nobody knows');

  SetLength(Tampered,length(Bytes));
  Move(Bytes[0],Tampered[0],length(Bytes));
  // The kind field of the first entry, straight after the header and the address
  Tampered[8+SizeOf(TRNLAddress)]:=99;
  Check(not TRNLCandidateUtils.Deserialize(Tampered,Restored),
        'a candidate kind nobody defined is refused, since the priority arithmetic would otherwise '+
        'run on a value with no meaning');

  Check(not TRNLCandidateUtils.Deserialize(nil,Restored),
        'and an empty buffer is not a candidate list either');

 finally
  TestEnd;
 end;

end;

procedure TestNATNetworkSimulatesTheFourNATKinds;
const EXTERNAL_HOST='198.51.100.1';
      INSIDE_HOST='10.0.0.2';
      PEER_A_HOST='203.0.113.10';
      PEER_B_HOST='203.0.113.11';
      PEER_C_HOST='203.0.113.12';
      INSIDE_PORT=18420;
      PEER_A_PORT=18421;
      PEER_B_PORT=18422;
      PEER_C_PORT=18423;
      PEER_A_OTHER_PORT=18424;
      PAYLOAD='nat';
type TExpectation=record
      Name:TRNLRawByteString;
      Kind:TRNLTestNATKind;
      // Whether an inside socket keeps the same external port when it sends somewhere else
      SameExternalPort:boolean;
      // Whether a peer which was never written to gets in through an existing mapping
      StrangerGetsIn:boolean;
      // Whether the same host which was written to gets in from a different port
      OtherPortOfKnownHostGetsIn:boolean;
     end;
const EXPECTATIONS:array[0..3] of TExpectation=
       ((Name:'full cone';          Kind:RNL_TEST_NAT_FULL_CONE;          SameExternalPort:true;  StrangerGetsIn:true;  OtherPortOfKnownHostGetsIn:true),
        (Name:'address restricted'; Kind:RNL_TEST_NAT_ADDRESS_RESTRICTED; SameExternalPort:true;  StrangerGetsIn:false; OtherPortOfKnownHostGetsIn:true),
        (Name:'port restricted';    Kind:RNL_TEST_NAT_PORT_RESTRICTED;    SameExternalPort:true;  StrangerGetsIn:false; OtherPortOfKnownHostGetsIn:false),
        (Name:'symmetric';          Kind:RNL_TEST_NAT_SYMMETRIC;          SameExternalPort:false; StrangerGetsIn:false; OtherPortOfKnownHostGetsIn:false));
var Instance:TRNLInstance;
    VirtualNetwork:TRNLVirtualNetwork;
    NAT:TRNLTestNATNetwork;
    ExternalHost,InsideHost:TRNLHostAddress;
    Inside,PeerA,PeerB,PeerC,PeerAOther:TRNLAddress;
    ExternalForA,ExternalForB,SeenSource,Target,ExpiredProbe:TRNLAddress;
    StartTime:TRNLTime;
    InsideSocket,SocketA,SocketB,SocketC,SocketAOther:TRNLSocket;
    Buffer:array[0..63] of TRNLUInt8;
    Index:TRNLSizeInt;
    Watchdog:TRNLTestWatchdog;

 function AddressOf(const aHost:TRNLRawByteString;const aPort:TRNLUInt16):TRNLAddress;
 begin
  FillChar(result,SizeOf(TRNLAddress),#0);
  VirtualNetwork.AddressSetHost(result,aHost);
  result.Port:=aPort;
 end;

 function BoundSocket(const aAddress:TRNLAddress):TRNLSocket;
 begin
  result:=NAT.SocketCreate(RNL_SOCKET_TYPE_DATAGRAM,RNL_IPV4);
  NAT.SocketBind(result,@aAddress,RNL_IPV4);
 end;

 // Sends the payload and reports whether it turned up at the other end
 function Deliver(const aFromSocket:TRNLSocket;const aTo:TRNLAddress;
                  const aToSocket:TRNLSocket;out aSeenSource:TRNLAddress):boolean;
 begin
  FillChar(aSeenSource,SizeOf(TRNLAddress),#0);
  result:=false;
  if NAT.Send(aFromSocket,@aTo,PAYLOAD[1],System.Length(PAYLOAD),RNL_IPV4)<>System.Length(PAYLOAD) then begin
   exit;
  end;
  result:=NAT.Receive(aToSocket,@aSeenSource,Buffer,SizeOf(Buffer),RNL_IPV4)=System.Length(PAYLOAD);
 end;

begin

 TestBegin('the nat network simulates the four nat kinds');
 Watchdog:=TRNLTestWatchdog.Create('nat simulator',120000);
 try

  for Index:=Low(EXPECTATIONS) to High(EXPECTATIONS) do begin

   Instance:=TRNLInstance.Create;
   try
    VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
    try

     // Four distinct outside hosts, because with everything on one host the difference between an
     // address restricted and a port restricted NAT would not be observable at all
     Inside:=AddressOf(INSIDE_HOST,INSIDE_PORT);
     PeerA:=AddressOf(PEER_A_HOST,PEER_A_PORT);
     PeerB:=AddressOf(PEER_B_HOST,PEER_B_PORT);
     PeerC:=AddressOf(PEER_C_HOST,PEER_C_PORT);
     PeerAOther:=AddressOf(PEER_A_HOST,PEER_A_OTHER_PORT);
     ExternalHost:=AddressOf(EXTERNAL_HOST,0).Host;
     InsideHost:=Inside.Host;

     NAT:=TRNLTestNATNetwork.Create(Instance,VirtualNetwork,EXPECTATIONS[Index].Kind,
                                    ExternalHost,InsideHost);
     try

      NAT.AddInside(Inside);

      InsideSocket:=BoundSocket(Inside);
      SocketA:=BoundSocket(PeerA);
      SocketB:=BoundSocket(PeerB);
      SocketC:=BoundSocket(PeerC);
      SocketAOther:=BoundSocket(PeerAOther);
      try

       // Nothing may get in while no mapping exists, not even through a full cone NAT: a mapping is
       // what an inside socket is reachable through, and none has been opened yet
       Target:=AddressOf(EXTERNAL_HOST,40000);
       Check(not Deliver(SocketA,Target,InsideSocket,SeenSource),
             EXPECTATIONS[Index].Name+': without a mapping nothing reaches the inside');

       // Inside to A, which opens a mapping and lets A answer
       if not Check(Deliver(InsideSocket,PeerA,SocketA,SeenSource),
                    EXPECTATIONS[Index].Name+': an inside socket can always send out') then begin
        exit;
       end;

       Check(SeenSource.Host.Equals(ExternalHost) and (SeenSource.Port<>INSIDE_PORT),
             EXPECTATIONS[Index].Name+': what the outside sees is the external address of the nat, '+
             'not the inside one');

       if not Check(NAT.ExternalAddressOf(Inside,PeerA,ExternalForA),
                    EXPECTATIONS[Index].Name+': a mapping exists once something has gone out') then begin
        exit;
       end;

       // The same inside socket to a second peer, which is where the mapping behaviour parts ways
       Deliver(InsideSocket,PeerB,SocketB,SeenSource);
       Check(NAT.ExternalAddressOf(Inside,PeerB,ExternalForB),
             EXPECTATIONS[Index].Name+': and one for the second peer as well');

       Check((ExternalForA.Port=ExternalForB.Port)=EXPECTATIONS[Index].SameExternalPort,
             EXPECTATIONS[Index].Name+': the external port for a second peer has to '+
             EitherText(EXPECTATIONS[Index].SameExternalPort,'stay the same','differ')+
             ', which is what decides whether an address learned from a third party is any use');

       // The filter. First a peer nobody ever wrote to.
       Check(Deliver(SocketC,ExternalForA,InsideSocket,SeenSource)=EXPECTATIONS[Index].StrangerGetsIn,
             EXPECTATIONS[Index].Name+': a peer which was never written to has to '+
             EitherText(EXPECTATIONS[Index].StrangerGetsIn,'get in','be filtered out'));

       // Then the host which was written to, but from another port of it
       Check(Deliver(SocketAOther,ExternalForA,InsideSocket,SeenSource)=EXPECTATIONS[Index].OtherPortOfKnownHostGetsIn,
             EXPECTATIONS[Index].Name+': the known host from another port has to '+
             EitherText(EXPECTATIONS[Index].OtherPortOfKnownHostGetsIn,'get in','be filtered out')+
             ', which is the whole difference between address and port restricted');

       // And the endpoint which really was written to, which every kind has to let back in
       Check(Deliver(SocketA,ExternalForA,InsideSocket,SeenSource),
             EXPECTATIONS[Index].Name+': the endpoint which was written to always gets back in');

       // Once the mapping has expired, the way back is gone again. Waited for rather than slept
       // through: the clock underneath has a granularity of its own, and on Windows that can be a
       // whole timer tick, so a fixed sleep of a few milliseconds need not move it at all. It did
       // not, which is how this test failed under wine while passing on Linux.
       NAT.MappingTimeoutMilliseconds:=1;
       StartTime:=Instance.Time;
       repeat
        Sleep(5);
       until (not NAT.ExternalAddressOf(Inside,PeerA,ExpiredProbe)) or
             (TRNLTime.RelativeDifference(Instance.Time,StartTime)>=2000);

       if not Check(not NAT.ExternalAddressOf(Inside,PeerA,ExpiredProbe),
                    EXPECTATIONS[Index].Name+': the mapping is gone once its timeout has passed') then begin
        exit;
       end;
       Check(not Deliver(SocketA,ExternalForA,InsideSocket,SeenSource),
             EXPECTATIONS[Index].Name+': an expired mapping closes the way back in, which is what '+
             'makes a rebinding happen at all');
       CheckAtLeastInt64(NAT.CountExpiredMappings,1,
                         EXPECTATIONS[Index].Name+': and the expiry really was the reason');
       NAT.MappingTimeoutMilliseconds:=0;

      finally
       NAT.SocketDestroy(InsideSocket);
       NAT.SocketDestroy(SocketA);
       NAT.SocketDestroy(SocketB);
       NAT.SocketDestroy(SocketC);
       NAT.SocketDestroy(SocketAOther);
      end;

      Info(EXPECTATIONS[Index].Name+': translated out '+
           TRNLRawByteString(IntToStr(NAT.CountTranslatedOutgoing))+
           ', delivered in '+TRNLRawByteString(IntToStr(NAT.CountDeliveredInbound))+
           ', filtered out '+TRNLRawByteString(IntToStr(NAT.CountFilteredInbound))+
           ', expired '+TRNLRawByteString(IntToStr(NAT.CountExpiredMappings)));

     finally
      FreeAndNil(NAT);
     end;

    finally
     FreeAndNil(VirtualNetwork);
    end;
   finally
    FreeAndNil(Instance);
   end;

  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;


procedure TestSTUNClientReadsItsMappedAddressAndRejectsMalformedAnswers;
const FIRST_PORT=18400;
      REPORTED_HOST='203.0.113.7';
      REPORTED_PORT=51234;
type TExpectation=record
      Name:TRNLRawByteString;
      Behaviour:TRNLTestSTUNServerBehaviour;
      Succeeds:boolean;
     end;
const EXPECTATIONS:array[0..8] of TExpectation=
       ((Name:'a correct answer';                 Behaviour:RNL_TEST_STUN_SERVER_CORRECT;                          Succeeds:true),
        (Name:'only a plain mapped address';      Behaviour:RNL_TEST_STUN_SERVER_PLAIN_MAPPED_ADDRESS_ONLY;        Succeeds:true),
        (Name:'an unknown attribute in front';    Behaviour:RNL_TEST_STUN_SERVER_UNKNOWN_ATTRIBUTE_FIRST;          Succeeds:true),
        (Name:'no answer at all';                 Behaviour:RNL_TEST_STUN_SERVER_SILENT;                           Succeeds:false),
        (Name:'a foreign transaction id';         Behaviour:RNL_TEST_STUN_SERVER_WRONG_TRANSACTION_ID;             Succeeds:false),
        (Name:'a wrong fingerprint';              Behaviour:RNL_TEST_STUN_SERVER_WRONG_FINGERPRINT;                Succeeds:false),
        (Name:'a truncated attribute';            Behaviour:RNL_TEST_STUN_SERVER_TRUNCATED_ATTRIBUTE;              Succeeds:false),
        (Name:'a length beyond the datagram';     Behaviour:RNL_TEST_STUN_SERVER_ATTRIBUTE_LENGTH_BEYOND_DATAGRAM; Succeeds:false),
        (Name:'an unaligned message length';      Behaviour:RNL_TEST_STUN_SERVER_UNALIGNED_MESSAGE_LENGTH;         Succeeds:false));
var Instance:TRNLInstance;
    Network:TRNLVirtualNetwork;
    Server:TRNLTestSTUNServer;
    ServerAddress,ReportedAddress:TRNLAddress;
    STUNResult:TRNLSTUNResult;
    Index:TRNLSizeInt;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('the stun client reads its mapped address and rejects malformed answers');
 Watchdog:=TRNLTestWatchdog.Create('stun client',120000);
 try

  for Index:=Low(EXPECTATIONS) to High(EXPECTATIONS) do begin

   Instance:=TRNLInstance.Create;
   try
    Network:=TRNLVirtualNetwork.Create(Instance);
    try

     FillChar(ReportedAddress,SizeOf(TRNLAddress),#0);
     Network.AddressSetHost(ReportedAddress,REPORTED_HOST);
     ReportedAddress.Port:=REPORTED_PORT;

     Server:=TRNLTestSTUNServer.Create(Instance,
                                       Network,
                                       FIRST_PORT+Index,
                                       EXPECTATIONS[Index].Behaviour,
                                       ReportedAddress);
     try

      FillChar(ServerAddress,SizeOf(TRNLAddress),#0);
      Network.AddressSetHost(ServerAddress,'127.0.0.1');
      ServerAddress.Port:=FIRST_PORT+Index;

      // A short deadline and a single attempt, because a rejected answer means waiting the deadline
      // out; there is nothing else to wait for
      STUNResult:=TRNLSTUNClient.Query(Instance,Network,ServerAddress,RNL_IPV4,300,1);

      Info(EXPECTATIONS[Index].Name+': success '+
           TRNLRawByteString(BoolToStr(STUNResult.Success,true))+
           ', requests seen by the server '+TRNLRawByteString(IntToStr(Server.CountRequests)));

      Check(STUNResult.Success=EXPECTATIONS[Index].Succeeds,
            EXPECTATIONS[Index].Name+' has to '+
            EitherText(EXPECTATIONS[Index].Succeeds,'be accepted','be rejected'));

      // The request has to have arrived in every single case, otherwise a rejection would only be
      // proving that nothing ever happened
      CheckAtLeastInt64(Server.CountRequests,1,
                        'and the request has to have reached the server at all');

      if EXPECTATIONS[Index].Succeeds then begin
       Check(STUNResult.MappedAddress.Host.Equals(ReportedAddress.Host) and
             (STUNResult.MappedAddress.Port=REPORTED_PORT),
             'and the address it reports has to be the one the server put into the answer, '+
             'obfuscated or plain');
      end;

     finally
      FreeAndNil(Server);
     end;

    finally
     FreeAndNil(Network);
    end;
   finally
    FreeAndNil(Instance);
   end;

  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

procedure TestHostBringsUpTheExpectedSockets;
const FIRST_PORT=18380;
type TExpectation=record
      Name:TRNLRawByteString;
      Mode:TRNLHostAddressFamilyWorkMode;
      CountSockets:TRNLSizeInt;
     end;
const EXPECTATIONS:array[0..4] of TExpectation=
       ((Name:'ipv4 only';    Mode:RNL_HOST_ADDRESS_FAMILY_WORK_MODE_IPV4_ONLY;     CountSockets:1),
        (Name:'ipv6 only';    Mode:RNL_HOST_ADDRESS_FAMILY_WORK_MODE_IPV6_ONLY;     CountSockets:1),
        (Name:'ipv4 and ipv6';Mode:RNL_HOST_ADDRESS_FAMILY_WORK_MODE_IPV4_AND_IPV6; CountSockets:2),
        (Name:'ipv4 on ipv6'; Mode:RNL_HOST_ADDRESS_FAMILY_WORK_MODE_IPV4_ON_IPV6;  CountSockets:1),
        (Name:'automatic';    Mode:RNL_HOST_ADDRESS_FAMILY_WORK_MODE_AUTOMATIC;     CountSockets:1));
var Instance:TRNLInstance;
    Network:TRNLVirtualNetwork;
    Host:TRNLHost;
    Index:TRNLSizeInt;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('a host brings up the expected sockets for every address family work mode');
 Watchdog:=TRNLTestWatchdog.Create('socket bring up',60000);
 try

  // The sockets of a host are no longer one fixed slot per address family but a list which is built
  // up as they come. That list has to come out of every work mode with exactly what the fixed slots
  // used to hold, which is what this pins down: a dual stack mode ends up with one socket serving
  // both families, and only the mode which really wants two separate ones gets two.
  for Index:=Low(EXPECTATIONS) to High(EXPECTATIONS) do begin

   Instance:=TRNLInstance.Create;
   try
    Network:=TRNLVirtualNetwork.Create(Instance);
    try
     Host:=TRNLHost.Create(Instance,Network);
     try
      Host.Address.Host:=RNL_HOST_ANY;
      Host.Address.Port:=FIRST_PORT+Index;
      Host.Start(EXPECTATIONS[Index].Mode);

      Info(EXPECTATIONS[Index].Name+': '+TRNLRawByteString(IntToStr(Host.CountSockets))+' socket(s)');

      CheckEqualsInt64(Host.CountSockets,EXPECTATIONS[Index].CountSockets,
                       'work mode '+EXPECTATIONS[Index].Name+' has to end up with the expected '+
                       'number of sockets');

     finally
      FreeAndNil(Host);
     end;
    finally
     FreeAndNil(Network);
    end;
   finally
    FreeAndNil(Instance);
   end;

  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

procedure TestCryptographySelfTestsPass;
var Succeeded:boolean;
begin

 TestBegin('the cryptographic self tests pass');
 try

  // Writes its whole report to standard output on the way, which is a lot of lines. It runs first
  // for that reason, so the noise stays in one place, and it is worth having: until this call
  // existed nothing in RNL ever ran these vectors, so the primitives everything else here relies
  // on were entirely unverified.
  Succeeded:=TRNLInstance.SelfTestCryptography;

  Check(Succeeded,'every cryptographic self test and checksum check vector in the library has to '+
                  'come out right');

 finally
  TestEnd;
 end;

end;

procedure TestRemoteLongTermPublicKeyIsVisibleAndPinnable;
const SERVER_PORT=18360;
      CLIENT_PORT=18361;
var Instance:TRNLInstance;
    Network:TRNLVirtualNetwork;
    Server,Client:TRNLHost;
    ServerAddress:TRNLAddress;
    Event:TRNLHostEvent;
    Peer:TRNLPeer;
    ExpectedKey,WrongKey:TRNLKey;
    StartTime:TRNLTime;
    Approved,Denied,SawIdentity:boolean;
    ObservedKey:TRNLKey;
    Watchdog:TRNLTestWatchdog;

 // Connects once with the given expectation and reports what came of it
 procedure RunScenario(const aExpectedKey:PRNLKey;out aApproved,aDenied,aSawIdentity:boolean;
                       out aObservedKey:TRNLKey);
 begin
  aApproved:=false;
  aDenied:=false;
  aSawIdentity:=false;
  FillChar(aObservedKey,SizeOf(TRNLKey),#0);
  Peer:=Client.Connect(ServerAddress,1,0,nil,nil,aExpectedKey);
  if not assigned(Peer) then begin
   exit;
  end;
  Peer.IncRef;
  try
   StartTime:=Instance.Time;
   Event.Initialize;
   try
    repeat
     while Server.Service(Event,0)=RNL_HOST_SERVICE_STATUS_EVENT do begin
      Event.Free;
     end;
     Event.Free;
     while Client.Service(Event,0)=RNL_HOST_SERVICE_STATUS_EVENT do begin
      case Event.Type_ of
       RNL_HOST_EVENT_TYPE_PEER_APPROVAL:begin
        aApproved:=true;
        if assigned(Event.Peer) then begin
         aObservedKey:=Event.Peer.RemoteLongTermPublicKey;
         aSawIdentity:=true;
        end;
       end;
       RNL_HOST_EVENT_TYPE_PEER_DENIAL:begin
        aDenied:=true;
       end;
       else begin
       end;
      end;
      Event.Free;
     end;
     Event.Free;
     Sleep(1);
    until aApproved or aDenied or (TRNLTime.RelativeDifference(Instance.Time,StartTime)>=2500);
   finally
    Event.Free;
   end;
  finally
   Peer.Disconnect;
   Peer.DecRef;
  end;
 end;

begin

 TestBegin('the remote long term public key is visible and can be pinned');
 Watchdog:=TRNLTestWatchdog.Create('long term key pinning',120000);
 try

  Instance:=TRNLInstance.Create;
  try
   Network:=TRNLVirtualNetwork.Create(Instance);
   try
    Server:=TRNLHost.Create(Instance,Network);
    try
     Server.Address.Host:=RNL_HOST_ANY;
     Server.Address.Port:=SERVER_PORT;
     Server.Start(RNL_HOST_ADDRESS_FAMILY_WORK_MODE_IPV4_ONLY);

     Client:=TRNLHost.Create(Instance,Network);
     try
      Client.Address.Host:=RNL_HOST_ANY;
      Client.Address.Port:=CLIENT_PORT;
      Client.Start(RNL_HOST_ADDRESS_FAMILY_WORK_MODE_IPV4_ONLY);

      Network.AddressSetHost(ServerAddress,'127.0.0.1');
      ServerAddress.Port:=SERVER_PORT;

      // Every host generates a fresh key pair unless the application sets one, so the server's own
      // public key is what a client would have to be told out of band
      ExpectedKey:=Server.LongTermPublicKey;
      WrongKey:=ExpectedKey;
      WrongKey.ui8[0]:=WrongKey.ui8[0] xor $ff;

      // Without any expectation, which is how everything behaved before, and the identity has to be
      // observable all the same
      RunScenario(nil,Approved,Denied,SawIdentity,ObservedKey);

      Check(Approved,'a connection without any expectation still comes up');

      Check(SawIdentity,'and the peer of the approval event carries the identity of the counter side');

      Check(TRNLMemory.SecureIsEqual(ObservedKey,ExpectedKey,SizeOf(TRNLKey)),
            'which is the long term public key of the server, so an application can log it or '+
            'remember it without any further help');

      // Pinned to the right key
      RunScenario(@ExpectedKey,Approved,Denied,SawIdentity,ObservedKey);

      Check(Approved,'pinning to the key the server really holds changes nothing about the outcome');

      // Pinned to a key nobody holds
      RunScenario(@WrongKey,Approved,Denied,SawIdentity,ObservedKey);

      Info('rejected long term public keys: '+
           TRNLRawByteString(IntToStr(Client.TotalRejectedRemoteLongTermPublicKeys)));

      Check(not Approved,'pinning to a different key does not let the connection come up');

      CheckAtLeastInt64(Client.TotalRejectedRemoteLongTermPublicKeys,1,
                        'and the reason is the identity check, not a timeout somewhere else');

     finally
      FreeAndNil(Client);
     end;
    finally
     FreeAndNil(Server);
    end;
   finally
    FreeAndNil(Network);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

procedure TestTranscriptBindingDowngrade;
const FIRST_PORT=18340;
var PortOffset:TRNLSizeInt;
    Watchdog:TRNLTestWatchdog;

 procedure RunScenario(const aMode:TRNLProtocolTranscriptBindingMode;
                       out aConnected,aBound:boolean);
 var Instance:TRNLInstance;
     VirtualNetwork:TRNLVirtualNetwork;
     FaultInjector:TRNLNetworkFaultInjector;
     HostPair:TRNLTestHostPair;
     Probe:TRNLProtocolHandshakePacketConnectionRequest;
     OlderVersion:TRNLUInt64;
 begin
  aConnected:=false;
  aBound:=false;
  OlderVersion:=TRNLEndianness.HostToLittleEndian64(RNL_PROTOCOL_VERSION);
  Instance:=TRNLInstance.Create;
  try
   VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
   try
    FaultInjector:=TRNLNetworkFaultInjector.Create(Instance,VirtualNetwork);
    try
     // Exactly the downgrade: the version travels in clear in the very first datagram, so anything
     // on the path can put it back to the older one
     FaultInjector.RewriteOutgoingHandshakeField(HandshakePacketType(RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_REQUEST),
                                                 HandshakeFieldOffset(Probe,Probe.Header.ProtocolVersion),
                                                 OlderVersion,
                                                 SizeOf(OlderVersion));
     HostPair:=TRNLTestHostPair.Create(Instance,
                                       FaultInjector,
                                       FIRST_PORT+(PortOffset*2),
                                       FIRST_PORT+(PortOffset*2)+1);
     try
      HostPair.Client.TranscriptBindingMode:=aMode;
      HostPair.Server.TranscriptBindingMode:=aMode;
      if aMode=RNL_PROTOCOL_TRANSCRIPT_BINDING_ALLOWED then begin
       aConnected:=HostPair.Connect(5000);
      end else begin
       aConnected:=HostPair.Connect(2000);
      end;
      if aConnected and assigned(HostPair.ClientPeer) then begin
       aBound:=HostPair.ClientPeer.TranscriptBinding;
      end;
     finally
      FreeAndNil(HostPair);
     end;
    finally
     FreeAndNil(FaultInjector);
    end;
   finally
    FreeAndNil(VirtualNetwork);
   end;
  finally
   FreeAndNil(Instance);
  end;
  inc(PortOffset);
 end;

var Connected,Bound:boolean;
begin

 TestBegin('a protocol version downgrade is only possible where it is documented to be');
 Watchdog:=TRNLTestWatchdog.Create('transcript binding downgrade',120000);
 try

  PortOffset:=0;

  RunScenario(RNL_PROTOCOL_TRANSCRIPT_BINDING_ALLOWED,Connected,Bound);

  Info('version rewritten downwards, both allowed: connected '+
       TRNLRawByteString(BoolToStr(Connected,true))+
       ', bound '+TRNLRawByteString(BoolToStr(Bound,true)));

  // Held down on purpose. This is not the behaviour anybody wants, it is the price of speaking two
  // versions at once, and it cannot be fixed from inside that mode: the fallback has no transcript
  // to bind the version field to. The test exists so that it stays a known property rather than
  // turning into a surprise.
  Check(Connected,'in allowed the connection still comes up, since falling back is the whole point '+
                  'of that mode');

  Check(not Bound,'and it comes up unbound, which is the documented downgrade: whoever can rewrite '+
                  'the version decides that the cleartext fields go unprotected');

  RunScenario(RNL_PROTOCOL_TRANSCRIPT_BINDING_REQUIRED,Connected,Bound);

  Info('version rewritten downwards, both required: connected '+
       TRNLRawByteString(BoolToStr(Connected,true)));

  Check(not Connected,'in required the same rewrite achieves nothing but preventing the connection, '+
                      'and preventing it was possible all along');

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

function TranscriptBindingModeName(const aMode:TRNLProtocolTranscriptBindingMode):TRNLRawByteString;
begin
 case aMode of
  RNL_PROTOCOL_TRANSCRIPT_BINDING_OFF:begin
   result:='off';
  end;
  RNL_PROTOCOL_TRANSCRIPT_BINDING_ALLOWED:begin
   result:='allowed';
  end;
  else begin
   result:='required';
  end;
 end;
end;

procedure TestTranscriptBindingInteroperabilityMatrix;
const MODES:array[0..2] of TRNLProtocolTranscriptBindingMode=
       (RNL_PROTOCOL_TRANSCRIPT_BINDING_OFF,
        RNL_PROTOCOL_TRANSCRIPT_BINDING_ALLOWED,
        RNL_PROTOCOL_TRANSCRIPT_BINDING_REQUIRED);
      FIRST_PORT=18300;
var Instance:TRNLInstance;
    Network:TRNLVirtualNetwork;
    HostPair:TRNLTestHostPair;
    ClientIndex,ServerIndex,PortOffset:TRNLSizeInt;
    Connected,ExpectConnected,Bound,ExpectBound:boolean;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('the transcript binding modes interoperate as documented');
 Watchdog:=TRNLTestWatchdog.Create('transcript binding matrix',180000);
 try

  PortOffset:=0;

  for ClientIndex:=Low(MODES) to High(MODES) do begin
   for ServerIndex:=Low(MODES) to High(MODES) do begin

    // Only a pairing where one side insists on a version the other refuses can fail. REQUIRED
    // turns the older version away, and OFF does not know the newer one, so those two never meet.
    ExpectConnected:=not (((MODES[ClientIndex]=RNL_PROTOCOL_TRANSCRIPT_BINDING_OFF) and
                           (MODES[ServerIndex]=RNL_PROTOCOL_TRANSCRIPT_BINDING_REQUIRED)) or
                          ((MODES[ClientIndex]=RNL_PROTOCOL_TRANSCRIPT_BINDING_REQUIRED) and
                           (MODES[ServerIndex]=RNL_PROTOCOL_TRANSCRIPT_BINDING_OFF)));

    // Bound whenever both sides can speak the newer version, which is exactly when neither of
    // them is OFF
    ExpectBound:=ExpectConnected and
                 (MODES[ClientIndex]<>RNL_PROTOCOL_TRANSCRIPT_BINDING_OFF) and
                 (MODES[ServerIndex]<>RNL_PROTOCOL_TRANSCRIPT_BINDING_OFF);

    Connected:=false;
    Bound:=false;

    Instance:=TRNLInstance.Create;
    try
     Network:=TRNLVirtualNetwork.Create(Instance);
     try
      HostPair:=TRNLTestHostPair.Create(Instance,
                                        Network,
                                        FIRST_PORT+(PortOffset*2),
                                        FIRST_PORT+(PortOffset*2)+1);
      try

       HostPair.Client.TranscriptBindingMode:=MODES[ClientIndex];
       HostPair.Server.TranscriptBindingMode:=MODES[ServerIndex];

       // A pairing which cannot work shows that by staying silent, so it only gets a short
       // deadline; there is nothing to wait for. The successful ones get room for the 500 ms
       // fallback which ALLOWED against OFF needs.
       if ExpectConnected then begin
        Connected:=HostPair.Connect(5000);
       end else begin
        Connected:=HostPair.Connect(1500);
       end;

       if Connected and assigned(HostPair.ClientPeer) then begin
        Bound:=HostPair.ClientPeer.TranscriptBinding;
       end;

      finally
       FreeAndNil(HostPair);
      end;
     finally
      FreeAndNil(Network);
     end;
    finally
     FreeAndNil(Instance);
    end;

    Info('client '+TranscriptBindingModeName(MODES[ClientIndex])+
         ' to server '+TranscriptBindingModeName(MODES[ServerIndex])+
         ': connected '+TRNLRawByteString(BoolToStr(Connected,true))+
         ', bound '+TRNLRawByteString(BoolToStr(Bound,true)));

    Check(Connected=ExpectConnected,
          'client '+TranscriptBindingModeName(MODES[ClientIndex])+
          ' to server '+TranscriptBindingModeName(MODES[ServerIndex])+
          ' has to '+EitherText(ExpectConnected,'connect','be refused'));

    Check(Bound=ExpectBound,
          'and it has to end up '+EitherText(ExpectBound,'bound','unbound'));

    inc(PortOffset);

   end;
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

procedure TestHandshakeFieldRewritingKeepsThePacketChecksumValid;
var Instance:TRNLInstance;
    VirtualNetwork:TRNLVirtualNetwork;
    FaultInjector:TRNLNetworkFaultInjector;
    HostPair:TRNLTestHostPair;
    Probe:TRNLProtocolHandshakePacketConnectionRequest;
    Filler:array[0..15] of TRNLUInt8;
    Index:TRNLSizeInt;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('handshake field rewriting keeps the packet checksum valid');
 Watchdog:=TRNLTestWatchdog.Create('handshake field rewriting',120000);
 try

  Instance:=TRNLInstance.Create;
  try
   VirtualNetwork:=TRNLVirtualNetwork.Create(Instance);
   try
    FaultInjector:=TRNLNetworkFaultInjector.Create(Instance,VirtualNetwork);
    try

     for Index:=Low(Filler) to High(Filler) do begin
      Filler[Index]:=TRNLUInt8($a5);
     end;

     // The connection token is the one field which can be changed without changing any meaning:
     // token checking is off by default, so nothing looks at it. What it does change is the bytes
     // of the datagram, and therefore its checksum. If the injector did not repair that, the
     // counter side would discard every single connection request and the handshake below could
     // not possibly succeed.
     FaultInjector.RewriteOutgoingHandshakeField(HandshakePacketType(RNL_PROTOCOL_HANDSHAKE_PACKET_TYPE_CONNECTION_REQUEST),
                                                 HandshakeFieldOffset(Probe,Probe.ConnectionToken),
                                                 Filler,
                                                 SizeOf(Filler));

     HostPair:=TRNLTestHostPair.Create(Instance,FaultInjector);
     try

      Check(HostPair.Connect,'the handshake must still complete while a field is being rewritten, '+
                             'which it can only do if the checksum was recomputed');

      Info('handshake packets rewritten: '+
           TRNLRawByteString(IntToStr(FaultInjector.CountRewrittenHandshakePackets)));

      CheckAtLeastInt64(FaultInjector.CountRewrittenHandshakePackets,1,
                        'and at least one packet has to have been rewritten at all, otherwise '+
                        'the assertion above holds for the wrong reason');

     finally
      FreeAndNil(HostPair);
     end;

    finally
     FreeAndNil(FaultInjector);
    end;
   finally
    FreeAndNil(VirtualNetwork);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

procedure TestBandwidthRateLimiterHonoursItsPeriodLength;
const MAXIMUM_PER_PERIOD=100000;
      PERIOD_LENGTH=1000;
      CHUNK=1000;
var RateLimiter:TRNLBandwidthRateLimiter;
    Index,CountAllowedInFirstPeriod,CountAllowedAfterPeriodEnd:TRNLSizeInt;
    Time:TRNLTime;
begin

 TestBegin('the bandwidth rate limiter honours its period length');
 try

  // The maximum per period and the length of a period must differ here. They are two entirely
  // different quantities, an amount and a duration, and equal values would hide any confusion
  // between the two, which is exactly what this test is about.
  RateLimiter.Setup(MAXIMUM_PER_PERIOD,PERIOD_LENGTH);

  // Any point in time will do, the limiter only ever looks at differences
  Time:=1000000;
  RateLimiter.Reset(Time);

  CountAllowedInFirstPeriod:=0;
  for Index:=1 to (MAXIMUM_PER_PERIOD div CHUNK)+1 do begin
   if RateLimiter.CanProceed(CHUNK,Time) then begin
    RateLimiter.AddAmount(CHUNK,Time);
    inc(CountAllowedInFirstPeriod);
   end;
  end;

  CheckEqualsInt64(CountAllowedInFirstPeriod,MAXIMUM_PER_PERIOD div CHUNK,
                   'the budget of a single period has to be exactly the configured maximum, so '+
                   'one attempt beyond it must be refused');

  // One period length plus a millisecond later the whole budget has to be available again. This
  // is the assertion that matters, because it is the only one which can tell a period measured
  // in milliseconds apart from a period whose length was taken from the amount instead.
  Time:=Time+(PERIOD_LENGTH+1);

  CountAllowedAfterPeriodEnd:=0;
  for Index:=1 to MAXIMUM_PER_PERIOD div CHUNK do begin
   if RateLimiter.CanProceed(CHUNK,Time) then begin
    RateLimiter.AddAmount(CHUNK,Time);
    inc(CountAllowedAfterPeriodEnd);
   end;
  end;

  Info('allowed in the first period: '+TRNLRawByteString(IntToStr(CountAllowedInFirstPeriod))+
       ', allowed '+TRNLRawByteString(IntToStr(PERIOD_LENGTH+1))+' ms later: '+
       TRNLRawByteString(IntToStr(CountAllowedAfterPeriodEnd)));

  CheckEqualsInt64(CountAllowedAfterPeriodEnd,MAXIMUM_PER_PERIOD div CHUNK,
                   'and once the period length has elapsed the full budget has to be available '+
                   'again, otherwise the period lasts as long as there are units in it and the '+
                   'effective rate becomes one unit per millisecond regardless of the limit');

 finally
  TestEnd;
 end;

end;

procedure TestBandwidthLimitedHostKeepsSendingAfterTheFirstPeriod;
const OUTGOING_BANDWIDTH_LIMIT_BITS=400000;      // 50000 bytes per second
      MESSAGE_SIZE=1000;
      COUNT_MESSAGES=600;
      FIRST_STRETCH_MILLISECONDS=1200;
      SECOND_STRETCH_MILLISECONDS=1500;
      MINIMUM_BYTES_AFTER_FIRST_STRETCH=20000;
var Instance:TRNLInstance;
    Network:TRNLVirtualNetwork;
    HostPair:TRNLTestHostPair;
    Index:TRNLSizeInt;
    BytesAfterFirstStretch,BytesAtEnd:TRNLUInt64;
    Watchdog:TRNLTestWatchdog;
begin

 TestBegin('a bandwidth limited host keeps sending after its first period');
 Watchdog:=TRNLTestWatchdog.Create('bandwidth limited sending',120000);
 try

  Instance:=TRNLInstance.Create;
  try
   Network:=TRNLVirtualNetwork.Create(Instance);
   try
    HostPair:=TRNLTestHostPair.Create(Instance,Network,18272,18273);
    try

     if not Check(HostPair.Connect,'the host pair has to connect') then begin
      exit;
     end;

     // Deliberately set after the handshake, so that the handshake itself is never subject to
     // the limit and only the payload transfer below is being measured
     HostPair.Client.OutgoingBandwidthLimit:=OUTGOING_BANDWIDTH_LIMIT_BITS;

     for Index:=1 to COUNT_MESSAGES do begin
      HostPair.ClientPeer.Channels[RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_ORDERED].SendMessageRawByteString(TestMessageText(Index,MESSAGE_SIZE));
     end;

     // Measured at the socket, on purpose, and not in delivered messages. A limit this low
     // makes the limiter drop the bulk of the datagrams, and on an ordered reliable channel the
     // next message can only be handed to the application once the earliest missing fragment has
     // been retransmitted. Delivered messages therefore say very little about whether the sender
     // is still sending at all, which is the only thing this test is about.
     if not Check(HostPair.Pump(FIRST_STRETCH_MILLISECONDS),
                  'no host service error while the first budget is being spent') then begin
      exit;
     end;
     BytesAfterFirstStretch:=HostPair.Server.TotalReceivedData;

     if not Check(HostPair.Pump(SECOND_STRETCH_MILLISECONDS),
                  'and none afterwards either') then begin
      exit;
     end;
     BytesAtEnd:=HostPair.Server.TotalReceivedData;

     Info('limit '+TRNLRawByteString(IntToStr(OUTGOING_BANDWIDTH_LIMIT_BITS))+' bit/s, bytes '+
          'arrived after '+TRNLRawByteString(IntToStr(FIRST_STRETCH_MILLISECONDS))+' ms: '+
          TRNLRawByteString(IntToStr(BytesAfterFirstStretch))+', after a further '+
          TRNLRawByteString(IntToStr(SECOND_STRETCH_MILLISECONDS))+' ms: '+
          TRNLRawByteString(IntToStr(BytesAtEnd)));

     CheckAtLeastInt64(BytesAfterFirstStretch,1,
                       'something has to arrive during the first budget at all, otherwise the '+
                       'measurement below says nothing');

     // The first budget is not the interesting part, a limiter with a far too long period spends
     // that one just as quickly. What matters is whether the budget ever comes back. With a
     // period whose length was taken from the amount instead of from the period length, sending
     // stops dead once the first budget is spent and this difference stays at exactly zero.
     CheckAtLeastInt64(TRNLInt64(BytesAtEnd-BytesAfterFirstStretch),MINIMUM_BYTES_AFTER_FIRST_STRETCH,
                       'and sending has to carry on across period boundaries instead of stopping '+
                       'once the first budget is spent');

    finally
     FreeAndNil(HostPair);
    end;
   finally
    FreeAndNil(Network);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

procedure TestConnectionRequestBudgetSurvivesAHashCollision;
const BURST=20;
      PERIOD=1000;
      SEARCH_LIMIT=1000000;
var Table:PRNLConnectionKnownCandidateHostAddressHashTable;
    AddressA,AddressB,Candidate:TRNLHostAddress;
    Slots:array of TRNLUInt32;
    Entry:PRNLConnectionKnownCandidateHostAddress;
    Index,Slot,CountAllowedForA,CountAllowedForAAfterTakeOver:TRNLSizeInt;
    Time:TRNLTime;
    Found:boolean;
begin

 TestBegin('a connection request budget survives a hash collision');
 try

  Time:=1000000;
  Found:=false;
  FillChar(AddressA,SizeOf(TRNLHostAddress),#0);
  FillChar(AddressB,SizeOf(TRNLHostAddress),#0);

  // The table has one entry per slot, so two host addresses which land on the same slot are what
  // the takeover path is about. Searching for such a pair at run time rather than hard coding one
  // keeps the test independent of the hash function, and the search is deterministic because the
  // hash is.
  SetLength(Slots,TRNLConnectionKnownCandidateHostAddressHashTable.HashSize);
  for Index:=0 to length(Slots)-1 do begin
   Slots[Index]:=0;
  end;

  for Index:=1 to SEARCH_LIMIT do begin
   Candidate:=TRNLHostAddress.CreateFromIPV4(TRNLUInt32(Index));
   Slot:=TRNLHashUtils.Hash32(Candidate,SizeOf(TRNLHostAddress)) and
         TRNLConnectionKnownCandidateHostAddressHashTable.HashMask;
   if Slots[Slot]<>0 then begin
    AddressA:=TRNLHostAddress.CreateFromIPV4(Slots[Slot]);
    AddressB:=Candidate;
    Found:=true;
    break;
   end;
   Slots[Slot]:=TRNLUInt32(Index);
  end;

  if not Check(Found,'two host addresses which share a slot have to be findable') then begin
   exit;
  end;

  GetMem(Table,SizeOf(TRNLConnectionKnownCandidateHostAddressHashTable));
  try
   Table^.Clear;

   // Spend the whole burst of the first address. The point in time never moves, so nothing decays
   // underneath the measurement.
   CountAllowedForA:=0;
   for Index:=1 to BURST+1 do begin
    Entry:=Table^.Find(AddressA,true);
    if assigned(Entry) and not Entry^.RateLimiter.RateLimit(Time,BURST,PERIOD) then begin
     inc(CountAllowedForA);
    end;
   end;

   CheckEqualsInt64(CountAllowedForA,BURST,
                    'an address may send exactly its burst before it is limited');

   // The colliding address takes the slot over, and then the first one takes it back
   Entry:=Table^.Find(AddressB,true);
   Check(assigned(Entry),'the colliding address gets the same slot');

   Entry:=Table^.Find(AddressA,true);
   if not Check(assigned(Entry),'and the first address can claim it back') then begin
    exit;
   end;

   CountAllowedForAAfterTakeOver:=0;
   for Index:=1 to BURST do begin
    Entry:=Table^.Find(AddressA,true);
    if assigned(Entry) and not Entry^.RateLimiter.RateLimit(Time,BURST,PERIOD) then begin
     inc(CountAllowedForAAfterTakeOver);
    end;
   end;

   Info('allowed before the takeover: '+TRNLRawByteString(IntToStr(CountAllowedForA))+
        ', allowed after it: '+TRNLRawByteString(IntToStr(CountAllowedForAAfterTakeOver)));

   // If the takeover starts the budget from scratch, then two addresses which collide clear each
   // other's budget on every request and the limit never triggers at all. Two cooperating
   // addresses would be enough for that, which would make it a complete bypass of the very
   // mechanism this table exists for.
   CheckEqualsInt64(CountAllowedForAAfterTakeOver,0,
                    'and a takeover by a colliding address must not hand the budget back');

  finally
   FreeMem(Table);
  end;

 finally
  TestEnd;
 end;

end;

procedure TestConnectionAttemptHistoryStaysInsideItsRingBuffer;
const SERVER_PORT=18274;
      CLIENT_PORT=18275;
      COUNT_ATTEMPTS=60;
      DURATION_MILLISECONDS=2500;
var Instance:TRNLInstance;
    Network:TRNLVirtualNetwork;
    Server,Client:TRNLHost;
    ServerAddress:TRNLAddress;
    Event:TRNLHostEvent;
    Peers:array of TRNLPeer;
    Index:TRNLSizeInt;
    StartTime:TRNLTime;
    Watchdog:TRNLTestWatchdog;
    Survived:boolean;
    FailureText:TRNLRawByteString;

 procedure PumpBoth;
 begin
  Event.Initialize;
  try
   while Server.Service(Event,0)=RNL_HOST_SERVICE_STATUS_EVENT do begin
    Event.Free;
   end;
   Event.Free;
   while Client.Service(Event,0)=RNL_HOST_SERVICE_STATUS_EVENT do begin
    Event.Free;
   end;
  finally
   Event.Free;
  end;
 end;

begin

 TestBegin('the connection attempt history stays inside its ring buffer');
 Watchdog:=TRNLTestWatchdog.Create('connection attempt history',120000);
 try

  Peers:=nil;
  Survived:=true;
  FailureText:='';

  Instance:=TRNLInstance.Create;
  try
   Network:=TRNLVirtualNetwork.Create(Instance);
   try
    Server:=TRNLHost.Create(Instance,Network);
    try
     Server.Address.Host:=RNL_HOST_ANY;
     Server.Address.Port:=SERVER_PORT;
     Server.Start(RNL_HOST_ADDRESS_FAMILY_WORK_MODE_IPV4_ONLY);

     Client:=TRNLHost.Create(Instance,Network);
     try
      Client.Address.Host:=RNL_HOST_ANY;
      Client.Address.Port:=CLIENT_PORT;
      Client.MaximumCountPeers:=COUNT_ATTEMPTS*2;
      Client.Start(RNL_HOST_ADDRESS_FAMILY_WORK_MODE_IPV4_ONLY);

      Network.AddressSetHost(ServerAddress,'127.0.0.1');
      ServerAddress.Port:=SERVER_PORT;

      SetLength(Peers,COUNT_ATTEMPTS);
      try

       // Many pending connection attempts from one address, each of which retransmits its
       // request every fPendingConnectionSendTimeout. That is what drives the attempt history
       // fast enough to wrap its ring buffer, and the run has to last past the one second after
       // which the read side starts to age entries out, because only then can the read position
       // end up ahead of the write position, which is the case that used to read past the end of
       // the array.
       for Index:=0 to COUNT_ATTEMPTS-1 do begin
        Peers[Index]:=Client.Connect(ServerAddress,1,0);
        if assigned(Peers[Index]) then begin
         Peers[Index].IncRef;
        end;
        PumpBoth;
        Sleep(1);
       end;

       StartTime:=Instance.Time;
       try
        repeat
         PumpBoth;
         Sleep(1);
        until TRNLTime.RelativeDifference(Instance.Time,StartTime)>=DURATION_MILLISECONDS;
       except
        on e:Exception do begin
         Survived:=false;
         FailureText:=TRNLRawByteString(e.ClassName+': '+e.Message);
        end;
       end;

       Info('connection attempts made: '+TRNLRawByteString(IntToStr(COUNT_ATTEMPTS))+
            ', attempts per second seen by the server: '+
            TRNLRawByteString(IntToStr(Server.ConnectionAttemptsPerSecond))+
            ', challenge difficulty: '+
            TRNLRawByteString(IntToStr(Server.ConnectionChallengeDifficultyLevel)));

       // With range checking compiled in, reading one element past the end of the history array
       // raises here rather than quietly mixing an absolute point in time into a sum of deltas
       if not Survived then begin
        Info('exception: '+FailureText);
       end;
       Check(Survived,'servicing must not raise while the attempt history wraps around');

       CheckAtLeastInt64(Server.ConnectionAttemptsPerSecond,1,
                         'and the measured attempt rate has to stay above zero, since the '+
                         'adaptive challenge difficulty is derived from it');

      finally
       for Index:=0 to length(Peers)-1 do begin
        if assigned(Peers[Index]) then begin
         Peers[Index].DecRef;
        end;
       end;
      end;

     finally
      FreeAndNil(Client);
     end;

    finally
     FreeAndNil(Server);
    end;

   finally
    FreeAndNil(Network);
   end;
  finally
   FreeAndNil(Instance);
  end;

 finally
  FreeAndNil(Watchdog);
  TestEnd;
 end;

end;

procedure RunRegressionTests;
begin

 // The cryptographic primitives first of all, because everything else rests on them and
 // because until now nothing ever checked them
 TestCryptographySelfTestsPass;
 TestHashesStreamInChunksAndHMACHandlesKeyLengths;

 // Pure configuration invariants first, they are instant and their failure explains a lot of
 // what the behavioural tests below would otherwise report in a much noisier way
 TestRetransmissionTimeoutConfigurationIsConsistent;
 TestHostBringsUpTheExpectedSockets;

 // The STUN client, which is where a parser meets datagrams from a stranger
 TestSTUNClientReadsItsMappedAddressAndRejectsMalformedAnswers;

 // The NAT simulator, which every later punching test will rest on
 TestNATNetworkSimulatesTheFourNATKinds;

 // The candidate types, which are pure arithmetic plus one more parser for untrusted input
 TestCandidatePriorityOrderAndSerialisation;
 TestGatherCandidatesFindsHostAndServerReflexive;
 TestHolePunchingOpensTheWayForAnIncomingConnection;
 TestCandidateFanOutStaysBoundedForALongCandidateList;
 TestNATMappingBehaviourIsDetectedForEveryNATKind;
 TestSimultaneousConnectResolvesToOneConnection;

 // The rate limiters, on their own before anything drives them over a network
 TestBandwidthRateLimiterHonoursItsPeriodLength;
 TestConnectionRequestBudgetSurvivesAHashCollision;

 // Test tooling correctness, everything which follows relies on it
 TestOutgoingBitFlippingSimulationActuallyFlipsBits;
 TestHandshakeFieldRewritingKeepsThePacketChecksumValid;

 // Handshake authenticity
 TestTranscriptBindingInteroperabilityMatrix;
 TestTranscriptBindingCoversTheCleartextHandshakeFields;
 TestTranscriptBindingDowngrade;
 TestRemoteLongTermPublicKeyIsVisibleAndPinnable;

 // Socket level error classification
 TestSoftSendFailuresDoNotTerminateHost;
 TestHardSendFailureTerminatesHost;
 TestSoftReceiveFailuresDoNotTerminateHost;
 TestOversizedDatagramsDoNotTerminateHost;
 TestRealSocketReceiveErrorClassification;
 TestRealSocketReportsItsBoundAddress;

 // Retransmission behaviour
 TestSingleLostReliablePacketIsRecoveredQuickly;
 TestReliableTransferUnderPacketLossIsTimely;

 // Bandwidth limits
 TestBandwidthLimitsReachCounterSide;
 TestBandwidthLimitedHostKeepsSendingAfterTheFirstPeriod;

 // MTU probing
 TestMTUProbingTerminatesAndReportsAMTU;
 TestMTUProbingStaysWithinTheDeclaredLimits;
 TestShrinkingMTUDoesNotBlockTheOutgoingQueue;

 // The unreliable channels and their shared fragmentation
 TestUnreliableChannelsTransportShortAndLongMessages;

 // Message size constraints and keep alive independence
 TestOversizedReliableMessageDoesNotStallTheChannel;
 TestKeepAliveSurvivesOutstandingReliableBlockPackets;

 // Container behaviour
 TestQueueGrowthIsNotQuadratic;

 // Peer capacity and connection flooding protection
 TestHostAcceptsExactlyItsConfiguredPeerCapacity;
 TestConnectionAttemptHistoryStaysInsideItsRingBuffer;
 TestRepeatedHandshakeRequestsDoNotEatTheFloodingBudget;

 // Address changes, disconnecting and exactly once delivery
 TestPeerFollowsAnAuthenticatedAddressChange;
 TestDelayedDisconnectAlwaysTerminates;
 TestUndeliverableReliablePacketGivesUpOnThePeer;
 TestReliableUnorderedChannelDeliversEachMessageOnce;
 TestCompressedTransferStaysIntact;

 // The platform specific poll and select code paths
 TestInterruptibleHostBlocksUntilItsTimeout;
 TestInterruptibleHostWakesUpOnInterrupt;
 TestSocketWaitDoesNotChurnKernelObjects;

end;

end.
