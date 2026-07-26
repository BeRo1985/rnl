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
     RNLTestHostPair;

procedure RunRegressionTests;

implementation

const PROBABILITY_ALWAYS=TRNLUInt32($ffffffff);
      PROBABILITY_TWENTY_FIVE_PERCENT=TRNLUInt32(TRNLUInt64($ffffffff)*25 div 100);
      PROBABILITY_THIRTY_PERCENT=TRNLUInt32(TRNLUInt64($ffffffff)*30 div 100);

      TEST_MESSAGE_PREFIX='RNLRegressionTestMessage';

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

procedure RunRegressionTests;
begin

 // Pure configuration invariants first, they are instant and their failure explains a lot of
 // what the behavioural tests below would otherwise report in a much noisier way
 TestRetransmissionTimeoutConfigurationIsConsistent;

 // Test tooling correctness, everything which follows relies on it
 TestOutgoingBitFlippingSimulationActuallyFlipsBits;

 // Socket level error classification
 TestSoftSendFailuresDoNotTerminateHost;
 TestHardSendFailureTerminatesHost;
 TestSoftReceiveFailuresDoNotTerminateHost;
 TestOversizedDatagramsDoNotTerminateHost;
 TestRealSocketReceiveErrorClassification;

 // Retransmission behaviour
 TestSingleLostReliablePacketIsRecoveredQuickly;
 TestReliableTransferUnderPacketLossIsTimely;

 // Bandwidth limits
 TestBandwidthLimitsReachCounterSide;

 // MTU probing
 TestMTUProbingTerminatesAndReportsAMTU;

 // The platform specific poll and select code paths
 TestInterruptibleHostBlocksUntilItsTimeout;
 TestInterruptibleHostWakesUpOnInterrupt;

end;

end.
