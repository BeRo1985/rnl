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

 // Pure configuration invariants first, they are instant and their failure explains a lot of
 // what the behavioural tests below would otherwise report in a much noisier way
 TestRetransmissionTimeoutConfigurationIsConsistent;

 // The rate limiters, on their own before anything drives them over a network
 TestBandwidthRateLimiterHonoursItsPeriodLength;
 TestConnectionRequestBudgetSurvivesAHashCollision;

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
