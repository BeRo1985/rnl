program combinedexample;
{$ifdef fpc}
 {$mode delphi}
{$else}
 {$ifdef conditionalexpressions}
  {$if CompilerVersion>=24.0}
   {$legacyifend on}
  {$ifend}
 {$endif}
{$endif}
{$if defined(Win32) or defined(Win64)}
 {$apptype console}
{$ifend}

// Hint: FPC has yet no TMonitor support

uses
  {$ifdef unix}
  cthreads,
  {$endif}
  SysUtils,
  Classes,
  SyncObjs,
  RNL in '..\..\src\RNL.pas';

const SimulatedIncomingPacketLossProbabilityFactor=TRNLUInt32($00000000);
      SimulatedOutgoingPacketLossProbabilityFactor=TRNLUInt32($00000000);
      SimulatedIncomingDuplicatePacketProbabilityFactor=TRNLUInt32($00000000);
      SimulatedOutgoingDuplicatePacketProbabilityFactor=TRNLUInt32($00000000);
      SimulatedIncomingBitFlippingProbabilityFactor=TRNLUInt32($00000000);
      SimulatedOutgoingBitFlippingProbabilityFactor=TRNLUInt32($00000000);
      SimulatedIncomingMinimumFlippingBits=1;
      SimulatedOutgoingMinimumFlippingBits=1;
      SimulatedIncomingMaximumFlippingBits=4;
      SimulatedOutgoingMaximumFlippingBits=4;
      SimulatedIncomingLatency=0;
      SimulatedOutgoingLatency=0;
      SimulatedIncomingJitter=0;
      SimulatedOutgoingJitter=0;

type TConsoleOutputThread=class(TThread)
      protected
       procedure Execute; override;
     end;

     TConsoleOutputQueue=TRNLQueue<string>;

     TServer=class(TThread)
      private
       fReadyEvent:TEvent;
      protected
       procedure Execute; override;
      public
       constructor Create(const aCreateSuspended:boolean); reintroduce;
       destructor Destroy; override;
     end;

     TClient=class(TThread)
      protected
       procedure Execute; override;
     end;

var RNLInstance:TRNLInstance=nil;

    RNLCompressorClass:TRNLCompressorClass=TRNLCompressorLZBRRC;

    ConsoleOutputQueue:TConsoleOutputQueue=nil;

    ConsoleOutputThread:TConsoleOutputThread=nil;

    ConsoleOutputLock:TCriticalSection=nil;

    ConsoleOutputEvent:TEvent=nil;

    RNLMainNetwork:TRNLNetwork=nil;

    RNLNetwork:TRNLNetwork=nil;

procedure ConsoleOutput(const s:string);
begin
 ConsoleOutputLock.Acquire;
 try
  ConsoleOutputQueue.Enqueue(s);
  ConsoleOutputEvent.SetEvent;
 finally
  ConsoleOutputLock.Release;
 end;
end;

procedure FlushConsoleOutput;
var s:string;
begin
 ConsoleOutputLock.Acquire;
 try
  while ConsoleOutputQueue.Dequeue(s) do begin
   writeln(s);
  end;
 finally
  ConsoleOutputLock.Release;
 end;
end;

procedure LogThreadException(const aThreadName:string;const aException:TObject);
{$if defined(fpc)}
var i:int32;
    Frames:PPointer;
    s:string;
begin
 if assigned(aException) then begin
  s:=aThreadName+' thread failed with exception class '+aException.ClassName+LineEnding;
  if aException is Exception then begin
   s:=s+'Exception Message: '+Exception(aException).Message+LineEnding;
  end;
  s:=s+LineEnding+'Stack trace:'+LineEnding+LineEnding;
  s:=s+BackTraceStrFunc(ExceptAddr);
  Frames:=ExceptFrames;
  for i:=0 to ExceptFrameCount-1 do begin
   s:=s+LineEnding+BackTraceStrFunc(Frames);
   inc(Frames);
  end;
  ConsoleOutput(s);
 end;
end;
{$else}
begin
 if assigned(aException) then begin
  if aException is Exception then begin
   ConsoleOutput(aThreadName+' thread failed with exception '+aException.ClassName+': '+Exception(aException).Message);
  end else begin
   ConsoleOutput(aThreadName+' thread failed with exception '+aException.ClassName);
  end;
 end;
end;
{$ifend}

procedure TConsoleOutputThread.Execute;
var s:string;
begin
{$ifndef fpc}
 NameThreadForDebugging('Console output');
{$endif}
 ConsoleOutput('Console output: Thread started');
 try
  while not Terminated do begin
   ConsoleOutputEvent.WaitFor(1000);
   while not Terminated do begin
    ConsoleOutputLock.Acquire;
    try
     if not ConsoleOutputQueue.Dequeue(s) then begin
      break;
     end;
    finally
     ConsoleOutputLock.Release;
    end;
    writeln(s);
   end;
  end;
 except
  on e:Exception do begin
   LogThreadException('Console output',e);
  end;
 end;
 ConsoleOutput('Console output: Thread stopped');
end;

constructor TServer.Create(const aCreateSuspended:boolean);
begin
 fReadyEvent:=TEvent.Create(nil,false,false,'');
 inherited Create(aCreateSuspended);
end;

destructor TServer.Destroy;
begin
 inherited Destroy;
 FreeAndNil(fReadyEvent);
end;

procedure TServer.Execute;
var //Address:TRNLAddress;
    Server:TRNLHost;
    Event:TRNLHostEvent;
begin
{$ifndef fpc}
 NameThreadForDebugging('Server');
{$endif}
 ConsoleOutput('Server: Thread started');
 try
  Server:=TRNLHost.Create(RNLInstance,RNLNetwork);
  try
   Server.Address.Host:=RNL_HOST_ANY;
   Server.Address.Port:=64242;
{  RNLNetwork.AddressSetHost(Server.Address^,'127.0.0.1');
   Server.Address.Port:=64242;{}
   Server.Compressor:=RNLCompressorClass.Create;
   Server.MaximumCountChannels:=4;
   Server.ChannelTypes[0]:=RNL_PEER_RELIABLE_ORDERED_CHANNEL;
   Server.ChannelTypes[1]:=RNL_PEER_RELIABLE_UNORDERED_CHANNEL;
   Server.ChannelTypes[2]:=RNL_PEER_UNRELIABLE_ORDERED_CHANNEL;
   Server.ChannelTypes[3]:=RNL_PEER_UNRELIABLE_UNORDERED_CHANNEL;
   Server.Start(RNL_HOST_ADDRESS_FAMILY_WORK_MODE_IPV4_AND_IPV6);
   fReadyEvent.SetEvent;
   Event.Initialize;
   try
    while (not Terminated) and (Server.Service(Event,1000)<>RNL_HOST_SERVICE_STATUS_ERROR) do begin
     try
      case Event.Type_ of
       RNL_HOST_EVENT_TYPE_PEER_CHECK_CONNECTION_TOKEN:begin
        if assigned(Event.ConnectionCandidate) then begin
         ConsoleOutput('Server: A new client is connecting');
         Event.ConnectionCandidate.AcceptConnectionToken;
        end;
       end;
       RNL_HOST_EVENT_TYPE_PEER_CHECK_AUTHENTICATION_TOKEN:begin
        if assigned(Event.ConnectionCandidate) then begin
         ConsoleOutput('Server: A new client is authenticating');
         Event.ConnectionCandidate.AcceptAuthenticationToken;
        end;
       end;
       RNL_HOST_EVENT_TYPE_PEER_CONNECT:begin
        ConsoleOutput(Format('Server: A new client connected, local peer ID %d, remote peer ID %d, channels count %d',
                             [Event.Peer.LocalPeerID,
                              Event.Peer.RemotePeerID,
                              Event.Peer.CountChannels]));
        Event.Peer.Channels[0].SendMessageString('Hello world!');
        Event.Peer.Channels[0].SendMessageString('Hello another world!');
        Event.Peer.Channels[0].SendMessageString('Hello world in an another world! Yet another hello world with an yet another hello world!');
        Event.Peer.Channels[0].SendMessageString('Hello another world in an world! Yet another hello world with an yet another hello world!');
  //    Server.Flush;
       end;
       RNL_HOST_EVENT_TYPE_PEER_DISCONNECT:begin
        ConsoleOutput(Format('Server: A client disconnected, local peer ID %d, remote peer ID %d, channels count %d',
                             [Event.Peer.LocalPeerID,
                              Event.Peer.RemotePeerID,
                              Event.Peer.CountChannels]));
       end;
       RNL_HOST_EVENT_TYPE_PEER_MTU:begin
        ConsoleOutput('Server: A client '+IntToStr(TRNLPtrUInt(Event.Peer))+' has new MTU '+IntToStr(TRNLPtrUInt(Event.MTU)));
       end;
       RNL_HOST_EVENT_TYPE_PEER_RECEIVE:begin
        ConsoleOutput('Server: A message received');
       end;
      end;
     finally
      Event.Free;
     end;
    end;
   finally
    Event.Finalize;
   end;
  finally
   Server.Free;
  end;
 except
  on e:Exception do begin
   LogThreadException('Server',e);
  end;
 end;
 ConsoleOutput('Server: Thread stopped');
end;

procedure TClient.Execute;
var Address:TRNLAddress;
    Client:TRNLHost;
    Event:TRNLHostEvent;
    Peer:TRNLPeer;
    Disconnected:boolean;
begin
{$ifndef fpc}
 NameThreadForDebugging('Client');
{$endif}
 ConsoleOutput('Client: Thread started');
 try
  Client:=TRNLHost.Create(RNLInstance,RNLNetwork);
  try
   Client.Compressor:=RNLCompressorClass.Create;
   Client.MaximumCountChannels:=4;
   Client.ChannelTypes[0]:=RNL_PEER_RELIABLE_ORDERED_CHANNEL;
   Client.ChannelTypes[1]:=RNL_PEER_RELIABLE_UNORDERED_CHANNEL;
   Client.ChannelTypes[2]:=RNL_PEER_UNRELIABLE_ORDERED_CHANNEL;
   Client.ChannelTypes[3]:=RNL_PEER_UNRELIABLE_UNORDERED_CHANNEL;
   Client.Start(RNL_HOST_ADDRESS_FAMILY_WORK_MODE_IPV4_AND_IPV6);
   ConsoleOutput('Client: Connecting');
   Address.Port:=64242;
   if ParamCount>1 then begin
    RNLNetwork.AddressSetHost(Address,TRNLRawByteString(ParamStr(2)));
   end else begin
    RNLNetwork.AddressSetHost(Address,'127.0.0.1');
   end;
   Address.Port:=64242;
   Peer:=Client.Connect(Address,4,0);
   if assigned(Peer) then begin
    Peer.IncRef; // Protect it for the Peer.Free call at the end (increase ReferenceCounter from 1 to 2, so that correct-used DecRef calls never will free this peer class instance)
    try
     Event.Initialize;
     try
      if Client.Service(Event,5000)=RNL_HOST_SERVICE_STATUS_EVENT then begin
       case Event.Type_ of
        RNL_HOST_EVENT_TYPE_PEER_APPROVAL:begin
         if Event.Peer=Peer then begin
          ConsoleOutput(Format('Client: Connected, local peer ID %d, remote peer ID %d, channels count %d',
                               [Event.Peer.LocalPeerID,
                                Event.Peer.RemotePeerID,
                                Event.Peer.CountChannels]));
          Disconnected:=false;
          while (not Terminated) and (Client.Service(Event,1000)<>RNL_HOST_SERVICE_STATUS_ERROR) do begin
           try
            case Event.Type_ of
             RNL_HOST_EVENT_TYPE_NONE:begin
             end;
             RNL_HOST_EVENT_TYPE_PEER_CONNECT:begin
              if Event.Peer=Peer then begin
               ConsoleOutput(Format('Client: Connected, local peer ID %d, remote peer ID %d, channels count %d',
                                    [Event.Peer.LocalPeerID,
                                     Event.Peer.RemotePeerID,
                                     Event.Peer.CountChannels]));
              end;
             end;
             RNL_HOST_EVENT_TYPE_PEER_DISCONNECT:begin
              ConsoleOutput(Format('Client: Disconnected, local peer ID %d, remote peer ID %d, channels count %d',
                                   [Event.Peer.LocalPeerID,
                                    Event.Peer.RemotePeerID,
                                    Event.Peer.CountChannels]));
              if Event.Peer=Peer then begin
               Disconnected:=true;
               break;
              end;
             end;
             RNL_HOST_EVENT_TYPE_PEER_DENIAL:begin
              if Event.Peer=Peer then begin
               ConsoleOutput('Client: Denied');
               Disconnected:=true;
               break;
              end;
             end;
             RNL_HOST_EVENT_TYPE_PEER_MTU:begin
              ConsoleOutput('Client: New MTU '+IntToStr(TRNLPtrUInt(Event.MTU)));
             end;
             RNL_HOST_EVENT_TYPE_PEER_RECEIVE:begin
              ConsoleOutput('Client: A message received on channel '+IntToStr(Event.Channel)+': "'+String(Event.Message.AsString)+'"');
             end;
            end;
           finally
            Event.Free;
           end;
          end;
          if not Disconnected then begin
           ConsoleOutput('Client: Disconnecting');
           Peer.Disconnect;
           while Client.Service(Event,3000)<>RNL_HOST_SERVICE_STATUS_ERROR do begin
            try
             case Event.type_ of
              RNL_HOST_EVENT_TYPE_PEER_RECEIVE:begin
              end;
              RNL_HOST_EVENT_TYPE_PEER_DISCONNECT:begin
               ConsoleOutput(Format('Client: Disconnected, local peer ID %d, remote peer ID %d, channels count %d',
                                    [Event.Peer.LocalPeerID,
                                     Event.Peer.RemotePeerID,
                                     Event.Peer.CountChannels]));
               if Event.Peer=Peer then begin
                break;
               end;
              end;
             end;
            finally
             Event.Free;
            end;
           end;
          end;
         end else begin
          ConsoleOutput('Connection failed');
         end;
        end;
        RNL_HOST_EVENT_TYPE_PEER_DENIAL:begin
         ConsoleOutput('Connection denied');
        end;
        else begin
         ConsoleOutput('Connection failed');
        end;
       end;
      end else begin
       ConsoleOutput('Connection failed');
      end;
     finally
      Event.Finalize;
     end;
    finally
     Peer.Free;
    end;
   end else begin
    ConsoleOutput('Connection failed');
   end;
  finally
   Client.Free;
  end;
 except
  on e:Exception do begin
   LogThreadException('Client',e);
  end;
 end;
 ConsoleOutput('Client: Thread stopped');
end;

var Server:TServer;
    Client:TClient;
    s:string;
begin
 s:=ParamStr(1);
 RNLInstance:=TRNLInstance.Create;
 try
  RNLMainNetwork:={$ifdef VirtualNetwork}TRNLVirtualNetwork{$else}TRNLRealNetwork{$endif}.Create(RNLInstance);
  try
   RNLNetwork:=TRNLNetworkInterferenceSimulator.Create(RNLInstance,RNLMainNetwork);
   try
    TRNLNetworkInterferenceSimulator(RNLNetwork).SimulatedIncomingPacketLossProbabilityFactor:=SimulatedIncomingPacketLossProbabilityFactor;
    TRNLNetworkInterferenceSimulator(RNLNetwork).SimulatedOutgoingPacketLossProbabilityFactor:=SimulatedOutgoingPacketLossProbabilityFactor;
    TRNLNetworkInterferenceSimulator(RNLNetwork).SimulatedIncomingDuplicatePacketProbabilityFactor:=SimulatedIncomingDuplicatePacketProbabilityFactor;
    TRNLNetworkInterferenceSimulator(RNLNetwork).SimulatedOutgoingDuplicatePacketProbabilityFactor:=SimulatedOutgoingDuplicatePacketProbabilityFactor;
    TRNLNetworkInterferenceSimulator(RNLNetwork).SimulatedIncomingBitFlippingProbabilityFactor:=SimulatedIncomingBitFlippingProbabilityFactor;
    TRNLNetworkInterferenceSimulator(RNLNetwork).SimulatedOutgoingBitFlippingProbabilityFactor:=SimulatedOutgoingBitFlippingProbabilityFactor;
    TRNLNetworkInterferenceSimulator(RNLNetwork).SimulatedIncomingMinimumFlippingBits:=SimulatedIncomingMinimumFlippingBits;
    TRNLNetworkInterferenceSimulator(RNLNetwork).SimulatedOutgoingMinimumFlippingBits:=SimulatedOutgoingMinimumFlippingBits;
    TRNLNetworkInterferenceSimulator(RNLNetwork).SimulatedIncomingMaximumFlippingBits:=SimulatedIncomingMaximumFlippingBits;
    TRNLNetworkInterferenceSimulator(RNLNetwork).SimulatedOutgoingMaximumFlippingBits:=SimulatedOutgoingMaximumFlippingBits;
    TRNLNetworkInterferenceSimulator(RNLNetwork).SimulatedIncomingLatency:=SimulatedIncomingLatency;
    TRNLNetworkInterferenceSimulator(RNLNetwork).SimulatedOutgoingLatency:=SimulatedOutgoingLatency;
    TRNLNetworkInterferenceSimulator(RNLNetwork).SimulatedIncomingJitter:=SimulatedIncomingJitter;
    TRNLNetworkInterferenceSimulator(RNLNetwork).SimulatedOutgoingJitter:=SimulatedOutgoingJitter;
    ConsoleOutputLock:=TCriticalSection.Create;
    try
     ConsoleOutputEvent:=TEvent.Create(nil,false,false,'');
     try
      ConsoleOutputQueue:=TConsoleOutputQueue.Create;
      try
       ConsoleOutputThread:=TConsoleOutputThread.Create(false);
       try
        if s='Server' then begin
         Server:=TServer.Create(false);
         try
          readln;
         finally
          Server.Terminate;
          Server.WaitFor;
          LogThreadException('Server',Server.FatalException);
          Server.Free;
         end;
        end else if s='Client' then begin
         Client:=TClient.Create(false);
         try
          readln;
         finally
          Client.Terminate;
          Client.WaitFor;
          LogThreadException('Client',Client.FatalException);
          Client.Free;
         end;
        end else begin
         Server:=TServer.Create(false);
         try
          Server.fReadyEvent.WaitFor(10000);
          Client:=TClient.Create(false);
          try
           readln;
          finally
           Client.Terminate;
           Client.WaitFor;
           Client.Free;
          end;
         finally
          Server.Terminate;
          Server.WaitFor;
          Server.Free;
         end;
        end;
       finally
        ConsoleOutputThread.Terminate;
        ConsoleOutputEvent.SetEvent;
        ConsoleOutputThread.WaitFor;
        LogThreadException('Console output',ConsoleOutputThread.FatalException);
        FreeAndNil(ConsoleOutputThread);
       end;
       FlushConsoleOutput;
      finally
       FreeAndNil(ConsoleOutputQueue);
      end;
     finally
      FreeAndNil(ConsoleOutputEvent);
     end;
    finally
     FreeAndNil(ConsoleOutputLock);
    end;
   finally
    FreeAndNil(RNLNetwork);
   end;
  finally
   FreeAndNil(RNLMainNetwork);
  end;
 finally
  FreeAndNil(RNLInstance);
 end;
 readln;
end.
