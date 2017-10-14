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

{-$define UseConsoleOutputConditionVariable}

uses
  {$ifdef unix}
  cthreads,
  {$endif}
  SysUtils,
  Classes,
  SyncObjs,
  RNL in '..\..\src\RNL.pas',
  PasMP in '..\..\externals\pasmp\src\PasMP.pas';

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

type TConsoleOutputThread=class(TPasMPThread)
      protected
       procedure Execute; override;
     end;

{$ifdef UseConsoleOutputConditionVariable}
     TConsoleOutputQueue=TRNLQueue<string>;
{$else}
     TConsoleOutputQueue=TPasMPUnboundedQueue<string>;
{$endif}

     TServer=class(TPasMPThread)
      private
       fReadyEvent:TPasMPEvent;
      protected
       procedure Execute; override;
      public
       constructor Create(const aCreateSuspended:boolean); reintroduce;
       destructor Destroy; override;
     end;

     TClient=class(TPasMPThread)
      protected
       procedure Execute; override;
     end;

var RNLInstance:TRNLInstance=nil;

    RNLCompressorClass:TRNLCompressorClass=TRNLCompressorLZBRRC;

    ConsoleOutputQueue:TConsoleOutputQueue=nil;

    ConsoleOutputThread:TConsoleOutputThread=nil;

{$ifdef UseConsoleOutputConditionVariable}
    ConsoleOutputConditionVariableLock:TPasMPConditionVariableLock=nil;

    ConsoleOutputConditionVariable:TPasMPConditionVariable=nil;
{$else}

    ConsoleOutputEvent:TPasMPEvent=nil;

{$endif}

    RNLMainNetwork:TRNLNetwork=nil;

    RNLNetwork:TRNLNetwork=nil;

procedure ConsoleOutput(const s:string);
begin
{$ifdef UseConsoleOutputConditionVariable}
 ConsoleOutputConditionVariableLock.Acquire;
 try
  ConsoleOutputQueue.Enqueue(s);
  ConsoleOutputConditionVariable.Signal;
 finally
  ConsoleOutputConditionVariableLock.Release;
 end;
{$else}
 ConsoleOutputQueue.Enqueue(s);
 ConsoleOutputEvent.SetEvent;
{$endif}
end;

procedure FlushConsoleOutput;
var s:string;
begin
{$ifdef UseConsoleOutputConditionVariable}
 ConsoleOutputConditionVariableLock.Acquire;
 try
{$endif}
  while ConsoleOutputQueue.Dequeue(s) do begin
   writeln(s);
  end;
{$ifdef UseConsoleOutputConditionVariable}
 finally
  ConsoleOutputConditionVariableLock.Release;
 end;
{$endif}
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
{$ifdef UseConsoleOutputConditionVariable}
  ConsoleOutputConditionVariableLock.Acquire;
  try
   while not Terminated do begin
    case ConsoleOutputConditionVariable.Wait(ConsoleOutputConditionVariableLock,1000) of
     wrSignaled:begin
      while (not Terminated) and ConsoleOutputQueue.Dequeue(s) do begin
       writeln(s);
      end;
     end;
    end;
   end;
  finally
   ConsoleOutputConditionVariableLock.Release;
  end;
{$else}
  while not Terminated do begin
   ConsoleOutputEvent.WaitFor(1000);
   while (not Terminated) and ConsoleOutputQueue.Dequeue(s) do begin
    writeln(s);
   end;
  end;
{$endif}
 except
  on e:Exception do begin
   LogThreadException('Console output',e);
  end;
 end;
 ConsoleOutput('Console output: Thread stopped');
end;

constructor TServer.Create(const aCreateSuspended:boolean);
begin
 fReadyEvent:=TPasMPEvent.Create(nil,false,false,'');
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
   Server.Start;
   fReadyEvent.SetEvent;
   Event.Initialize;
   try
    while (not Terminated) and (Server.Service(Event,1000)<>RNL_HOST_SERVICE_STATUS_ERROR) do begin
     try
      case Event.Type_ of
       RNL_HOST_EVENT_TYPE_CONNECT:begin
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
       RNL_HOST_EVENT_TYPE_DISCONNECT:begin
        ConsoleOutput(Format('Server: A client disconnected, local peer ID %d, remote peer ID %d, channels count %d',
                             [Event.Peer.LocalPeerID,
                              Event.Peer.RemotePeerID,
                              Event.Peer.CountChannels]));
       end;
       RNL_HOST_EVENT_TYPE_MTU:begin
        ConsoleOutput('Server: A client '+IntToStr(TRNLPtrUInt(Event.Peer))+' has new MTU '+IntToStr(TRNLPtrUInt(Event.MTU)));
       end;
       RNL_HOST_EVENT_TYPE_RECEIVE:begin
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
   Client.Start;
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
        RNL_HOST_EVENT_TYPE_APPROVAL:begin
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
             RNL_HOST_EVENT_TYPE_CONNECT:begin
              if Event.Peer=Peer then begin
               ConsoleOutput(Format('Client: Connected, local peer ID %d, remote peer ID %d, channels count %d',
                                    [Event.Peer.LocalPeerID,
                                     Event.Peer.RemotePeerID,
                                     Event.Peer.CountChannels]));
              end;
             end;
             RNL_HOST_EVENT_TYPE_DISCONNECT:begin
              ConsoleOutput(Format('Client: Disconnected, local peer ID %d, remote peer ID %d, channels count %d',
                                   [Event.Peer.LocalPeerID,
                                    Event.Peer.RemotePeerID,
                                    Event.Peer.CountChannels]));
              if Event.Peer=Peer then begin
               Disconnected:=true;
               break;
              end;
             end;
             RNL_HOST_EVENT_TYPE_DENIAL:begin
              if Event.Peer=Peer then begin
               ConsoleOutput('Client: Denied');
               Disconnected:=true;
               break;
              end;
             end;
             RNL_HOST_EVENT_TYPE_MTU:begin
              ConsoleOutput('Client: New MTU '+IntToStr(TRNLPtrUInt(Event.MTU)));
             end;
             RNL_HOST_EVENT_TYPE_RECEIVE:begin
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
              RNL_HOST_EVENT_TYPE_RECEIVE:begin
              end;
              RNL_HOST_EVENT_TYPE_DISCONNECT:begin
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
        RNL_HOST_EVENT_TYPE_DENIAL:begin
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
{$ifdef UseConsoleOutputConditionVariable}
    ConsoleOutputConditionVariableLock:=TPasMPConditionVariableLock.Create;
    try
     ConsoleOutputConditionVariable:=TPasMPConditionVariable.Create;
     try
      ConsoleOutputQueue:=TConsoleOutputQueue.Create;
{$else}
    try
     ConsoleOutputEvent:=TPasMPEvent.Create(nil,false,false,'');
     try
      ConsoleOutputQueue:=TConsoleOutputQueue.Create(false);
{$endif}
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
{$ifdef UseConsoleOutputConditionVariable}
        ConsoleOutputConditionVariable.Signal;
{$else}
        ConsoleOutputEvent.SetEvent;
{$endif}
        ConsoleOutputThread.WaitFor;
        LogThreadException('Console output',ConsoleOutputThread.FatalException);
        FreeAndNil(ConsoleOutputThread);
       end;
       FlushConsoleOutput;
      finally
       FreeAndNil(ConsoleOutputQueue);
      end;
{$ifdef UseConsoleOutputConditionVariable}
     finally
      FreeAndNil(ConsoleOutputConditionVariable);
     end;
    finally
     FreeAndNil(ConsoleOutputConditionVariableLock);
    end;
{$else}
     finally
      FreeAndNil(ConsoleOutputEvent);
     end;
    finally
    end;
{$endif}
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
