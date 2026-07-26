(******************************************************************************
 *                            RNL TEST HOST PAIR                              *
 ******************************************************************************
 *                        Version 2026-07-27-00-00-0000                       *
 ******************************************************************************
 *                                                                            *
 * A connected server plus client pair, both driven from one single thread, so  *
 * that the tests stay deterministic and need no thread synchronisation at all. *
 * Every host event is recorded, so that a test can afterwards assert on what   *
 * did and what did not happen.                                                *
 *                                                                            *
 ******************************************************************************)
unit RNLTestHostPair;
{$ifdef fpc}
 {$mode delphi}
{$endif}
{$h+}

interface

uses SysUtils,
     Classes,
     RNL;

const RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_ORDERED=0;
      RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_UNORDERED=1;
      RNL_TEST_HOST_PAIR_CHANNEL_UNRELIABLE_ORDERED=2;
      RNL_TEST_HOST_PAIR_CHANNEL_UNRELIABLE_UNORDERED=3;
      RNL_TEST_HOST_PAIR_COUNT_CHANNELS=4;

type TRNLTestHostPair=class
      private

       fInstance:TRNLInstance;

       fNetwork:TRNLNetwork;

       fServer:TRNLHost;

       fClient:TRNLHost;

       fClientPeer:TRNLPeer;

       fServerAddress:TRNLAddress;

       fServerReceivedMessages:TStringList;

       fClientReceivedMessages:TStringList;

       fCountServerConnectEvents:TRNLSizeInt;
       fCountClientApprovalEvents:TRNLSizeInt;
       fCountServerDisconnectEvents:TRNLSizeInt;
       fCountClientDisconnectEvents:TRNLSizeInt;
       fCountServerBandwidthLimitsEvents:TRNLSizeInt;
       fCountClientBandwidthLimitsEvents:TRNLSizeInt;
       fCountServerMTUEvents:TRNLSizeInt;
       fCountClientMTUEvents:TRNLSizeInt;

       fLastServerMTU:TRNLUInt16;
       fLastClientMTU:TRNLUInt16;

       fServerServiceStatus:TRNLHostServiceStatus;
       fClientServiceStatus:TRNLHostServiceStatus;

       function ServiceHost(const aHost:TRNLHost;
                           const aIsServer:boolean;
                           const aTimeout:TRNLInt64):boolean;

      public

       constructor Create(const aInstance:TRNLInstance;
                          const aNetwork:TRNLNetwork;
                          const aServerPort:TRNLUInt16=18234;
                          const aClientPort:TRNLUInt16=18235);
       destructor Destroy; override;

       // Runs the handshake. Returns true as soon as both sides consider themselves
       // connected, false on timeout or on a host service error.
       function Connect(const aTimeoutMilliseconds:TRNLInt64=5000):boolean;

       // Services both hosts for the given wall clock duration. Returns false as soon as
       // one of the two hosts reported RNL_HOST_SERVICE_STATUS_ERROR.
       function Pump(const aMilliseconds:TRNLInt64):boolean;

       // Services both hosts until the client has received aCount messages, or until the
       // timeout expires. Returns false on a host service error.
       function PumpUntilClientReceived(const aCount:TRNLSizeInt;
                                        const aTimeoutMilliseconds:TRNLInt64;
                                        out aElapsedMilliseconds:TRNLInt64):boolean;

       // Services both hosts until the server has received aCount messages, or until the
       // timeout expires. Returns false on a host service error.
       function PumpUntilServerReceived(const aCount:TRNLSizeInt;
                                        const aTimeoutMilliseconds:TRNLInt64;
                                        out aElapsedMilliseconds:TRNLInt64):boolean;

       // Services both hosts until the client got at least aCount MTU events, or until the
       // timeout expires. Returns false on a host service error.
       function PumpUntilClientMTUEvent(const aCount:TRNLSizeInt;
                                        const aTimeoutMilliseconds:TRNLInt64;
                                        out aElapsedMilliseconds:TRNLInt64):boolean;

       property Instance:TRNLInstance read fInstance;
       property Server:TRNLHost read fServer;
       property Client:TRNLHost read fClient;
       property ClientPeer:TRNLPeer read fClientPeer;

       property ServerReceivedMessages:TStringList read fServerReceivedMessages;
       property ClientReceivedMessages:TStringList read fClientReceivedMessages;

       property CountServerConnectEvents:TRNLSizeInt read fCountServerConnectEvents;
       property CountClientApprovalEvents:TRNLSizeInt read fCountClientApprovalEvents;
       property CountServerDisconnectEvents:TRNLSizeInt read fCountServerDisconnectEvents;
       property CountClientDisconnectEvents:TRNLSizeInt read fCountClientDisconnectEvents;
       property CountServerBandwidthLimitsEvents:TRNLSizeInt read fCountServerBandwidthLimitsEvents;
       property CountClientBandwidthLimitsEvents:TRNLSizeInt read fCountClientBandwidthLimitsEvents;
       property CountServerMTUEvents:TRNLSizeInt read fCountServerMTUEvents;
       property CountClientMTUEvents:TRNLSizeInt read fCountClientMTUEvents;

       property LastServerMTU:TRNLUInt16 read fLastServerMTU;
       property LastClientMTU:TRNLUInt16 read fLastClientMTU;

       property ServerServiceStatus:TRNLHostServiceStatus read fServerServiceStatus;
       property ClientServiceStatus:TRNLHostServiceStatus read fClientServiceStatus;

     end;

implementation

constructor TRNLTestHostPair.Create(const aInstance:TRNLInstance;
                                    const aNetwork:TRNLNetwork;
                                    const aServerPort:TRNLUInt16=18234;
                                    const aClientPort:TRNLUInt16=18235);
 procedure SetupChannelTypes(const aHost:TRNLHost);
 begin
  aHost.MaximumCountChannels:=RNL_TEST_HOST_PAIR_COUNT_CHANNELS;
  aHost.ChannelTypes[RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_ORDERED]:=RNL_PEER_RELIABLE_ORDERED_CHANNEL;
  aHost.ChannelTypes[RNL_TEST_HOST_PAIR_CHANNEL_RELIABLE_UNORDERED]:=RNL_PEER_RELIABLE_UNORDERED_CHANNEL;
  aHost.ChannelTypes[RNL_TEST_HOST_PAIR_CHANNEL_UNRELIABLE_ORDERED]:=RNL_PEER_UNRELIABLE_ORDERED_CHANNEL;
  aHost.ChannelTypes[RNL_TEST_HOST_PAIR_CHANNEL_UNRELIABLE_UNORDERED]:=RNL_PEER_UNRELIABLE_UNORDERED_CHANNEL;
 end;
begin

 inherited Create;

 fInstance:=aInstance;

 fNetwork:=aNetwork;

 fClientPeer:=nil;

 fServerReceivedMessages:=TStringList.Create;
 fClientReceivedMessages:=TStringList.Create;

 fCountServerConnectEvents:=0;
 fCountClientApprovalEvents:=0;
 fCountServerDisconnectEvents:=0;
 fCountClientDisconnectEvents:=0;
 fCountServerBandwidthLimitsEvents:=0;
 fCountClientBandwidthLimitsEvents:=0;
 fCountServerMTUEvents:=0;
 fCountClientMTUEvents:=0;

 fLastServerMTU:=0;
 fLastClientMTU:=0;

 fServerServiceStatus:=RNL_HOST_SERVICE_STATUS_TIMEOUT;
 fClientServiceStatus:=RNL_HOST_SERVICE_STATUS_TIMEOUT;

 fServer:=TRNLHost.Create(fInstance,fNetwork);
 fServer.Address.Host:=RNL_HOST_ANY;
 fServer.Address.Port:=aServerPort;
 SetupChannelTypes(fServer);
 // Deliberately IPv4 only, because on TRNLVirtualNetwork both address families would bind
 // to the very same localhost address, which makes the address lookup ambiguous
 fServer.Start(RNL_HOST_ADDRESS_FAMILY_WORK_MODE_IPV4_ONLY);

 fClient:=TRNLHost.Create(fInstance,fNetwork);
 fClient.Address.Host:=RNL_HOST_ANY;
 fClient.Address.Port:=aClientPort;
 SetupChannelTypes(fClient);
 fClient.Start(RNL_HOST_ADDRESS_FAMILY_WORK_MODE_IPV4_ONLY);

 fNetwork.AddressSetHost(fServerAddress,'127.0.0.1');
 fServerAddress.Port:=aServerPort;

end;

destructor TRNLTestHostPair.Destroy;
begin
 if assigned(fClientPeer) then begin
  fClientPeer.DecRef;
  fClientPeer:=nil;
 end;
 FreeAndNil(fClient);
 FreeAndNil(fServer);
 FreeAndNil(fClientReceivedMessages);
 FreeAndNil(fServerReceivedMessages);
 inherited Destroy;
end;

function TRNLTestHostPair.ServiceHost(const aHost:TRNLHost;
                                      const aIsServer:boolean;
                                      const aTimeout:TRNLInt64):boolean;
var Event:TRNLHostEvent;
    Status:TRNLHostServiceStatus;
    CountIterations:TRNLSizeInt;
begin

 result:=true;

 Event.Initialize;
 try

  // Bounded, so that a host which keeps producing events can not starve the other one
  CountIterations:=0;

  repeat

   Status:=aHost.Service(Event,aTimeout);

   if aIsServer then begin
    fServerServiceStatus:=Status;
   end else begin
    fClientServiceStatus:=Status;
   end;

   if Status=RNL_HOST_SERVICE_STATUS_ERROR then begin
    result:=false;
    exit;
   end;

   if Status<>RNL_HOST_SERVICE_STATUS_EVENT then begin
    break;
   end;

   case Event.Type_ of

    RNL_HOST_EVENT_TYPE_PEER_CONNECT:begin
     if aIsServer then begin
      inc(fCountServerConnectEvents);
     end;
    end;

    RNL_HOST_EVENT_TYPE_PEER_APPROVAL:begin
     if not aIsServer then begin
      inc(fCountClientApprovalEvents);
     end;
    end;

    RNL_HOST_EVENT_TYPE_PEER_DISCONNECT:begin
     if aIsServer then begin
      inc(fCountServerDisconnectEvents);
     end else begin
      inc(fCountClientDisconnectEvents);
     end;
    end;

    RNL_HOST_EVENT_TYPE_PEER_BANDWIDTH_LIMITS:begin
     if aIsServer then begin
      inc(fCountServerBandwidthLimitsEvents);
     end else begin
      inc(fCountClientBandwidthLimitsEvents);
     end;
    end;

    RNL_HOST_EVENT_TYPE_PEER_MTU:begin
     if aIsServer then begin
      inc(fCountServerMTUEvents);
      fLastServerMTU:=Event.MTU;
     end else begin
      inc(fCountClientMTUEvents);
      fLastClientMTU:=Event.MTU;
     end;
    end;

    RNL_HOST_EVENT_TYPE_PEER_RECEIVE:begin
     if assigned(Event.Message) then begin
      if aIsServer then begin
       fServerReceivedMessages.Add(String(Event.Message.AsRawByteString));
      end else begin
       fClientReceivedMessages.Add(String(Event.Message.AsRawByteString));
      end;
     end;
    end;

    else begin
     // Every other event type is of no interest to these tests
    end;

   end;

   inc(CountIterations);

  until CountIterations>=1024;

 finally
  Event.Free;
 end;

end;

function TRNLTestHostPair.Connect(const aTimeoutMilliseconds:TRNLInt64=5000):boolean;
var StartTime:TRNLTime;
begin

 result:=false;

 fClientPeer:=fClient.Connect(fServerAddress,RNL_TEST_HOST_PAIR_COUNT_CHANNELS,0);

 if not assigned(fClientPeer) then begin
  exit;
 end;

 // Protect it against the DecRef calls of the event dispatching, so that it stays valid
 // for the whole lifetime of this host pair
 fClientPeer.IncRef;

 StartTime:=fInstance.Time;

 repeat

  if not ServiceHost(fServer,true,0) then begin
   exit;
  end;

  if not ServiceHost(fClient,false,0) then begin
   exit;
  end;

  if (fCountClientApprovalEvents>0) and (fCountServerConnectEvents>0) then begin
   result:=true;
   exit;
  end;

  Sleep(1);

 until TRNLTime.RelativeDifference(fInstance.Time,StartTime)>=aTimeoutMilliseconds;

end;

function TRNLTestHostPair.Pump(const aMilliseconds:TRNLInt64):boolean;
var StartTime:TRNLTime;
begin

 result:=true;

 StartTime:=fInstance.Time;

 repeat

  if not ServiceHost(fServer,true,0) then begin
   result:=false;
   exit;
  end;

  if not ServiceHost(fClient,false,0) then begin
   result:=false;
   exit;
  end;

  Sleep(1);

 until TRNLTime.RelativeDifference(fInstance.Time,StartTime)>=aMilliseconds;

end;

function TRNLTestHostPair.PumpUntilClientReceived(const aCount:TRNLSizeInt;
                                                  const aTimeoutMilliseconds:TRNLInt64;
                                                  out aElapsedMilliseconds:TRNLInt64):boolean;
var StartTime:TRNLTime;
begin

 result:=true;

 StartTime:=fInstance.Time;

 repeat

  if not ServiceHost(fServer,true,0) then begin
   result:=false;
   break;
  end;

  if not ServiceHost(fClient,false,0) then begin
   result:=false;
   break;
  end;

  if fClientReceivedMessages.Count>=aCount then begin
   break;
  end;

  Sleep(1);

 until TRNLTime.RelativeDifference(fInstance.Time,StartTime)>=aTimeoutMilliseconds;

 aElapsedMilliseconds:=TRNLTime.RelativeDifference(fInstance.Time,StartTime);

end;

function TRNLTestHostPair.PumpUntilServerReceived(const aCount:TRNLSizeInt;
                                                  const aTimeoutMilliseconds:TRNLInt64;
                                                  out aElapsedMilliseconds:TRNLInt64):boolean;
var StartTime:TRNLTime;
begin

 result:=true;

 StartTime:=fInstance.Time;

 repeat

  if not ServiceHost(fServer,true,0) then begin
   result:=false;
   break;
  end;

  if not ServiceHost(fClient,false,0) then begin
   result:=false;
   break;
  end;

  if fServerReceivedMessages.Count>=aCount then begin
   break;
  end;

  Sleep(1);

 until TRNLTime.RelativeDifference(fInstance.Time,StartTime)>=aTimeoutMilliseconds;

 aElapsedMilliseconds:=TRNLTime.RelativeDifference(fInstance.Time,StartTime);

end;

function TRNLTestHostPair.PumpUntilClientMTUEvent(const aCount:TRNLSizeInt;
                                                  const aTimeoutMilliseconds:TRNLInt64;
                                                  out aElapsedMilliseconds:TRNLInt64):boolean;
var StartTime:TRNLTime;
begin

 result:=true;

 StartTime:=fInstance.Time;

 repeat

  if not ServiceHost(fServer,true,0) then begin
   result:=false;
   break;
  end;

  if not ServiceHost(fClient,false,0) then begin
   result:=false;
   break;
  end;

  if fCountClientMTUEvents>=aCount then begin
   break;
  end;

  Sleep(1);

 until TRNLTime.RelativeDifference(fInstance.Time,StartTime)>=aTimeoutMilliseconds;

 aElapsedMilliseconds:=TRNLTime.RelativeDifference(fInstance.Time,StartTime);

end;

end.
