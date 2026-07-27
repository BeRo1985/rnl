(******************************************************************************
 *                         RNL TEST NAT NETWORK                               *
 ******************************************************************************
 *                        Version 2026-07-27-00-00-0000                       *
 ******************************************************************************
 *                                                                            *
 * A NAT, simulated well enough that hole punching can be tested against it.    *
 * Punching against real NATs is not reproducible: the outcome depends on the   *
 * router in the room, and a test which passes today for reasons nobody can     *
 * name is worse than no test.                                                 *
 *                                                                            *
 * Two things decide whether punching works, and they are independent:          *
 *                                                                            *
 *   the mapping   which external port an inside socket is given, and whether   *
 *                 that depends on where it is sending to                      *
 *   the filter    which senders are allowed back in through that mapping       *
 *                                                                            *
 *   type                mapping                     filter                    *
 *   ------------------  --------------------------  ----------------------     *
 *   full cone           per inside socket           none                       *
 *   address restricted  per inside socket           addresses sent to          *
 *   port restricted     per inside socket           address and port sent to    *
 *   symmetric           per inside socket and per   address and port sent to    *
 *                       destination                                           *
 *                                                                            *
 * Symmetric is the case punching cannot beat, because the external port a peer  *
 * was told about is not the one its own datagrams will arrive on.              *
 *                                                                            *
 * Mappings expire, which is what makes rebinding testable at all: a connection  *
 * which has gone quiet for long enough loses its way back in.                  *
 *                                                                            *
 * On the virtual network every socket lives on 127.0.0.1 and only the port      *
 * tells them apart, so "inside" is expressed as a set of ports. That is a       *
 * simplification of a real topology and a faithful model of what matters here.  *
 *                                                                            *
 ******************************************************************************)
unit RNLTestNATNetwork;
{$ifdef fpc}
 {$mode delphi}
{$endif}
{$h+}

interface

uses SysUtils,
     Classes,
     SyncObjs,
     RNL;

type TRNLTestNATKind=
      (
       RNL_TEST_NAT_FULL_CONE,
       RNL_TEST_NAT_ADDRESS_RESTRICTED,
       RNL_TEST_NAT_PORT_RESTRICTED,
       RNL_TEST_NAT_SYMMETRIC
      );

     TRNLTestNATNetwork=class(TRNLNetwork)
      private

       type TMapping=record
             Used:boolean;
             InsideAddress:TRNLAddress;
             ExternalPort:TRNLUInt16;
             // Only consulted for a symmetric NAT, where the mapping depends on the destination
             OutsideHost:TRNLHostAddress;
             OutsidePort:TRNLUInt16;
             LastUsed:TRNLTime;
            end;
            TMappings=array of TMapping;

            // One entry per outside endpoint an inside socket has sent something to, which is what
            // the restricted filters go by
            TPermission=record
             Used:boolean;
             InsideAddress:TRNLAddress;
             OutsideHost:TRNLHostAddress;
             OutsidePort:TRNLUInt16;
             LastUsed:TRNLTime;
            end;
            TPermissions=array of TPermission;

            TSocketPort=record
             Used:boolean;
             Socket:TRNLSocket;
             Port:TRNLUInt16;
            end;
            TSocketPorts=array of TSocketPort;

      private

       fInstance:TRNLInstance;

       fNetwork:TRNLNetwork;

       fKind:TRNLTestNATKind;

       fExternalHost:TRNLHostAddress;

       // Where the inside sockets live. On the virtual network that is localhost, but stating it
       // rather than assuming it keeps the two sides of the translation named.
       fInsideHost:TRNLHostAddress;

       fNextExternalPort:TRNLUInt16;

       fMappingTimeoutMilliseconds:TRNLInt64;

       fInsideAddresses:array of TRNLAddress;

       fMappings:TMappings;

       fPermissions:TPermissions;

       fSocketPorts:TSocketPorts;

       fLock:TCriticalSection;

       fCountTranslatedOutgoing:TRNLUInt64;
       fCountDeliveredInbound:TRNLUInt64;
       fCountFilteredInbound:TRNLUInt64;
       fCountExpiredMappings:TRNLUInt64;

       function IsInside(const aAddress:TRNLAddress):boolean;
       function PortOfSocket(const aSocket:TRNLSocket):TRNLUInt16;
       // The filters and the symmetric mapping lookup go by who is sending or receiving, never by
       // where a datagram is headed, so both need the socket's own address and not the one in the
       // call
       function AddressOfSocket(const aSocket:TRNLSocket):TRNLAddress;
       procedure RememberSocketPort(const aSocket:TRNLSocket;const aPort:TRNLUInt16);
       procedure ExpireStaleEntries;
       function AcquireMapping(const aInside,aOutside:TRNLAddress):TRNLUInt16;
       function FindMappingByExternalPort(const aExternalPort:TRNLUInt16;
                                          const aSender:TRNLAddress;
                                          out aInside:TRNLAddress):boolean;
       function FindMappingByInside(const aInside:TRNLAddress;
                                    const aOutside:TRNLAddress;
                                    out aExternalPort:TRNLUInt16):boolean;
       procedure RememberPermission(const aInside,aOutside:TRNLAddress);
       function InboundAllowed(const aInside,aSender:TRNLAddress):boolean;

       function GetCountTranslatedOutgoing:TRNLUInt64;
       function GetCountDeliveredInbound:TRNLUInt64;
       function GetCountFilteredInbound:TRNLUInt64;
       function GetCountExpiredMappings:TRNLUInt64;

      public

       constructor Create(const aInstance:TRNLInstance;
                          const aNetwork:TRNLNetwork;
                          const aKind:TRNLTestNATKind;
                          const aExternalHost:TRNLHostAddress;
                          const aInsideHost:TRNLHostAddress); reintroduce;
       destructor Destroy; override;

       // Declares a port to sit behind the NAT. Everything else is outside.
       procedure AddInside(const aAddress:TRNLAddress);

       // The address an outside peer would have to be told in order to reach that inside socket,
       // which is what a server reflexive candidate amounts to. False while no mapping exists yet,
       // since a NAT only creates one once something has been sent out through it.
       function ExternalAddressOf(const aInside:TRNLAddress;
                                  const aOutside:TRNLAddress;
                                  out aAddress:TRNLAddress):boolean;

       // Throws every mapping and permission away, the way a router losing its state would
       procedure ForgetEverything;

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

       property Kind:TRNLTestNATKind read fKind;
       // Zero switches expiry off, which is what every test that is not about expiry wants
       property MappingTimeoutMilliseconds:TRNLInt64 read fMappingTimeoutMilliseconds write fMappingTimeoutMilliseconds;
       property CountTranslatedOutgoing:TRNLUInt64 read GetCountTranslatedOutgoing;
       property CountDeliveredInbound:TRNLUInt64 read GetCountDeliveredInbound;
       property CountFilteredInbound:TRNLUInt64 read GetCountFilteredInbound;
       property CountExpiredMappings:TRNLUInt64 read GetCountExpiredMappings;

     end;

implementation

const FIRST_EXTERNAL_PORT=40000;

constructor TRNLTestNATNetwork.Create(const aInstance:TRNLInstance;
                                      const aNetwork:TRNLNetwork;
                                      const aKind:TRNLTestNATKind;
                                      const aExternalHost:TRNLHostAddress;
                                      const aInsideHost:TRNLHostAddress);
begin
 inherited Create(aInstance);
 fInstance:=aInstance;
 fNetwork:=aNetwork;
 fKind:=aKind;
 fExternalHost:=aExternalHost;
 fInsideHost:=aInsideHost;
 fNextExternalPort:=FIRST_EXTERNAL_PORT;
 fMappingTimeoutMilliseconds:=0;
 fInsideAddresses:=nil;
 fMappings:=nil;
 fPermissions:=nil;
 fSocketPorts:=nil;
 fLock:=TCriticalSection.Create;
 fCountTranslatedOutgoing:=0;
 fCountDeliveredInbound:=0;
 fCountFilteredInbound:=0;
 fCountExpiredMappings:=0;
end;

destructor TRNLTestNATNetwork.Destroy;
begin
 fInsideAddresses:=nil;
 fMappings:=nil;
 fPermissions:=nil;
 fSocketPorts:=nil;
 FreeAndNil(fLock);
 inherited Destroy;
end;

procedure TRNLTestNATNetwork.AddInside(const aAddress:TRNLAddress);
var Count:TRNLSizeInt;
begin
 fLock.Acquire;
 try
  Count:=length(fInsideAddresses);
  SetLength(fInsideAddresses,Count+1);
  fInsideAddresses[Count]:=aAddress;
 finally
  fLock.Release;
 end;
end;

function TRNLTestNATNetwork.IsInside(const aAddress:TRNLAddress):boolean;
var Index:TRNLSizeInt;
begin
 result:=false;
 for Index:=0 to length(fInsideAddresses)-1 do begin
  if fInsideAddresses[Index].Host.Equals(aAddress.Host) and
     (fInsideAddresses[Index].Port=aAddress.Port) then begin
   result:=true;
   exit;
  end;
 end;
end;

procedure TRNLTestNATNetwork.RememberSocketPort(const aSocket:TRNLSocket;const aPort:TRNLUInt16);
var Index,Count:TRNLSizeInt;
begin
 for Index:=0 to length(fSocketPorts)-1 do begin
  if fSocketPorts[Index].Used and (fSocketPorts[Index].Socket=aSocket) then begin
   fSocketPorts[Index].Port:=aPort;
   exit;
  end;
 end;
 Count:=length(fSocketPorts);
 SetLength(fSocketPorts,Count+1);
 fSocketPorts[Count].Used:=true;
 fSocketPorts[Count].Socket:=aSocket;
 fSocketPorts[Count].Port:=aPort;
end;

function TRNLTestNATNetwork.PortOfSocket(const aSocket:TRNLSocket):TRNLUInt16;
var Index:TRNLSizeInt;
    Address:TRNLAddress;
begin
 for Index:=0 to length(fSocketPorts)-1 do begin
  if fSocketPorts[Index].Used and (fSocketPorts[Index].Socket=aSocket) then begin
   result:=fSocketPorts[Index].Port;
   exit;
  end;
 end;
 // Not seen being bound, which happens for a socket bound to port zero and then given one by the
 // network, so ask
 result:=0;
 if fNetwork.SocketGetAddress(aSocket,Address,RNL_IPV4) then begin
  result:=Address.Port;
  RememberSocketPort(aSocket,result);
 end;
end;

function TRNLTestNATNetwork.AddressOfSocket(const aSocket:TRNLSocket):TRNLAddress;
begin
 if not fNetwork.SocketGetAddress(aSocket,result,RNL_IPV4) then begin
  FillChar(result,SizeOf(TRNLAddress),#0);
  result.Host:=fInsideHost;
  result.Port:=PortOfSocket(aSocket);
 end;
end;

procedure TRNLTestNATNetwork.ExpireStaleEntries;
var Index:TRNLSizeInt;
    Now_:TRNLTime;
begin
 if fMappingTimeoutMilliseconds<=0 then begin
  exit;
 end;
 Now_:=fInstance.Time;
 for Index:=0 to length(fMappings)-1 do begin
  if fMappings[Index].Used and
     (TRNLTime.RelativeDifference(Now_,fMappings[Index].LastUsed)>=fMappingTimeoutMilliseconds) then begin
   fMappings[Index].Used:=false;
   inc(fCountExpiredMappings);
  end;
 end;
 for Index:=0 to length(fPermissions)-1 do begin
  if fPermissions[Index].Used and
     (TRNLTime.RelativeDifference(Now_,fPermissions[Index].LastUsed)>=fMappingTimeoutMilliseconds) then begin
   fPermissions[Index].Used:=false;
  end;
 end;
end;

function TRNLTestNATNetwork.AcquireMapping(const aInside,aOutside:TRNLAddress):TRNLUInt16;
var Index,Count,Free_:TRNLSizeInt;
    Matches:boolean;
begin
 Free_:=-1;
 for Index:=0 to length(fMappings)-1 do begin
  if fMappings[Index].Used then begin
   if fMappings[Index].InsideAddress.Host.Equals(aInside.Host) and (fMappings[Index].InsideAddress.Port=aInside.Port) then begin
    // A symmetric NAT hands out a fresh external port per destination, every other kind reuses the
    // one it gave this socket the first time
    if fKind=RNL_TEST_NAT_SYMMETRIC then begin
     Matches:=fMappings[Index].OutsideHost.Equals(aOutside.Host) and
              (fMappings[Index].OutsidePort=aOutside.Port);
    end else begin
     Matches:=true;
    end;
    if Matches then begin
     fMappings[Index].LastUsed:=fInstance.Time;
     result:=fMappings[Index].ExternalPort;
     exit;
    end;
   end;
  end else if Free_<0 then begin
   Free_:=Index;
  end;
 end;
 if Free_<0 then begin
  Count:=length(fMappings);
  SetLength(fMappings,Count+1);
  Free_:=Count;
 end;
 fMappings[Free_].Used:=true;
 fMappings[Free_].InsideAddress:=aInside;
 fMappings[Free_].ExternalPort:=fNextExternalPort;
 fMappings[Free_].OutsideHost:=aOutside.Host;
 fMappings[Free_].OutsidePort:=aOutside.Port;
 fMappings[Free_].LastUsed:=fInstance.Time;
 inc(fNextExternalPort);
 result:=fMappings[Free_].ExternalPort;
end;

function TRNLTestNATNetwork.FindMappingByExternalPort(const aExternalPort:TRNLUInt16;
                                                      const aSender:TRNLAddress;
                                                      out aInside:TRNLAddress):boolean;
var Index:TRNLSizeInt;
begin
 result:=false;
 FillChar(aInside,SizeOf(TRNLAddress),#0);
 for Index:=0 to length(fMappings)-1 do begin
  if fMappings[Index].Used and (fMappings[Index].ExternalPort=aExternalPort) then begin
   // For a symmetric NAT the mapping only works for the destination it was created for, which is
   // exactly why a peer told about this port cannot use it
   if (fKind=RNL_TEST_NAT_SYMMETRIC) and
      not (fMappings[Index].OutsideHost.Equals(aSender.Host) and
           (fMappings[Index].OutsidePort=aSender.Port)) then begin
    continue;
   end;
   aInside:=fMappings[Index].InsideAddress;
   fMappings[Index].LastUsed:=fInstance.Time;
   result:=true;
   exit;
  end;
 end;
end;

function TRNLTestNATNetwork.FindMappingByInside(const aInside:TRNLAddress;
                                                const aOutside:TRNLAddress;
                                                out aExternalPort:TRNLUInt16):boolean;
var Index:TRNLSizeInt;
begin
 result:=false;
 aExternalPort:=0;
 for Index:=0 to length(fMappings)-1 do begin
  if fMappings[Index].Used and (fMappings[Index].InsideAddress.Host.Equals(aInside.Host) and (fMappings[Index].InsideAddress.Port=aInside.Port)) then begin
   if (fKind=RNL_TEST_NAT_SYMMETRIC) and
      not (fMappings[Index].OutsideHost.Equals(aOutside.Host) and
           (fMappings[Index].OutsidePort=aOutside.Port)) then begin
    continue;
   end;
   aExternalPort:=fMappings[Index].ExternalPort;
   result:=true;
   exit;
  end;
 end;
end;

procedure TRNLTestNATNetwork.RememberPermission(const aInside,aOutside:TRNLAddress);
var Index,Count,Free_:TRNLSizeInt;
begin
 Free_:=-1;
 for Index:=0 to length(fPermissions)-1 do begin
  if fPermissions[Index].Used then begin
   if (fPermissions[Index].InsideAddress.Host.Equals(aInside.Host) and (fPermissions[Index].InsideAddress.Port=aInside.Port)) and
      fPermissions[Index].OutsideHost.Equals(aOutside.Host) and
      (fPermissions[Index].OutsidePort=aOutside.Port) then begin
    fPermissions[Index].LastUsed:=fInstance.Time;
    exit;
   end;
  end else if Free_<0 then begin
   Free_:=Index;
  end;
 end;
 if Free_<0 then begin
  Count:=length(fPermissions);
  SetLength(fPermissions,Count+1);
  Free_:=Count;
 end;
 fPermissions[Free_].Used:=true;
 fPermissions[Free_].InsideAddress:=aInside;
 fPermissions[Free_].OutsideHost:=aOutside.Host;
 fPermissions[Free_].OutsidePort:=aOutside.Port;
 fPermissions[Free_].LastUsed:=fInstance.Time;
end;

function TRNLTestNATNetwork.InboundAllowed(const aInside,aSender:TRNLAddress):boolean;
var Index:TRNLSizeInt;
begin
 if fKind=RNL_TEST_NAT_FULL_CONE then begin
  // Anybody who knows the external port gets in
  result:=true;
  exit;
 end;
 result:=false;
 for Index:=0 to length(fPermissions)-1 do begin
  if fPermissions[Index].Used and
     (fPermissions[Index].InsideAddress.Host.Equals(aInside.Host) and (fPermissions[Index].InsideAddress.Port=aInside.Port)) and
     fPermissions[Index].OutsideHost.Equals(aSender.Host) then begin
   // An address restricted NAT stops caring here, the other two also want the port to match
   if (fKind=RNL_TEST_NAT_ADDRESS_RESTRICTED) or
      (fPermissions[Index].OutsidePort=aSender.Port) then begin
    result:=true;
    exit;
   end;
  end;
 end;
end;

function TRNLTestNATNetwork.ExternalAddressOf(const aInside:TRNLAddress;
                                              const aOutside:TRNLAddress;
                                              out aAddress:TRNLAddress):boolean;
var ExternalPort:TRNLUInt16;
begin
 FillChar(aAddress,SizeOf(TRNLAddress),#0);
 fLock.Acquire;
 try
  ExpireStaleEntries;
  result:=FindMappingByInside(aInside,aOutside,ExternalPort);
  if result then begin
   aAddress.Host:=fExternalHost;
   aAddress.Port:=ExternalPort;
  end;
 finally
  fLock.Release;
 end;
end;

procedure TRNLTestNATNetwork.ForgetEverything;
begin
 fLock.Acquire;
 try
  fMappings:=nil;
  fPermissions:=nil;
 finally
  fLock.Release;
 end;
end;

function TRNLTestNATNetwork.Send(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aData;const aDataLength:TRNLSizeInt;const aFamily:TRNLAddressFamily):TRNLSizeInt;
var Redirected,Sender,Inside:TRNLAddress;
    DoRedirect,DoDrop:boolean;
begin

 if not assigned(aAddress) then begin
  result:=fNetwork.Send(aSocket,aAddress,aData,aDataLength,aFamily);
  exit;
 end;

 DoRedirect:=false;
 DoDrop:=false;

 fLock.Acquire;
 try

  ExpireStaleEntries;

  Sender:=AddressOfSocket(aSocket);

  if IsInside(Sender) then begin

   // Inside towards outside: this is what opens a mapping and what grants the sender permission to
   // answer. The datagram itself travels unchanged; the translation only becomes visible when the
   // far side receives it, see Receive.
   AcquireMapping(Sender,aAddress^);
   RememberPermission(Sender,aAddress^);
   inc(fCountTranslatedOutgoing);

  end else if aAddress^.Host.Equals(fExternalHost) then begin

   // Outside towards the NAT's external address, so this has to find its way to an inside socket,
   // if there is a mapping for that port and the sender is allowed through the filter
   if FindMappingByExternalPort(aAddress^.Port,Sender,Inside) then begin
    if InboundAllowed(Inside,Sender) then begin
     Redirected:=Inside;
     DoRedirect:=true;
     inc(fCountDeliveredInbound);
    end else begin
     DoDrop:=true;
     inc(fCountFilteredInbound);
    end;
   end else begin
    // No mapping at all, so nothing is listening behind that port
    DoDrop:=true;
    inc(fCountFilteredInbound);
   end;

  end;

 finally
  fLock.Release;
 end;

 if DoDrop then begin
  // Swallowed by the NAT, which from the sender's point of view is ordinary loss
  result:=aDataLength;
  exit;
 end;

 if DoRedirect then begin
  result:=fNetwork.Send(aSocket,@Redirected,aData,aDataLength,aFamily);
  exit;
 end;

 result:=fNetwork.Send(aSocket,aAddress,aData,aDataLength,aFamily);

end;

function TRNLTestNATNetwork.Receive(const aSocket:TRNLSocket;const aAddress:PRNLAddress;out aData;const aDataLength:TRNLSizeInt;const aFamily:TRNLAddressFamily):TRNLSizeInt;
var ExternalPort:TRNLUInt16;
    Receiver:TRNLAddress;
begin

 result:=fNetwork.Receive(aSocket,aAddress,aData,aDataLength,aFamily);

 if (result>0) and assigned(aAddress) then begin
  fLock.Acquire;
  try
   Receiver:=AddressOfSocket(aSocket);
   // Only an outside socket gets to see the translation; an inside one sees the real remote address,
   // which is what it would see behind a real router as well
   if (not IsInside(Receiver)) and
      IsInside(aAddress^) and
      FindMappingByInside(aAddress^,Receiver,ExternalPort) then begin
    aAddress^.Host:=fExternalHost;
    aAddress^.Port:=ExternalPort;
   end;
  finally
   fLock.Release;
  end;
 end;

end;

function TRNLTestNATNetwork.SocketBind(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aFamily:TRNLAddressFamily):boolean;
var Address:TRNLAddress;
begin
 result:=fNetwork.SocketBind(aSocket,aAddress,aFamily);
 if result then begin
  fLock.Acquire;
  try
   if fNetwork.SocketGetAddress(aSocket,Address,aFamily) then begin
    RememberSocketPort(aSocket,Address.Port);
   end else if assigned(aAddress) then begin
    RememberSocketPort(aSocket,aAddress^.Port);
   end;
  finally
   fLock.Release;
  end;
 end;
end;

procedure TRNLTestNATNetwork.SocketDestroy(const aSocket:TRNLSocket);
var Index:TRNLSizeInt;
begin
 fLock.Acquire;
 try
  for Index:=0 to length(fSocketPorts)-1 do begin
   if fSocketPorts[Index].Used and (fSocketPorts[Index].Socket=aSocket) then begin
    fSocketPorts[Index].Used:=false;
   end;
  end;
 finally
  fLock.Release;
 end;
 fNetwork.SocketDestroy(aSocket);
end;

function TRNLTestNATNetwork.GetCountTranslatedOutgoing:TRNLUInt64;
begin
 fLock.Acquire;
 try
  result:=fCountTranslatedOutgoing;
 finally
  fLock.Release;
 end;
end;

function TRNLTestNATNetwork.GetCountDeliveredInbound:TRNLUInt64;
begin
 fLock.Acquire;
 try
  result:=fCountDeliveredInbound;
 finally
  fLock.Release;
 end;
end;

function TRNLTestNATNetwork.GetCountFilteredInbound:TRNLUInt64;
begin
 fLock.Acquire;
 try
  result:=fCountFilteredInbound;
 finally
  fLock.Release;
 end;
end;

function TRNLTestNATNetwork.GetCountExpiredMappings:TRNLUInt64;
begin
 fLock.Acquire;
 try
  result:=fCountExpiredMappings;
 finally
  fLock.Release;
 end;
end;

function TRNLTestNATNetwork.AddressSetHost(var aAddress:TRNLAddress;const aName:TRNLRawByteString):boolean;
begin
 result:=fNetwork.AddressSetHost(aAddress,aName);
end;

function TRNLTestNATNetwork.AddressGetHost(const aAddress:TRNLAddress;out aName;const aNameLength:TRNLInt32;const aFlags:TRNLInt32=0):boolean;
begin
 result:=fNetwork.AddressGetHost(aAddress,aName,aNameLength,aFlags);
end;

function TRNLTestNATNetwork.AddressGetHostIP(const aAddress:TRNLAddress;out aName;const aNameLength:TRNLInt32):boolean;
begin
 result:=fNetwork.AddressGetHostIP(aAddress,aName,aNameLength);
end;

function TRNLTestNATNetwork.SocketCreate(const aType:TRNLSocketType;const aFamily:TRNLAddressFamily):TRNLSocket;
begin
 result:=fNetwork.SocketCreate(aType,aFamily);
end;

function TRNLTestNATNetwork.SocketShutdown(const aSocket:TRNLSocket;const aHow:TRNLSocketShutdown=RNL_SOCKET_SHUTDOWN_READ_WRITE):boolean;
begin
 result:=fNetwork.SocketShutdown(aSocket,aHow);
end;

function TRNLTestNATNetwork.SocketGetAddress(const aSocket:TRNLSocket;out aAddress:TRNLAddress;const aFamily:TRNLAddressFamily):boolean;
begin
 result:=fNetwork.SocketGetAddress(aSocket,aAddress,aFamily);
end;

function TRNLTestNATNetwork.SocketSetOption(const aSocket:TRNLSocket;const aOption:TRNLSocketOption;const aValue:TRNLInt32):boolean;
begin
 result:=fNetwork.SocketSetOption(aSocket,aOption,aValue);
end;

function TRNLTestNATNetwork.SocketGetOption(const aSocket:TRNLSocket;const aOption:TRNLSocketOption;out aValue:TRNLInt32):boolean;
begin
 result:=fNetwork.SocketGetOption(aSocket,aOption,aValue);
end;

function TRNLTestNATNetwork.SocketListen(const aSocket:TRNLSocket;const aBackLog:TRNLInt32):boolean;
begin
 result:=fNetwork.SocketListen(aSocket,aBackLog);
end;

function TRNLTestNATNetwork.SocketConnect(const aSocket:TRNLSocket;const aAddress:TRNLAddress;const aFamily:TRNLAddressFamily):boolean;
begin
 result:=fNetwork.SocketConnect(aSocket,aAddress,aFamily);
end;

function TRNLTestNATNetwork.SocketAccept(const aSocket:TRNLSocket;const aAddress:PRNLAddress;const aFamily:TRNLAddressFamily):TRNLSocket;
begin
 result:=fNetwork.SocketAccept(aSocket,aAddress,aFamily);
end;

function TRNLTestNATNetwork.SocketSelect(const aMaxSocket:TRNLSocket;var aReadSet,aWriteSet:TRNLSocketSet;const aTimeout:TRNLInt64;const aEvent:TRNLNetworkEvent=nil):TRNLInt32;
begin
 result:=fNetwork.SocketSelect(aMaxSocket,aReadSet,aWriteSet,aTimeout,aEvent);
end;

function TRNLTestNATNetwork.SocketWait(const aSockets:array of TRNLSocket;var aConditions:TRNLSocketWaitConditions;const aTimeout:TRNLInt64;const aEvent:TRNLNetworkEvent=nil):boolean;
begin
 result:=fNetwork.SocketWait(aSockets,aConditions,aTimeout,aEvent);
end;

end.
