(********************************************************************************
 *                            RNL TURN RELAY PROBE                              *
 ********************************************************************************
 *                                                                              *
 * Drives RNL's own STUN and TURN client against a real relay over the network. *
 * It is a tool and not a test, and it lives here rather than in src/tests for  *
 * one reason: it needs the internet and a relay which is up, so it can fail    *
 * for reasons that have nothing to do with RNL. The suite next door is         *
 * hermetic and has to stay that way.                                           *
 *                                                                              *
 * It is worth running all the same. iceplan.md left "no coturn in the chain"   *
 * open, because the test server builds its answers with the same message layer *
 * the client parses them with, so an error in that layer could be mirrored on  *
 * both sides and stay invisible. This asks a stranger instead.                 *
 *                                                                              *
 * Two defects turned up the first time it ran: an allocation which was refused *
 * reported no reason at all, and AddressGetHost returned the opposite of the   *
 * truth. Neither was reachable from the hermetic suite.                        *
 *                                                                              *
 * Build:                                                                       *
 *   cd src/tools && fpc -Mdelphi -O1 -Fu.. -FU. turnprobe.dpr                  *
 *                                                                              *
 * Run:                                                                         *
 *   ./turnprobe                     only the 401 exchange, no credentials      *
 *   ./turnprobe <user> <password>   a real allocation                          *
 *                                                                              *
 * Without credentials the interesting answer is which rejection comes back.    *
 * A 401 means the relay read the signed request and turned down only the       *
 * credentials, so realm, nonce and MESSAGE-INTEGRITY were all right. A 400     *
 * would mean it could not read the request at all.                             *
 *                                                                              *
 ********************************************************************************)
program turnprobe;
{$mode delphi}
{$h+}
uses SysUtils,Classes,DateUtils,RNL;
const RELAY_PORT=5349;
var Instance:TRNLInstance;
    Real_:TRNLRealNetwork;
    Username,Password:TRNLRawByteString;
    // Set by --dtls, and then the whole exchange runs through the record layer instead of over
    // bare datagrams. Port 5349 is what a relay offers (D)TLS on, so the same port serves both.
    UseDTLS:boolean=false;
    ServerName:TRNLRawByteString='';
    Verification:TRNLDTLSVerification;
    Pinned:boolean=false;
    Roots:TRNLX509.TChainEntries;
    RootBytes:array of TRNLRawByteString;
    CountRoots:TRNLSizeInt=0;

 // AddressGetHost returns getnameinfo(..)<>0, which is inverted, so the result is ignored here and
 // the buffer read regardless - it is filled correctly either way
 function Show(const aAddress:TRNLAddress):TRNLRawByteString;
 var Text_:array[0..63] of AnsiChar;
 begin
  FillChar(Text_,SizeOf(Text_),#0);
  Real_.AddressGetHostIP(aAddress,Text_,SizeOf(Text_));
  result:=TRNLRawByteString(Text_)+':'+TRNLRawByteString(IntToStr(aAddress.Port));
 end;

 // A DER trust anchor straight off disk, or a SHA-256 fingerprint in hex. The second is what a
 // relay one owns oneself wants: openssl x509 -fingerprint -sha256 reads it off the server.
 function LoadAnchor(const aArgument:string):boolean;
 var Stream:TFileStream;
     Bytes:TRNLRawByteString;
     Fingerprint:TRNLDTLSVerification.TFingerprint;
     Index:TRNLSizeInt;
     Text_:string;
 begin
  result:=false;
  Text_:=StringReplace(aArgument,':','',[rfReplaceAll]);
  if (Length(Text_)=64) and not FileExists(aArgument) then begin
   for Index:=0 to 31 do begin
    Fingerprint[Index]:=TRNLUInt8(StrToInt('$'+Copy(Text_,(Index*2)+1,2)));
   end;
   Verification.InitializeFingerprints;
   result:=Verification.AddFingerprint(Fingerprint);
   Pinned:=result;
   exit;
  end;
  try
   Stream:=TFileStream.Create(aArgument,fmOpenRead or fmShareDenyNone);
   try
    SetLength(Bytes,Stream.Size);
    Stream.ReadBuffer(Bytes[1],Stream.Size);
   finally
    FreeAndNil(Stream);
   end;
  except
   on e:Exception do begin
    writeln('  could not read ',aArgument,': ',e.Message);
    exit;
   end;
  end;
  SetLength(RootBytes,Length(RootBytes)+1);
  RootBytes[Length(RootBytes)-1]:=Bytes;
  Roots[CountRoots].Data:=PRNLUInt8Array(TRNLPointer(@RootBytes[Length(RootBytes)-1][1]));
  Roots[CountRoots].Size:=Length(Bytes);
  inc(CountRoots);
  Verification.InitializeChain(ServerName,Roots,CountRoots,TRNLInt64(DateTimeToUnix(Now)));
  result:=true;
 end;

 procedure Probe(const aHost:TRNLRawByteString;const aFamily:TRNLAddressFamily);
 var ServerAddress,Relayed:TRNLAddress;
     STUN:TRNLSTUNResult;
     Relay:TRNLTURNNetwork;
     Socket:TRNLSocket;
 begin
  writeln('--- ',aHost,' ---');
  ServerAddress.Port:=RELAY_PORT;
  if not Real_.AddressSetHost(ServerAddress,aHost) then begin
   writeln('  could not resolve');
   exit;
  end;
  writeln('  relay            ',Show(ServerAddress));

  STUN:=TRNLSTUNClient.Query(Instance,Real_,ServerAddress,aFamily,2000,3);
  if STUN.Success then begin
   writeln('  stun binding     answered, mapped ',Show(STUN.MappedAddress),
           ', rtt ',STUN.RoundTripTime,' ms');
  end else begin
   writeln('  stun binding     NO ANSWER');
  end;

  Relay:=TRNLTURNNetwork.Create(Instance,Real_,ServerAddress,Username,Password);
  try
   if UseDTLS then begin
    Relay.Transport:=RNL_TURN_TRANSPORT_KIND_DTLS;
    Relay.DTLSVersion:=RNL_TURN_DTLS_VERSION_AUTOMATIC;
    Relay.DTLSServerName:=ServerName;
    Relay.DTLSVerification:=Verification;
   end else begin
    Relay.Transport:=RNL_TURN_TRANSPORT_KIND_UDP;
   end;
   Socket:=Relay.SocketCreate(RNL_SOCKET_TYPE_DATAGRAM,aFamily);
   if Socket=RNL_SOCKET_NULL then begin
    writeln('  no socket');
    exit;
   end;
   try
    if Relay.SocketBind(Socket,nil,aFamily) and Relay.GetRelayedAddress(Socket,Relayed) then begin
     writeln('  turn allocation  GRANTED, relayed ',Show(Relayed));
    end else begin
     writeln('  turn allocation  refused');
    end;
    if UseDTLS then begin
     writeln('  dtls handshakes  ',Relay.TotalFailedDTLSHandshakes,' failed');
    end;
    writeln('  granted ',Relay.TotalAllocations,', failed ',Relay.TotalFailedAllocations,
            ', last error ',Relay.LastFailedAllocationErrorCode,
            ', stale nonces ',Relay.TotalStaleNonces);
   finally
    Relay.SocketDestroy(Socket);
   end;
  finally
   FreeAndNil(Relay);
  end;
 end;

var Argument:TRNLSizeInt;
    Positional:TRNLSizeInt;
begin

 Positional:=0;
 for Argument:=1 to ParamCount do begin
  if ParamStr(Argument)='--dtls' then begin
   UseDTLS:=true;
  end else if Copy(ParamStr(Argument),1,8)='--anchor' then begin
   // --anchor=<file.der> or --anchor=<sha256 fingerprint>
   if not LoadAnchor(Copy(ParamStr(Argument),10,MaxInt)) then begin
    writeln('could not use that anchor');
    Halt(2);
   end;
  end else if Copy(ParamStr(Argument),1,6)='--name' then begin
   ServerName:=TRNLRawByteString(Copy(ParamStr(Argument),8,MaxInt));
  end else begin
   inc(Positional);
   if Positional=1 then begin
    Username:=TRNLRawByteString(ParamStr(Argument));
   end else if Positional=2 then begin
    Password:=TRNLRawByteString(ParamStr(Argument));
   end;
  end;
 end;

 if UseDTLS then begin
  writeln('the relay is talked to over DTLS, so the allocation exchange runs through the');
  if Pinned then begin
   writeln('record layer and the relay is recognised by a pinned fingerprint');
  end else if CountRoots>0 then begin
   writeln('record layer and the relay is recognised by its certificate chain');
  end else begin
   writeln('record layer - but nothing is configured to recognise it by, so this will stop');
   writeln('at the certificate. Pass --anchor=<file.der> or --anchor=<sha256 fingerprint>.');
  end;
  writeln;
 end;

 if Positional>=2 then begin
  writeln('credentials given, a real allocation is attempted');
 end else begin
  Username:='rnl-probe-no-such-user';
  Password:='rnl-probe-no-such-password';
  writeln('no credentials, so what is exercised is realm, nonce and MESSAGE-INTEGRITY -');
  writeln('a 401 means coturn read the message and rejected only the credentials,');
  writeln('a 400 would mean it could not read the message at all');
 end;
 writeln;
 Instance:=TRNLInstance.Create;
 try
  Real_:=TRNLRealNetwork.Create(Instance);
  try
   Probe('167.235.207.182',RNL_IPV4);
   writeln;
   Probe('2a01:4f8:c012:2a69::1',RNL_IPV6);
  finally
   FreeAndNil(Real_);
  end;
 finally
  FreeAndNil(Instance);
 end;
end.
