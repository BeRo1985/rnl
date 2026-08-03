(******************************************************************************
 *                            RNL DTLS RELAY PROBE                            *
 ******************************************************************************
 *                                                                            *
 * Drives RNL's own TRNLDTLS12Client through a handshake with a real relay     *
 * over the network. It is a tool and not a test, and it lives here for the    *
 * same reason turnprobe.dpr does: it needs the internet and a relay which is  *
 * up, so it can fail for reasons that have nothing to do with RNL.           *
 *                                                                            *
 * It is the only thing which proves interoperability at all. The suite next   *
 * door drives the client against a stub built out of RNL's own key schedule,  *
 * record layer and transcript, so a handshake completing there says the two   *
 * halves agree with each other and nothing about whether they agree with      *
 * anybody else. Here the other end is coturn.                                 *
 *                                                                            *
 * Build:                                                                      *
 *   cd src/tools && fpc -Mdelphi -O1 -Fu.. -FU. dtlsprobe.dpr                 *
 *                                                                            *
 * Run:                                                                        *
 *   ./dtlsprobe <host> [port] [root.der ...]                                  *
 *                                                                            *
 * Without a trust anchor the handshake is expected to stop at the certificate *
 * with "untrusted root" - which still says that the ClientHello, the cookie    *
 * exchange, the ServerHello and the chain itself were all read. With one it    *
 * should run to the end. The anchors this relay needs can be taken out of      *
 * the local store, for example                                                *
 *                                                                            *
 *   openssl x509 -in /etc/ssl/certs/ISRG_Root_X2.pem -outform der -out x2.der  *
 *                                                                            *
 * The chain it serves is ECDSA the whole way up to ISRG Root X2, which is why  *
 * RNL can check it without ever having an RSA implementation. The last entry   *
 * it sends is that root cross signed by ISRG Root X1 with RSA; nothing here    *
 * has to look at that one, because the root above it is already trusted.       *
 *                                                                            *
 ******************************************************************************)
program dtlsprobe;
{$mode delphi}
{$h+}
uses SysUtils,Classes,DateUtils,RNL;

const DEFAULT_PORT=5349;
      // Long enough for six flights and their backoff, which is what the client itself gives up
      // after, plus a little
      DEADLINE_MILLISECONDS=50000;

var Instance:TRNLInstance;
    Real_:TRNLRealNetwork;
    RandomGenerator:TRNLRandomGenerator;
    Roots:TRNLX509.TChainEntries;
    RootData:array[0..TRNLX509.MaximumChainLength-1] of TRNLRawByteString;
    CountRoots:TRNLSizeInt;
    // How the peer is to be recognised, built from the arguments. Chain by default, since that is
    // what a public relay wants; a fingerprint where one is given, which is the only thing a bare
    // key can be judged by at all.
    Verification:TRNLDTLSVerification;
    Pinned:boolean;

function StateName(const aState:TRNLDTLS12ClientState):TRNLRawByteString;
begin
 case aState of
  RNL_DTLS12_CLIENT_STATE_IDLE:begin result:='idle'; end;
  RNL_DTLS12_CLIENT_STATE_AWAITING_HELLO_VERIFY_REQUEST:begin result:='awaiting HelloVerifyRequest'; end;
  RNL_DTLS12_CLIENT_STATE_AWAITING_SERVER_FLIGHT:begin result:='awaiting the server flight'; end;
  RNL_DTLS12_CLIENT_STATE_AWAITING_SERVER_FINISHED:begin result:='awaiting the server Finished'; end;
  RNL_DTLS12_CLIENT_STATE_ESTABLISHED:begin result:='established'; end;
  else begin result:='failed'; end;
 end;
end;

function FailureName(const aFailure:TRNLDTLS12ClientFailure):TRNLRawByteString;
begin
 case aFailure of
  RNL_DTLS12_CLIENT_FAILURE_NONE:begin result:='none'; end;
  RNL_DTLS12_CLIENT_FAILURE_TIMEOUT:begin result:='timeout'; end;
  RNL_DTLS12_CLIENT_FAILURE_ALERT:begin result:='alert'; end;
  RNL_DTLS12_CLIENT_FAILURE_MALFORMED_MESSAGE:begin result:='malformed message'; end;
  RNL_DTLS12_CLIENT_FAILURE_UNEXPECTED_MESSAGE:begin result:='unexpected message'; end;
  RNL_DTLS12_CLIENT_FAILURE_UNSUPPORTED_CURVE:begin result:='unsupported curve'; end;
  RNL_DTLS12_CLIENT_FAILURE_BAD_CERTIFICATE:begin result:='bad certificate'; end;
  RNL_DTLS12_CLIENT_FAILURE_BAD_KEY_EXCHANGE_SIGNATURE:begin result:='bad key exchange signature'; end;
  RNL_DTLS12_CLIENT_FAILURE_BAD_FINISHED:begin result:='bad Finished'; end;
  else begin result:='internal'; end;
 end;
end;

function VerdictName(const aVerdict:TRNLX509Verdict):TRNLRawByteString;
begin
 case aVerdict of
  RNL_X509_VERDICT_ACCEPTED:begin result:='accepted'; end;
  RNL_X509_VERDICT_MALFORMED:begin result:='malformed'; end;
  RNL_X509_VERDICT_EMPTY_CHAIN:begin result:='empty chain'; end;
  RNL_X509_VERDICT_CHAIN_TOO_LONG:begin result:='chain too long'; end;
  RNL_X509_VERDICT_BAD_SIGNATURE:begin result:='bad signature'; end;
  RNL_X509_VERDICT_ISSUER_MISMATCH:begin result:='issuer mismatch'; end;
  RNL_X509_VERDICT_NOT_A_CERTIFICATE_AUTHORITY:begin result:='not a certificate authority'; end;
  RNL_X509_VERDICT_PATH_TOO_LONG:begin result:='path too long'; end;
  RNL_X509_VERDICT_MISSING_KEY_CERT_SIGN:begin result:='missing keyCertSign'; end;
  RNL_X509_VERDICT_EXPIRED:begin result:='expired'; end;
  RNL_X509_VERDICT_NOT_YET_VALID:begin result:='not yet valid'; end;
  RNL_X509_VERDICT_NO_CLOCK:begin result:='no clock'; end;
  RNL_X509_VERDICT_UNTRUSTED_ROOT:begin result:='untrusted root'; end;
  RNL_X509_VERDICT_WRONG_HOST_NAME:begin result:='wrong host name'; end;
  else begin result:='not a server certificate'; end;
 end;
end;

// A DER file straight off disk. No PEM: converting one is a line of openssl, and a parser for it
// here would be a parser nothing else in RNL needs.
function LoadRoot(const aFileName:string):boolean;
var Stream:TFileStream;
begin
 result:=false;
 if CountRoots>=TRNLX509.MaximumChainLength then begin
  exit;
 end;
 try
  Stream:=TFileStream.Create(aFileName,fmOpenRead or fmShareDenyNone);
  try
   SetLength(RootData[CountRoots],Stream.Size);
   Stream.ReadBuffer(RootData[CountRoots][1],Stream.Size);
  finally
   FreeAndNil(Stream);
  end;
 except
  on e:Exception do begin
   writeln('  could not read ',aFileName,': ',e.Message);
   exit;
  end;
 end;
 Roots[CountRoots].Data:=PRNLUInt8Array(TRNLPointer(@RootData[CountRoots][1]));
 Roots[CountRoots].Size:=Length(RootData[CountRoots]);
 inc(CountRoots);
 result:=true;
end;

// A SHA-256 in hex, with or without colons, rather than a file. What an operator reads off their
// own server - of the certificate, or of the bare key where RFC 7250 is in play.
function LoadPin(const aArgument:string):boolean;
var Fingerprint:TRNLDTLSVerification.TFingerprint;
    Index:TRNLSizeInt;
    Text_:string;
begin
 result:=false;
 Text_:=StringReplace(aArgument,':','',[rfReplaceAll]);
 if Length(Text_)<>64 then begin
  writeln('  a pin is a SHA-256 in hex, 64 characters');
  exit;
 end;
 for Index:=0 to 31 do begin
  Fingerprint[Index]:=TRNLUInt8(StrToInt('$'+Copy(Text_,(Index*2)+1,2)));
 end;
 if not Pinned then begin
  Verification.InitializeFingerprints;
  Pinned:=true;
 end;
 result:=Verification.AddFingerprint(Fingerprint);
end;

procedure Probe(const aHost:TRNLRawByteString;const aPort:TRNLUInt16);
var ServerAddress:TRNLAddress;
    Socket:TRNLSocket;
    Family:TRNLAddressFamily;
    FromAddress:TRNLAddress;
    Client:TRNLDTLS12Client;
    Datagram:array[0..2047] of TRNLUInt8;
    DatagramSize,Received:TRNLSizeInt;
    Conditions:TRNLSocketWaitConditions;
    Started,Now_:TRNLUInt64;
    CountSent,CountReceived,Sent:TRNLSizeInt;
    Payload:array[0..19] of TRNLUInt8;
    Index:TRNLSizeInt;
begin

 ServerAddress.Port:=aPort;
 if not Real_.AddressSetHost(ServerAddress,aHost) then begin
  writeln('  could not resolve ',aHost);
  exit;
 end;

 // Whatever the name resolved to, and not a guess. An IPv6 address handed to an AF_INET socket
 // makes every sendto fail with EINVAL, which looks exactly like a server that is not answering.
 Family:=ServerAddress.GetAddressFamily;
 Socket:=Real_.SocketCreate(RNL_SOCKET_TYPE_DATAGRAM,Family);
 if Socket=RNL_SOCKET_NULL then begin
  writeln('  no socket');
  exit;
 end;

 try

  if not Real_.SocketBind(Socket,nil,Family) then begin
   writeln('  could not bind');
   exit;
  end;
  // Without this the second Receive of a round blocks for ever waiting for a datagram which is not
  // coming, and the whole probe looks like a server which went quiet
  Real_.SocketSetOption(Socket,RNL_SOCKET_OPTION_NONBLOCK,1);

  Client:=TRNLDTLS12Client.Create(RandomGenerator,aHost,Verification);
  try

   CountSent:=0;
   CountReceived:=0;
   Started:=TRNLUInt64(Instance.Time);
   Client.Start(Started);

   repeat

    Now_:=TRNLUInt64(Instance.Time);

    while Client.PopOutgoingDatagram(Datagram,DatagramSize,SizeOf(Datagram)) do begin
     // The result is worth reporting rather than ignoring: a send which fails locally, for
     // example an IPv6 address handed to an AF_INET socket, looks exactly like a server which
     // is not answering, and that cost an hour once
     Sent:=Real_.Send(Socket,@ServerAddress,Datagram,DatagramSize,Family);
     if Sent<>DatagramSize then begin
      writeln('  send             ',Sent,' of ',DatagramSize);
     end;
     inc(CountSent);
    end;

    Conditions:=[RNL_SOCKET_WAIT_CONDITION_IO_RECEIVE];
    if Real_.SocketWait([Socket],Conditions,100) and
       (RNL_SOCKET_WAIT_CONDITION_IO_RECEIVE in Conditions) then begin
     repeat
      Received:=Real_.Receive(Socket,@FromAddress,Datagram,SizeOf(Datagram),Family);
      if Received>0 then begin
       inc(CountReceived);
       Client.ProcessDatagram(Datagram,Received,TRNLUInt64(Instance.Time));
      end;
     until Received<=0;
    end;

    Client.Update(TRNLUInt64(Instance.Time));

   until (Client.State=RNL_DTLS12_CLIENT_STATE_ESTABLISHED) or
         (Client.State=RNL_DTLS12_CLIENT_STATE_FAILED) or
         ((TRNLUInt64(Instance.Time)-Started)>DEADLINE_MILLISECONDS);

   writeln('  datagrams        ',CountSent,' sent, ',CountReceived,' received');
   writeln('  state            ',StateName(Client.State));
   if Client.State=RNL_DTLS12_CLIENT_STATE_FAILED then begin
    write('  failure          ',FailureName(Client.Failure));
    if Client.Failure=RNL_DTLS12_CLIENT_FAILURE_BAD_CERTIFICATE then begin
     write(' (',VerdictName(Client.CertificateVerdict),')');
    end else if Client.Failure=RNL_DTLS12_CLIENT_FAILURE_ALERT then begin
     write(' (description ',Client.AlertDescription,')');
    end;
    writeln;
   end;

   // A STUN binding request down the tunnel, which is what the transport will really carry. The
   // relay answers it inside the same encrypted channel or it does not, and either way the record
   // layer has been exercised in both directions on live traffic.
   if Client.State=RNL_DTLS12_CLIENT_STATE_ESTABLISHED then begin
    FillChar(Payload,SizeOf(Payload),#0);
    Payload[0]:=$00;
    Payload[1]:=$01;
    Payload[2]:=$00;
    Payload[3]:=$00;
    Payload[4]:=$21;
    Payload[5]:=$12;
    Payload[6]:=$a4;
    Payload[7]:=$42;
    for Index:=8 to 19 do begin
     Payload[Index]:=TRNLUInt8($30+Index);
    end;
    if Client.Send(Payload,SizeOf(Payload)) then begin
     while Client.PopOutgoingDatagram(Datagram,DatagramSize,SizeOf(Datagram)) do begin
      Real_.Send(Socket,@ServerAddress,Datagram,DatagramSize,Family);
     end;
     Conditions:=[RNL_SOCKET_WAIT_CONDITION_IO_RECEIVE];
     if Real_.SocketWait([Socket],Conditions,2000) and
        (RNL_SOCKET_WAIT_CONDITION_IO_RECEIVE in Conditions) then begin
      Received:=Real_.Receive(Socket,@FromAddress,Datagram,SizeOf(Datagram),Family);
      if Received>0 then begin
       Client.ProcessDatagram(Datagram,Received,TRNLUInt64(Instance.Time));
      end;
     end;
     if Client.PopApplicationData(Datagram,DatagramSize,SizeOf(Datagram)) then begin
      writeln('  stun over dtls   answered, ',DatagramSize,' bytes back');
     end else begin
      writeln('  stun over dtls   no answer');
     end;
    end;
   end;

  finally
   FreeAndNil(Client);
  end;

 finally
  Real_.SocketDestroy(Socket);
 end;

end;

var Host:TRNLRawByteString;
    Port:TRNLUInt16;
    Argument,Positional:TRNLSizeInt;
    RawKey:boolean;
begin

 if ParamCount<1 then begin
  writeln('usage: dtlsprobe [--pin=<sha256>] [--rawkey] <host> [port] [root.der ...]');
  writeln('  --pin     recognise the peer by the SHA-256 of what it presents, instead of by a');
  writeln('            chain. Repeatable, since a certificate gets replaced eventually.');
  writeln('  --rawkey  offer RFC 7250, so that the peer may send a bare SubjectPublicKeyInfo');
  writeln('            instead of a certificate. Needs a pin - a bare key can be recognised and');
  writeln('            nothing else, and the pin is then taken over the key''s own bytes.');
  Halt(2);
 end;

 CountRoots:=0;
 FillChar(Roots,SizeOf(TRNLX509.TChainEntries),#0);
 FillChar(Verification,SizeOf(TRNLDTLSVerification),#0);
 Pinned:=false;
 RawKey:=false;
 Host:='';
 Port:=DEFAULT_PORT;
 Positional:=0;

 for Argument:=1 to ParamCount do begin
  if Copy(ParamStr(Argument),1,6)='--pin=' then begin
   if not LoadPin(Copy(ParamStr(Argument),7,MaxInt)) then begin
    writeln('could not use that pin');
    Halt(2);
   end;
  end else if ParamStr(Argument)='--rawkey' then begin
   RawKey:=true;
  end else begin
   inc(Positional);
   if Positional=1 then begin
    Host:=TRNLRawByteString(ParamStr(Argument));
   end else if (Positional=2) and (StrToIntDef(ParamStr(Argument),0)>0) then begin
    Port:=TRNLUInt16(StrToInt(ParamStr(Argument)));
   end else begin
    if LoadRoot(ParamStr(Argument)) then begin
     writeln('trust anchor     ',ParamStr(Argument),' (',Roots[CountRoots-1].Size,' bytes)');
    end;
   end;
  end;
 end;

 if Length(Host)=0 then begin
  writeln('no host given');
  Halt(2);
 end;

 if Pinned then begin
  Verification.AllowRawPublicKey:=RawKey;
  if RawKey then begin
   writeln('recognition      a pinned fingerprint, and a bare public key of RFC 7250 is offered');
  end else begin
   writeln('recognition      a pinned fingerprint');
  end;
 end else begin
  if RawKey then begin
   writeln('--rawkey without a pin does nothing: a bare key carries no chain, no issuer, no');
   writeln('validity and no name, so there would be nothing left to judge it by');
  end;
  Verification.InitializeChain(Host,Roots,CountRoots,TRNLInt64(DateTimeToUnix(Now)));
  if CountRoots=0 then begin
   writeln('no trust anchor given, so "bad certificate (untrusted root)" is the expected outcome');
  end;
 end;
 writeln;
 writeln('--- ',Host,':',Port,' ---');

 Instance:=TRNLInstance.Create;
 try
  Real_:=TRNLRealNetwork.Create(Instance);
  try
   RandomGenerator:=TRNLRandomGenerator.Create;
   try
    Probe(Host,Port);
   finally
    FreeAndNil(RandomGenerator);
   end;
  finally
   FreeAndNil(Real_);
  end;
 finally
  FreeAndNil(Instance);
 end;

end.
