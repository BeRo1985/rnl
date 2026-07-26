(******************************************************************************
 *                            RNL TEST FRAMEWORK                              *
 ******************************************************************************
 *                        Version 2026-07-27-00-00-0000                       *
 ******************************************************************************
 *                                                                            *
 * A deliberately minimal self-contained test harness for RNL, in the same     *
 * spirit as the RNL contribution rules: no third-party units, compatible with *
 * both FreePascal >= 3.0.4 and newer modern Delphi versions.                  *
 *                                                                            *
 * The watchdog thread is the important part here, because a whole class of    *
 * RNL defects manifests as an endless loop inside the host service loop, and  *
 * a hanging test process reports nothing at all. With the watchdog such a     *
 * defect turns into an ordinary, loud test failure instead.                   *
 *                                                                            *
 ******************************************************************************)
unit RNLTestFramework;
{$ifdef fpc}
 {$mode delphi}
{$endif}
{$h+}

interface

uses {$if defined(fpc) and defined(Unix)}
      BaseUnix,
     {$ifend}
     SysUtils,
     Classes,
     SyncObjs,
     RNL;

type TRNLTestWatchdog=class(TThread)
      private
       fName:TRNLRawByteString;
       fTimeoutMilliseconds:TRNLInt64;
       fDoneEvent:TEvent;
      protected
       procedure Execute; override;
      public
       constructor Create(const aName:TRNLRawByteString;const aTimeoutMilliseconds:TRNLInt64); reintroduce;
       destructor Destroy; override;
     end;

procedure TestBegin(const aName:TRNLRawByteString);
procedure TestEnd;

function Check(const aCondition:boolean;const aDescription:TRNLRawByteString):boolean;
function CheckEqualsInt64(const aGot,aExpected:TRNLInt64;const aDescription:TRNLRawByteString):boolean;
function CheckAtLeastInt64(const aGot,aMinimum:TRNLInt64;const aDescription:TRNLRawByteString):boolean;
function CheckAtMostInt64(const aGot,aMaximum:TRNLInt64;const aDescription:TRNLRawByteString):boolean;
function CheckEqualsRawByteString(const aGot,aExpected:TRNLRawByteString;const aDescription:TRNLRawByteString):boolean;

procedure Info(const aText:TRNLRawByteString);

function TestSummaryAndSucceeded:boolean;

implementation

var CountTests:TRNLSizeInt=0;
    CountFailedTests:TRNLSizeInt=0;
    CountChecks:TRNLSizeInt=0;
    CountFailedChecks:TRNLSizeInt=0;
    CurrentTestName:TRNLRawByteString='';
    CurrentTestFailed:boolean=false;
    CurrentTestStartTime:TRNLTime;
    FailedTestNames:TStringList=nil;
    TimeInstance:TRNLInstance=nil;

function NowMilliseconds:TRNLInt64;
begin
 result:=TRNLInt64(TRNLUInt64(TimeInstance.Time));
end;

constructor TRNLTestWatchdog.Create(const aName:TRNLRawByteString;const aTimeoutMilliseconds:TRNLInt64);
begin
 fName:=aName;
 fTimeoutMilliseconds:=aTimeoutMilliseconds;
 fDoneEvent:=TEvent.Create(nil,true,false,'');
 FreeOnTerminate:=false;
 inherited Create(false);
end;

destructor TRNLTestWatchdog.Destroy;
begin
 if not Finished then begin
  Terminate;
  fDoneEvent.SetEvent;
  WaitFor;
 end;
 FreeAndNil(fDoneEvent);
 inherited Destroy;
end;

procedure TRNLTestWatchdog.Execute;
begin
 if fDoneEvent.WaitFor(fTimeoutMilliseconds)=wrTimeout then begin
  // Deliberately not an exception, because the stuck thread is another one, and it would
  // just keep running. Only killing the whole process gets a verdict out of here.
  writeln;
  writeln('!!! WATCHDOG: "',fName,'" did not finish within ',fTimeoutMilliseconds,' ms.');
  writeln('!!! This very probably means an endless loop inside the host service loop.');
  Flush(Output);
  Halt(2);
 end;
end;

procedure TestBegin(const aName:TRNLRawByteString);
begin
 CurrentTestName:=aName;
 CurrentTestFailed:=false;
 CurrentTestStartTime:=TimeInstance.Time;
 inc(CountTests);
 writeln('[ RUN      ] ',aName);
 Flush(Output);
end;

procedure TestEnd;
var ElapsedMilliseconds:TRNLInt64;
begin
 ElapsedMilliseconds:=TRNLInt64(TRNLUInt64(TimeInstance.Time))-TRNLInt64(TRNLUInt64(CurrentTestStartTime));
 if CurrentTestFailed then begin
  inc(CountFailedTests);
  if assigned(FailedTestNames) then begin
   FailedTestNames.Add(String(CurrentTestName));
  end;
  writeln('[   FAILED ] ',CurrentTestName,' (',ElapsedMilliseconds,' ms)');
 end else begin
  writeln('[       OK ] ',CurrentTestName,' (',ElapsedMilliseconds,' ms)');
 end;
 writeln;
 Flush(Output);
 CurrentTestName:='';
end;

function Check(const aCondition:boolean;const aDescription:TRNLRawByteString):boolean;
begin
 result:=aCondition;
 inc(CountChecks);
 if not result then begin
  inc(CountFailedChecks);
  CurrentTestFailed:=true;
  writeln('             FAIL: ',aDescription);
  Flush(Output);
 end;
end;

function CheckEqualsInt64(const aGot,aExpected:TRNLInt64;const aDescription:TRNLRawByteString):boolean;
begin
 result:=Check(aGot=aExpected,
               aDescription+' (got '+TRNLRawByteString(IntToStr(aGot))+
               ', expected '+TRNLRawByteString(IntToStr(aExpected))+')');
end;

function CheckAtLeastInt64(const aGot,aMinimum:TRNLInt64;const aDescription:TRNLRawByteString):boolean;
begin
 result:=Check(aGot>=aMinimum,
               aDescription+' (got '+TRNLRawByteString(IntToStr(aGot))+
               ', expected at least '+TRNLRawByteString(IntToStr(aMinimum))+')');
end;

function CheckAtMostInt64(const aGot,aMaximum:TRNLInt64;const aDescription:TRNLRawByteString):boolean;
begin
 result:=Check(aGot<=aMaximum,
               aDescription+' (got '+TRNLRawByteString(IntToStr(aGot))+
               ', expected at most '+TRNLRawByteString(IntToStr(aMaximum))+')');
end;

function CheckEqualsRawByteString(const aGot,aExpected:TRNLRawByteString;const aDescription:TRNLRawByteString):boolean;
begin
 result:=Check(aGot=aExpected,
               aDescription+' (got "'+aGot+'", expected "'+aExpected+'")');
end;

procedure Info(const aText:TRNLRawByteString);
begin
 writeln('             info: ',aText);
 Flush(Output);
end;

function TestSummaryAndSucceeded:boolean;
var Index:TRNLSizeInt;
begin
 writeln('============================================================');
 writeln(CountTests,' test(s) run, ',CountChecks,' check(s) evaluated');
 if CountFailedTests=0 then begin
  writeln('ALL TESTS PASSED');
  result:=true;
 end else begin
  writeln(CountFailedTests,' test(s) FAILED, ',CountFailedChecks,' check(s) failed:');
  if assigned(FailedTestNames) then begin
   for Index:=0 to FailedTestNames.Count-1 do begin
    writeln('  - ',FailedTestNames[Index]);
   end;
  end;
  result:=false;
 end;
 writeln('============================================================');
 Flush(Output);
end;

initialization
 TimeInstance:=TRNLInstance.Create;
 FailedTestNames:=TStringList.Create;
finalization
 FreeAndNil(FailedTestNames);
 FreeAndNil(TimeInstance);
end.
