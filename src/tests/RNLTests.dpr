(******************************************************************************
 *                              RNL TEST RUNNER                               *
 ******************************************************************************
 *                        Version 2026-07-27-00-00-0000                       *
 ******************************************************************************
 *                                                                            *
 * Exits with code 0 when everything passed, with 1 on a test failure and with  *
 * 2 when the watchdog had to kill a hanging test.                             *
 *                                                                            *
 * Build with FreePascal:                                                      *
 *   cd src/tests && ./build.sh && ./RNLTests                                  *
 *                                                                            *
 ******************************************************************************)
program RNLTests;
{$ifdef fpc}
 {$mode delphi}
{$endif}
{$ifdef Windows}
 {$apptype console}
{$endif}
{$h+}

uses {$ifdef unix}
      cthreads,
     {$endif}
     SysUtils,
     Classes,
     RNL in '../RNL.pas',
     RNLTestFramework in 'RNLTestFramework.pas',
     RNLTestNetworkFaultInjector in 'RNLTestNetworkFaultInjector.pas',
     RNLTestHostPair in 'RNLTestHostPair.pas',
     RNLTestSTUNServer in 'RNLTestSTUNServer.pas',
     RNLTestNATNetwork in 'RNLTestNATNetwork.pas',
     RNLTestRegressions in 'RNLTestRegressions.pas';

begin

 writeln('RNL ',RNL_VERSION);
 writeln('============================================================');
 writeln;

 try

  RunRegressionTests;

 except
  on e:Exception do begin
   writeln;
   writeln('!!! Unhandled ',e.ClassName,': ',e.Message);
   Flush(Output);
   Halt(1);
  end;
 end;

 if TestSummaryAndSucceeded then begin
  Halt(0);
 end else begin
  Halt(1);
 end;

end.
