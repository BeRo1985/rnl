# RNL tests

Self-contained regression tests for RNL. No third-party test framework is used, in line
with the RNL contribution rules, so these build with plain FreePascal or Delphi.

## Building and running

```sh
cd src/tests
./build.sh
./RNLTests
```

Exit codes: `0` all passed, `1` a test failed, `2` the watchdog had to kill a hanging test.

For Delphi, open `RNLTests.dpr` and build it as a console application.

## What is in here

| Unit | Purpose |
| --- | --- |
| `RNLTests.dpr` | Test runner |
| `RNLTestFramework.pas` | Minimal assertions, reporting and the watchdog |
| `RNLTestNetworkFaultInjector.pas` | A `TRNLNetwork` decorator which injects socket level faults |
| `RNLTestHostPair.pas` | A connected server plus client pair, driven from a single thread |
| `RNLTestRegressions.pas` | The actual test cases |

## Why there is a fault injector

`TRNLNetworkInterferenceSimulator` simulates everything which can happen to a packet on its
way — loss, duplication, reordering, latency, jitter, bit flips. What it can not simulate is
anything which happens to the *local socket*, and `TRNLVirtualNetwork` underneath it has
neither an MTU nor a send buffer which could ever fill up.

On a real network `TRNLRealNetwork.Send` and `.Receive` report a whole range of conditions
which are routine and transient — a full send buffer, a datagram above the path MTU, an
interrupted syscall, or an ICMP error which the kernel queued onto the socket for a
previously sent datagram. None of them can ever occur on the virtual network, so a whole
class of behaviour is simply unreachable from a purely simulator based test.

`TRNLNetworkFaultInjector` closes that gap. It can inject, either probabilistically or
deterministically:

* soft send failures (`Send` returns `0`, as on `EWOULDBLOCK` / `ENOBUFS` / `EMSGSIZE`)
* hard send failures (`Send` returns `-1`)
* soft receive failures (`Receive` returns `0` although a datagram was there)
* hard receive failures (`Receive` returns `-1`)
* a maximum datagram size, which makes larger datagrams fail like `EMSGSIZE` does
* deterministic loss of the next N outgoing datagrams above a given size

The deterministic variant is what makes timing assertions possible at all: losing one exactly
known datagram and then measuring the recovery is reproducible, whereas the total duration of
a bulk transfer under probabilistic loss varies by a factor of two between runs and is
dominated by the backoff rather than by the initial retransmission timeout.

## The watchdog

Several failure modes in a network library are not wrong results but endless loops inside the
service loop. A hanging test process reports nothing at all, so every test which drives a
host wraps itself in a `TRNLTestWatchdog`. When the deadline passes, it prints why and kills
the process with exit code `2`, which turns a hang into an ordinary, loud test failure.

## Notes on writing further tests

* Both hosts of `TRNLTestHostPair` are serviced from one single thread, which keeps the tests
  deterministic and free of any synchronisation of their own.
* The host pair binds IPv4 only. On `TRNLVirtualNetwork` both address families would bind to
  the very same localhost address, which makes the address lookup ambiguous.
* Prefer deterministic fault injection plus a tight assertion over probabilistic fault
  injection plus a loose one. A test which passes both with and without the defect it is
  supposed to guard is worse than no test, because it looks like coverage.
* When adding a test, verify it actually fails once the corresponding defect is reintroduced.
