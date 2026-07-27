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

### Also run the Windows build

```sh
./build.sh --win64
wine ./RNLTests.exe        # or run it on Windows
```

This is worth doing even from a non Windows machine. The Windows socket wait is a code path
of its own: it emulates `poll` on top of `WSAEventSelect` and `WSAWaitForMultipleEvents`,
while every other platform uses `poll` or `select` directly. Nothing shared covers it, and
the two `interruptible host` tests are what exercise it.

Both builds must produce the same number of tests and the same number of checks. A differing
check count means some assertion sits inside a polling loop and is therefore counted a
timing dependent number of times, which is a defect in the test, not a platform difference.

## What is in here

| Unit | Purpose |
| --- | --- |
| `RNLTests.dpr` | Test runner |
| `RNLTestFramework.pas` | Minimal assertions, reporting and the watchdog |
| `RNLTestNetworkFaultInjector.pas` | A `TRNLNetwork` decorator which injects socket level faults |
| `RNLTestHostPair.pas` | A connected server plus client pair, driven from a single thread |
| `RNLTestSTUNServer.pas` | Two STUN servers: one which answers a binding request in nine different ways, most of them wrong on purpose, and one which can answer from somewhere else |
| `RNLTestNATNetwork.pas` | A `TRNLNetwork` decorator which behaves like a NAT, in four kinds |
| `RNLTestTURNServer.pas` | A TURN server complete enough to carry a connection over it |
| `RNLTestRegressions.pas` | The actual test cases |
| `checkalignment.py` | Checks that continuation lines line up under what they continue |

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
* a complete address change of one side, the way a NAT rebinding behaves
* rewriting a named field of an outgoing handshake packet, with the checksum recomputed so that the
  packet stays valid — which is what an attacker with the path in hand can do, and therefore the only
  way to show that a field is protected rather than merely present
* remembering the distinct source addresses of everything sent towards one address, which is how the
  fan out over several local sockets is observed from the outside

The deterministic variant is what makes timing assertions possible at all: losing one exactly
known datagram and then measuring the recovery is reproducible, whereas the total duration of
a bulk transfer under probabilistic loss varies by a factor of two between runs and is
dominated by the backoff rather than by the initial retransmission timeout.

The address change deliberately models all three parts of a real rebinding at once: the source
address of arriving datagrams changes, datagrams towards the new address reach the socket which
really sits behind it, and datagrams towards the old address are lost because that mapping is
gone. Leaving the last part out would make the old address stay reachable, and a counter side
which never notices the change would then keep working by accident — which is exactly the
situation a real network does not offer, and exactly why such a test would prove nothing.

## Why some tests drive a data structure directly

Most tests here run two hosts against each other, because that is where the interesting
behaviour lives. Two of them do not: they drive `TRNLBandwidthRateLimiter` and the connection
request rate limiter table directly, with no network at all.

That is deliberate. A rate limiter is a small amount of arithmetic over time, and the effect of
getting that arithmetic wrong is a plausible looking but wrong number rather than a visible
failure. Driving it directly makes the assertion exact, instant and free of any timing, whereas
observing the same defect through two hosts, a reliable channel and a retransmission timer takes
seconds and can be blamed on half a dozen other things.

The rule of thumb: assert on the smallest thing which can hold the defect. A test which drives
the whole stack in order to check one comparison is slower, flakier and says less about what
broke.

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

## The three servers, and why they are three

`RNLTestSTUNServer.pas` holds two classes and `RNLTestTURNServer.pas` a third. They look similar and
are deliberately not one.

`TRNLTestSTUNServer` exists to answer *wrongly*. Its nine behaviours are a truncated attribute, an
attribute longer than the datagram, a message length which is not a multiple of four, a foreign
transaction id, a wrong fingerprint, and so on. A parser for datagrams from a stranger is exactly where
a length field must not be believed, and the only way to show that it is not believed is to send
lengths which lie. That server therefore lays out its own bytes and cannot use the message layer of the
library — a correct builder is the one thing it must not have.

`TRNLTestSTUNBehaviourServer` is the opposite: it only ever sends correct messages, but it sends them
from four sockets, two addresses times two ports, which is what RFC 5780 needs of a server that is to
be usable for behaviour discovery. It is built on `TRNLSTUNMessage`, which is pinned against the RFC
5769 vector, so sharing that code with the library costs nothing here.

`TRNLTestTURNServer` speaks the part of RFC 8656 a client actually needs. Each allocation gets a socket
of its own, because that is what a relayed address is: an address a peer can send to which forwards to
exactly one client. Without that second socket the whole exercise would be a loopback and would prove
nothing about relaying.

## What the NAT simulator is for

Hole punching cannot be tested without something that behaves like a NAT, and the four kinds differ in
ways that matter: full cone, address restricted and port restricted differ only in what they let back
*in*, while symmetric also changes the address it hands *out*. `TRNLTestNATNetwork` implements all four
over the same mapping and permission tables, keyed by the full inside address.

That split is what makes the behaviour discovery testable at all. The three restricting kinds have to
come out with the same mapping behaviour and three different filtering behaviours; a detection which
confused the two halves would have to get at least one of them wrong.

## Two tests use real sockets

Almost everything here runs on `TRNLVirtualNetwork`, which is deterministic and needs no ports. Two
tests do not.

The first checks that a real socket reports the address it was actually bound to, which is a code path
the virtual network does not have.

The second carries a connection over a TURN relay reached by TCP. That one has no choice:
`TRNLVirtualNetwork` has no streams at all — its `SocketListen` returns false and its `SocketAccept`
returns nothing. Building TCP into it would be a good deal more work than a loopback socket pair, and a
real stack which segments where it likes is the better test anyway, since the whole question is whether
the framing survives arbitrary segmentation.

Both bind high ports on loopback. If those are occupied the test fails rather than hanging, but it is
worth knowing that this is the one place where the suite is not hermetic.

## Keeping the line alignment

`checkalignment.py` checks one thing: that a continuation line lines up under whatever it continues, so
that a parameter list wrapped over four lines stays readable. It is separate from the compiler because
no compiler cares, and it is worth having because a patch which inserts a line into a wrapped call is
the most common way for that alignment to rot.

```sh
cd src/tests
python3 checkalignment.py
```

It has to report no deviations before a change is done. A misalignment it finds is never a matter of
taste; it is always the result of an edit that moved something.
