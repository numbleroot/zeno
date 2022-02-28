# Fault-Tolerant Mix-net zeno


## Note on Name and Scope of Repository

This repository holds the source code for mixnet *zeno*, which we used under changed name *FTMix* as a
proof-of-concept mixnet with reliability features at its core in our publication
["Strong Anonymity is not Enough: Introducing Fault Tolerance to Planet-Scale Anonymous Communication Systems"](https://dl.acm.org/doi/10.1145/3465481.3469189)
(FARES Workshop 2022).

Please mind that while zeno comes with organizational protocols such as VDF-style mix rotations (emulated
as `scrypt` calls) intended to reduce the fallout from mix compromise, we do not explain, evaluate, or
discuss these features in the publication. The scope of the ultimately published article narrowed over
time from presenting both aspects (increased fault tolerance and decreased required infrastructure trust)
to only the fault tolerance aspects. We rely only on reliability and general system metrics for FTMix in
the evaluation metrics used in the final publication (e.g., end-to-end transmission latencies across
multiple independent cascades with message transmissions in two consecutive rounds), and make no claims
about lowered infrastructure trust requirements.

Please keep this in mind when reading, running, or modifying this source code artifact, and read "FTMix"
when you see "zeno" in this code.


## Introduction

Prototype *zeno* is an Anonymous Communication System (ACS) that aims to keep one-to-one conversations private and
anonymous while tolerating Byzantine conditions. Based on a Chaumian mix-net architecture, zeno relays the
messages of conversing users across mixes determined in a bias-resistant way and with redundancy in space and time in
order to achieve a high level of fault tolerance. Our goal is to prevent Byzantine failures common to large-scale
Distributed Systems from rendering an ACS unavailable to its users, which may eventually force them to switch to less
privacy-preserving communication systems. We assess zeno's resource demands and end-to-end transmission latencies
in comparison to mix-net Vuvuzela and CPIR system Pung in a
[planet-scale public cloud evaluation](https://github.com/numbleroot/acs-eval-2019).

This repository holds the Go sources for prototype zeno as well as pseudo-code representations of the four primary
algorithms of our fault-tolerant mix-net proposal in [./algorithms](https://github.com/numbleroot/zeno/tree/master/algorithms).


### Academic Code Ahead

**Warning: This code is written for academic purposes only.** Handle with care, treat as insecure, and do not deploy
to end users.


## Setup

Clone the repository and change into the newly created directory. Assuming you have a working Go installation on
your machine, run:
```
$ make
```

This will create the zeno executable. See the supported arguments:
```
$ ./zeno -help
```


## Relied-Upon Third Party Libraries

This source code artifact does not work without the help of:
* [`github.com/capnproto/go-capnproto2`](https://github.com/capnproto/go-capnproto2): Cap'n Proto data interchange format, bindings for Go, [license](https://github.com/capnproto/go-capnproto2/blob/cd831da3dc6103dbab14ea35458a2517e4cd0343/LICENSE)
* [`golang.org/x/crypto`](https://cs.opensource.google/go/x/crypto): Google's supplementary cryptographic libraries for Go, [license](https://cs.opensource.google/go/x/crypto/+/master:LICENSE;drc=a1a18262106c9dba0a8e319d02983a41ca82f3e3)
