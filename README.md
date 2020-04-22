# Fault-Tolerant Mix-net zeno

Prototype *zeno* is an Anonymous Communication System (ACS) that aims to keep one-to-one conversations private and
anonymous while tolerating Byzantine conditions. Based on a Chaumian mix-net architecture, zeno relays the
messages of conversing users across mixes determined in a bias-resistant way and with redundancy in space and time in
order to achieve a high level of fault tolerance. Our goal is to prevent Byzantine failures common to large-scale
Distributed Systems from rendering an ACS unavailable to its users, eventually forcing them to switch to less
privacy-preserving communication systems. We assess zeno's resource demands and end-to-end transmission latencies
in comparison to mix-net Vuvuzela and CPIR system Pung in a
[planet-scale public cloud evaluation](https://github.com/numbleroot/acs-eval-2019).

This repository holds the Go sources for prototype zeno as well as pseudo-code representations of the four primary
algorithms of our fault-tolerant mix-net proposal in [./algorithms](https://github.com/numbleroot/zeno/tree/master/algorithms).


### Academic Code Ahead

**Warning: This code is written for academic purposes only.** Handle with care, treat as insecure, and do not deploy
to end users. Feedback welcome.


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
