# Fault-Tolerant Anonymous Communication System zeno

Fault-tolerant mix-net *zeno* to keep conversations private and anonymous. This repository holds the Go sources
for zeno as well as pseudo-code representations of the four main algorithms of our fault-tolerant mix-net proposal
in [./algorithms](https://github.com/numbleroot/zeno/tree/master/algorithms).


### Academic Code Ahead

**Warning:** This code is written for academic purposes only. Handle with care, treat as insecure, do not deploy
to end users. Feedback welcome.


## Setup

Clone the repository and change into the newly created directory. Assuming you have a working Go installation on
your machine, run:
```
$ make
```

This will create the desired executable. See the supported flags:
```
$ ./zeno -help
```
