# How to use

First build and insert the kernel module:

```
$ cd kern
$ sudo make
$ sudo insmod dune.ko
```

Note: unless you disable KASLR, you must rebuild Dune every time your computer
restarts.

If you make a change and rebuild, remove the kernel module with `sudo rmmod
dune` before re-inserting.

Next build libdune:

```
$ make -C libdune
```

Now you can run a test:

```
$ cd test
$ make hello
$ sudo ./hello
hello: not running dune yet
hello: now printing from dune mode
hello: caught divide by zero!
hello: recovered from divide by zero
```

If you run into an error, use `sudo dmesg` to show the kernel log, including
`printk` statements from inside the kernel module and backtraces for errors.

# Linux 5 support status.

So far Linux I have only tested on Linux 5.13.

## Features

* [ ] floating point support.

## Tests

* [x] `hello` passing.
* [x] `test` passing.
* [x] `fork` passing.
* [x] `test_sandbox` passing.
* [x] `timetest` passing.
* [ ] `mprotect` fails when attempting to print inside trap handler.

## Benchmarks

Benchmark performance is somewhat variable, but here is an example:

`bench_linux`:

```
TSC overhead is 21
Benchmarking Linux performance...
System call took 155 cycles
Kernel fault took 5042 cycles
User fault took 136030699 cycles
PROT1,TRAP,UNPROT took 493098 cycles
PROTN,TRAP,UNPROT took 478795 cycles
```

`bench_dune`:

```
TSC overhead is 22
Benchmarking dune performance...
System call took 3768 cycles
Kernel fault took 3845 cycles
User fault took 132713514 cycles
PROT1,TRAP,UNPROT took 62597 cycles
PROTN,TRAP,UNPROT took 62111 cycles
```

## Shared libraries

Shared library support is in progress on the `shared-dune` branch.

* [x] build position-independent `libdune.so`.
* [ ] running dune programs linked with `libdune.so`.
