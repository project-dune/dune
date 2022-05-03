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

So far I have only tested on Linux 5.13.

I have attempted to keep the git history clean so it is clear what has been
changed to bring Dune more up-to-date. Note: I have applied an autoformatter to
increase coding style consistency throughout the codebase. Make sure to check
individual commit diffs rather than the overall diff to avoid looking at
changes introduced by the autoformatter.

## Features

* [ ] floating point support.
    * Problem: https://lkml.iu.edu/hypermail/linux/kernel/1902.2/04786.html

## Tests

* [x] `hello` passing.
* [x] `test` passing.
* [x] `fork` passing.
* [x] `test_sandbox` passing.
* [x] `timetest` passing.
* [ ] `mprotect` fails when attempting to print inside trap handler.
    * Fails with error (for example):

    ```
    ept: failed to get user page 7ffe5e191ff0
    vmx: page fault failure GPA: 0x7fde191ff0, GVA: 0x7ffe5e191ff0
    RSP 0x00007ffe5e191bc8
    ```

    Note this stack pointer is outside the stack pagemap.

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

Shared library support is in progress on the `dune-so` branch.

* [x] build position-independent `libdune.so`.
* [ ] running dune programs linked with `libdune.so`.
    * Fails during VM entry, displaying: `unhandled exit: reason -2147483615,
      exit qualification 0`.
