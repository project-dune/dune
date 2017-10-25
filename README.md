# DUNE

----
# Overview

Dune is a system that lets you safely run applications in Ring 0 by using
hardware virtualization.  This lets applications access privileged CPU features
and do things like change their own page table, register interrupt handlers and
more, while still being able to perform normal system calls.  More information
is available here:

https://github.com/project-dune

This work was published on OSDI'12:

http://dl.acm.org/citation.cfm?id=2387913

Dune has two components:

1. A kernel module to enable virtualization (kern)
2. A utility library to help with using Dune (libdune)

We also provide an optional patched glibc (eglibc-2.14). It slightly
improves system call performance by performing a VMCALL directly.
If used, it does not need to be installed globally.

Dune is enabled only on applications that call `dune_init()`. All other
applications on the system remain unaffected.

The directory layout of this archive is as follows:

* kern/    -> the Dune kernel module
* libdune/ -> the Dune library OS
* bench/   -> a series of benchmarks to compare Dune and Linux performance
* test/    -> simple test programs and examples
* sandbox/ -> a generic implementation for sandboxing untrusted binaries

----
# Requirements

* A 64-bit x86 Linux environment
* A recent Intel CPU (we use Nehalem and later) with VT-x support.
* A recent kernel version --- We use 3.0 and later, but earlier versions
  may also work.
* Kernel headers must be installed for the running kernel.

We provide a script called `dune_req.sh` that will attempt to verify
if these requirements are met.

----
# Setup

```
$ make
# insmod kern/dune.ko
# test/hello
```

You'll need to be root to load the module. However, applications can use
Dune without running as root; simply change the permission of '/dev/dune'
accordingly.

Another program worth trying after Dune is setup is the Dune benchmark suite.
It can be run with the following command:

```
$ make -C bench
# bench/bench_dune
```

Run the following command to build a faster version of glibc (optional):

```
# make libc
```

If eglibc build fails some systems (e.g. Ubuntu) may have incompatible default
CFLAGS set.  Before running the libc build set the following flags.

```
# setenv CFLAGS "-U_FORTIFY_SOURCE -O2 -fno-stack-protector"
```

The alternate glibc can be used by prefixing dune apps with the
`dune_env.sh` script.

----
# Limitations

Dune is fairly far along, but could benefit from better support for signals
and more robust pthread support inside libdune. We're currently working on
these issues.

Dune does not support kernel address space layout randomization (KASLR). For
newer kernels, you must specify the nokaslr parameter in the kernel command
line. Check before inserting the module by executing `cat /proc/cmdline`. If
the command line does not include the nokaslr parameter, then you must add it.
In order to add it in Ubuntu-based distributions, you must:

* edit the file `/etc/default/grub`,
* append `nokaslr` in the `GRUB_CMDLINE_LINUX_DEFAULT` option,
* execute `sudo grub-mkconfig -o /boot/grub/grub.cfg`, and
* reboot the system.

As an alternative solution, you can add a new entry in your grub2 files with
the `nokaslr` flag. Edit the file `/etc/grub.d/40_custom` as described below:

```
menuentry "Kernel nokaslr" {
    search --set=root --fs-uuid XXXX-XXXX
    linux /vmlinuz-linux root=UUID=YYYY-YYYY ro quiet splash nokaslr
    initrd /initramfs-linux.img
}

```

Keep in mind that you have to adapt the above file to your system. For
example:

* XXXX-XXXX should be the UUID wherein /boot directory is located
* YYYY-YYYY the UUID wherein / directory is located
* kernel/initrd should match yours system name (look at /boot/). 

Finally, update your grub and reboot.

```
sudo grub-mkconfig -o /boot/grub/grub.cfg
```
----
# Programming

1. Call `dune_init()` to enter dune mode.  (Link to libdune.)
2. The application will continue to function as normal.  You can use printf,
   use sockets, access files, etc.
3. But you can then also perform privileged CPU instructions.

----
# Contributing

Found a bug and know how to fix it? Not sure if that small improvement is
worth a pull request? Do it! It will be greatly appreciated.

However, any significant improvement or change should be documented as a
GitHub issue before anybody starts working on it.

----
# Questions?

Contact us at project-dune@googlegroups.com.

Last edited: 10/24/17
