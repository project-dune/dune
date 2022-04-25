#!/bin/sh

grep "\\b$1\\b" /proc/kallsyms | awk '{ print $1 }'
