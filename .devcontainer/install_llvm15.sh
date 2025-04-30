#!/bin/bash
set -e
cd /opt
tar -xvf clang+llvm-15.0.0-x86_64-linux-gnu-rhel-8.4.tar.xz
rm -rf clang+llvm-15.0.0-x86_64-linux-gnu-rhel-8.4.tar.xz
mv clang+llvm-15.0.0-x86_64-linux-gnu-rhel-8.4 llvm15
