#!/bin/bash

# dev: --compilation_mode=dbg
# release: --compilation_mode=opt
# build targets:
# - dev.bin                  - build service binaries
# - release.bin              - build service binaries

BUILD_TARGET=${1-"release.bin"}
if [ $# -lt 2 ]; then
    CLI_DEFINES=""
else
    CLI_DEFINES=${@:2}
fi

echo "INFO: build target: $BUILD_TARGET"
echo "INFO: extra cli defines: $CLI_DEFINES"

CLI_CMODE=
CLI_JOBS="--jobs=16"
REMOTE_CACHE=""

COPY="install -C -m 644"
COPYBIN="install -C -m 755"
COPYDIR="/bin/cp -L -u -r"
FORCE_COPYDIR="/bin/cp -r"
REMOVE="/usr/bin/rm -rf"
bazel_cache_dir="/$HOME/.cache/bazel"

if [ "$(uname)" == "Darwin" ];then
    # Mac OSX
    echo "platform: MAC"
    COPY="/bin/cp"
    COPYBIN="install -C -m 755"
    COPYDIR="/bin/cp -L -r"
    FORCE_COPYDIR="/bin/cp -r"
    REMOVE="/bin/rm -rf"
fi

function copy_binaries() {
    echo "INFO: copying all binaries..."
    mkdir -p ./bin 2>/dev/null
    $COPYBIN bazel-bin/dtvm bin/
    $COPYBIN bazel-bin/libzetaengine.a bin/
    if [ -f bazel-bin/ircompiler ]; then
        $COPYBIN bazel-bin/ircompiler bin/
    fi
}

function do_build() {
    # fetch mychain_cpp_thirdparty as local bazel registry
    python3 create_local_bazel_registry.py
    # build with mychain_cpp_thirdparty as local bazel registry
    bazel_registry="--registry=file://$(pwd)/.local_bazel_registry --registry=https://bcr.bazel.build"
    local target=$1
    echo "INFO: bazel build --verbose_failures $CLI_CMODE $CLI_DEFINES $CLI_JOBS $REMOTE_CACHE ${bazel_registry} $target"
    bazel build --verbose_failures $CLI_CMODE $CLI_DEFINES $CLI_JOBS $REMOTE_CACHE ${bazel_registry} $target
}

case "$BUILD_TARGET" in
"dev.bin")
    CLI_CMODE="--compilation_mode=dbg --copt=-O0"
    do_build :bin
    test $? -eq 0 && { copy_binaries; }
    ;;

"release.bin")
    CLI_CMODE="--compilation_mode=opt"
    do_build :bin
    test $? -eq 0 && { copy_binaries; }
    ;;

"release.lib")
    CLI_CMODE="--compilation_mode=opt  --copt=\"-fPIE\""
    do_build :zetaengine
    do_build utils_lib
    do_build @zen_deps_asmjit//:asmjit
    test $? -eq 0 && { copy_binaries; }
    ;;

"compile_db")
    CLI_CMODE="--compilation_mode=fastbuild"
    outfile="bazel-out/k8-fastbuild/bin/compile_commands.json"
    rm -f compile_commands.json
    rm -f ${outfile}
    do_build //:compile_db
    execroot=$(bazel info execution_root)
    sed -i.bak "s@__EXEC_ROOT__@${execroot}@" "${outfile}"
    mv ${outfile} . || true
    echo "Compilation Database: ${outfile}"
    ;;

*)
    echo "unknown build mode"
    exit 1
    ;;

esac
