#!/bin/bash
# Usage: run_campus.sh <config> [run-number] [extra opp args...]
ROOT="$(cd "$(dirname "$0")" && pwd)"
set +u
source "${OMNETPP_ROOT:-$(cd "$(dirname "$0")"/../.. && pwd)}/setenv" >/dev/null 2>&1
cd "$ROOT/simulations/campus"
mkdir -p results
CFG="$1"; RUN="$2"; shift; shift
exec "${OPP_BIN:-$ROOT/NDNPreEncryption}" -u Cmdenv -c "$CFG" ${RUN:+-r "$RUN"} "$@" \
  -n "$ROOT:$ROOT/../inet4.5/src:$ROOT/../simu5G/src" \
  -l "$ROOT/../inet4.5/src/INET" -l "$ROOT/../simu5G/src/simu5g" omnetpp.ini
