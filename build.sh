#!/bin/bash
# Serial message generation first (parallel make races on *_m.h), then build.
set +u
source "${OMNETPP_ROOT:-$(cd "$(dirname "$0")"/../.. && pwd)}/setenv" >/dev/null 2>&1
cd "$(dirname "$0")"
rm -f src/messages/NDNMessages_m.cc src/messages/NDNMessages_m.h
make MODE=release msgheaders >/dev/null && make MODE=release -j"$(nproc)" 2>&1 | grep -E "error|warning: unused" ; echo "build rc=${PIPESTATUS[0]}"
