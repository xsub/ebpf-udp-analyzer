#!/usr/bin/env sh
set -eu

ports="${FFMPEG_PORTS:-5000 5001 5002}"

for port in $ports; do
    ffmpeg \
        -hide_banner \
        -loglevel warning \
        -nostdin \
        -i "udp://0.0.0.0:${port}?fifo_size=1000000&overrun_nonfatal=1" \
        -f null - &
done

wait

