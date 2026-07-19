#!/usr/bin/env sh
set -eu

collector="${1:-dry-run}"
duration="${DURATION:-3}"
bucket_ms="${BUCKET_MS:-1000}"
output_dir="${OUTPUT_DIR:-data/harness}"
output_file="${OUTPUT_FILE:-$output_dir/udp_samples.ndjson}"
sqlite_file="${SQLITE_FILE:-$output_dir/udp_samples.sqlite}"

mkdir -p "$output_dir"

if [ "$collector" = "dry-run" ]; then
    PYTHONPATH=src python3 -m udp_analyzer run \
        --collector dry-run \
        --watch \
        --duration "$duration" \
        --bucket-ms "$bucket_ms" \
        --output json \
        --storage sqlite \
        --db-path "$sqlite_file" \
        > "$output_file"

    PYTHONPATH=src python3 harness/assert_output.py \
        --input "$output_file" \
        --profile dry-run
elif [ "$collector" = "ebpf" ]; then
    if [ -z "${DURATION+x}" ]; then
        duration=6
    fi
    interface="${INTERFACE:-}"
    if [ -z "$interface" ]; then
        interface="$(ip route show default | awk '/default/ {print $5; exit}')"
    fi

    make -C bpf

    PYTHONPATH=src python3 -m udp_analyzer run \
        --collector ebpf \
        --interface "$interface" \
        --watch \
        --duration "$duration" \
        --bucket-ms "$bucket_ms" \
        --output json \
        --storage sqlite \
        --db-path "$sqlite_file" \
        > "$output_file" &

    analyzer_pid=$!

    if [ "${GENERATE_DNS:-1}" = "1" ]; then
        sleep 1
        dns_target="${DNS_TARGET:-}"
        if [ -z "$dns_target" ]; then
            dns_target="$(awk '$1 == "nameserver" && $2 ~ /^[0-9.]+$/ {print $2; exit}' /etc/resolv.conf 2>/dev/null || true)"
        fi
        if [ -z "$dns_target" ]; then
            dns_target="192.0.2.53"
        fi
        python3 -c 'import random,socket,sys
target = sys.argv[1]
name = sys.argv[2]
tid = random.randrange(65536).to_bytes(2, "big")
qname = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00"
query = tid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x01\x00\x01"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)
sock.sendto(query, (target, 53))
sock.recvfrom(512)
' "$dns_target" "${DNS_NAME:-example.com}" || true
    fi

    wait "$analyzer_pid"

    PYTHONPATH=src python3 harness/assert_output.py \
        --input "$output_file" \
        --profile ebpf \
        ${ALLOW_EMPTY_EBPF:+--allow-empty}
else
    echo "unknown collector: $collector" >&2
    exit 2
fi

echo "output: $output_file"
echo "sqlite: $sqlite_file"
