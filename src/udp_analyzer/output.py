from __future__ import annotations

import json
import sys
from typing import Optional, TextIO

from .models import UdpSample


TABLE_COLUMNS = [
    "ts",
    "layer",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "ifname",
    "process_name",
    "host_pid",
    "packets",
    "bytes",
]


def emit_samples(
    samples: list[UdpSample], output: str, stream: Optional[TextIO] = None
) -> None:
    stream = stream or sys.stdout
    if output == "none":
        return
    if output == "json":
        for sample in samples:
            print(json.dumps(sample.to_dict(), sort_keys=True), file=stream)
        return
    if output == "table":
        _emit_table(samples, stream)
        return
    raise ValueError(f"unsupported output mode: {output}")


def _emit_table(samples: list[UdpSample], stream: TextIO) -> None:
    if not samples:
        print("(no samples)", file=stream)
        return

    rows = []
    for sample in samples:
        data = sample.to_dict()
        rows.append([str(data[column]) for column in TABLE_COLUMNS])

    widths = [
        max(len(column), *(len(row[index]) for row in rows))
        for index, column in enumerate(TABLE_COLUMNS)
    ]
    header = "  ".join(
        column.ljust(widths[index]) for index, column in enumerate(TABLE_COLUMNS)
    )
    print(header, file=stream)
    print("  ".join("-" * width for width in widths), file=stream)
    for row in rows:
        print(
            "  ".join(value.ljust(widths[index]) for index, value in enumerate(row)),
            file=stream,
        )
