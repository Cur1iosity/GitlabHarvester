#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterator, TextIO


def iter_json_objects(fp: TextIO) -> Iterator[dict[str, Any]]:
    """
    Incremental decoder that supports:
      - JSONL (one object per line)
      - multi-line pretty JSON objects (indent=2)

    Yields decoded JSON objects one by one.
    """
    decoder = json.JSONDecoder()
    buf = ""

    for chunk in fp:
        buf += chunk
        while True:
            buf = buf.lstrip()
            if not buf:
                break
            try:
                obj, idx = decoder.raw_decode(buf)
            except json.JSONDecodeError:
                break  # need more data

            yield obj
            buf = buf[idx:]

    if buf.strip():
        raise ValueError("Trailing data could not be decoded as JSON.")


def convert_jsonl_to_json(
    input_path: Path,
    output_path: Path,
    sort_keys: bool = False,
) -> None:
    """
    Convert JSONL (or multi-line JSON objects) into a single
    human-readable JSON array.

    The result will be:

    [
      {...},
      {...},
      ...
    ]
    """
    objects: list[Any] = []

    with input_path.open("r", encoding="utf-8") as fin:
        for obj in iter_json_objects(fin):
            objects.append(obj)

    with output_path.open("w", encoding="utf-8") as fout:
        json.dump(
            objects,
            fout,
            ensure_ascii=False,
            sort_keys=sort_keys,
        )

    print(f"[convert] input : {input_path}")
    print(f"[convert] output: {output_path}")
    print(f"[convert] objects: {len(objects)}")

