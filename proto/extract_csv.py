#!/usr/bin/env python3
# save as extract_payload_any.py

import csv
import sys
import argparse
from typing import List, Tuple

def sniff_dialect(path: str) -> csv.Dialect:
    with open(path, 'r', encoding='utf-8-sig', newline='') as f:
        sample = f.read(8192)
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=[',',';','\t','|',':'])
        dialect.doublequote = True
        return dialect
    except Exception:
        return csv.excel

def read_rows(path: str, dialect: csv.Dialect) -> List[List[str]]:
    rows = []
    with open(path, 'r', encoding='utf-8-sig', newline='') as f:
        r = csv.reader(f, dialect)
        for row in r:
            rows.append(row)
    return rows

def extract_by_column_header(rows: List[List[str]], header_key: str) -> Tuple[List[str], str]:
    if not rows:
        return [], "no_rows"
    header = rows[0]
    # find payload column case-insensitively, trimmed
    idx = None
    for i, h in enumerate(header):
        if (h or "").strip().lower() == header_key:
            idx = i; break
    if idx is None:
        return [], "no_header_match"
    vals = []
    for row in rows[1:]:
        if idx < len(row):
            v = (row[idx] or "").strip()
            if v != "":
                vals.append(v)
    return vals, f"header='{header[idx]}' idx={idx} count={len(vals)}"

def extract_by_row_label(rows: List[List[str]], row_key: str) -> Tuple[List[str], str]:
    out = []
    info = []
    for r_i, row in enumerate(rows):
        for c_i, cell in enumerate(row):
            if (cell or "").strip().lower() == row_key:
                rest = [ (x or "").strip() for x in row[c_i+1:] if (x or "").strip() != "" ]
                # if nothing to the right, try classic key,value in first two cells
                if not rest and c_i == 0 and len(row) >= 2:
                    v = (row[1] or "").strip()
                    if v:
                        rest = [v]
                if rest:
                    out.extend(rest)
                    info.append(f"row={r_i} col={c_i} extracted={len(rest)}")
                else:
                    info.append(f"row={r_i} col={c_i} found_key_but_no_values")
                break
    return out, "; ".join(info) if info else "no_row_match"

def extract_by_any_contains(rows: List[List[str]], needle: str) -> Tuple[List[str], str]:
    # find rows that contain the word and dump the rest of the row (excluding the matching cell)
    out = []
    hits = []
    for r_i, row in enumerate(rows):
        lc = [ (c or "").lower() for c in row ]
        if any(needle in c for c in lc):
            # take everything after the first matching cell; if none, take entire row minus matches
            try:
                first_idx = next(i for i,c in enumerate(lc) if needle in c)
            except StopIteration:
                continue
            rest = [ (x or "").strip() for x in row[first_idx+1:] if (x or "").strip() != "" ]
            if not rest:
                # fallback: take other cells that do not contain the needle
                rest = [ (x or "").strip() for i,x in enumerate(row) if needle not in lc[i] and (x or "").strip() != "" ]
            if rest:
                out.extend(rest)
            hits.append(f"row={r_i}, cols={len(row)}, grabbed={len(rest)}")
    return out, ("; ".join(hits) if hits else "no_contains_match")

def write_items(items: List[str], path: str):
    with open(path, 'w', encoding='utf-8') as f:
        if len(items) <= 1:
            f.write(items[0] if items else "")
        else:
            for x in items:
                f.write(x + "\n")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input_csv")
    ap.add_argument("output_txt")
    ap.add_argument("--mode", choices=["column","row","any"], default="any",
                   help="column: header named 'payload'; row: a cell equals 'payload'; any: any cell contains 'payload'")
    ap.add_argument("--key", default="payload", help="label or header to search (lowercased compare)")
    args = ap.parse_args()

    dialect = sniff_dialect(args.input_csv)
    rows = read_rows(args.input_csv, dialect)

    items, detail = [], ""
    if args.mode == "column":
        items, detail = extract_by_column_header(rows, args.key.lower())
    elif args.mode == "row":
        items, detail = extract_by_row_label(rows, args.key.lower())
    else:
        # try column -> row -> contains
        items, detail = extract_by_column_header(rows, args.key.lower())
        print(f"[try] column: {detail} -> {len(items)} items")
        if not items:
            items, detail = extract_by_row_label(rows, args.key.lower())
            print(f"[try] row: {detail} -> {len(items)} items")
        if not items:
            items, detail = extract_by_any_contains(rows, args.key.lower())
            print(f"[try] contains: {detail} -> {len(items)} items")

    write_items(items, args.output_txt)
    print(f"[done] wrote {len(items)} item(s) to {args.output_txt}")

if __name__ == "__main__":
    main()