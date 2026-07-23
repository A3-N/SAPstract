"""Command-line interface for :mod:`sapstract`."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Optional

from . import __version__
from .errors import SSFSError
from .inspection import inspect_ssfs_file
from .scc import SCC_PASSWORD_RECORD, get_scc_password, put_scc_password
from .store import KeyMode, SSFSStore


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sapstract",
        description="Dependency-free Python 3 tooling for SAP SSFS stores",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--sid", help="SAP system name; defaults to SAPSYSTEMNAME")
    parser.add_argument("--data-path", help="directory containing SSFS_<SID>.DAT")
    parser.add_argument("--key-path", help="directory containing SSFS_<SID>.KEY")
    parser.add_argument(
        "--lky-path",
        help="directory containing SSFS_<SID>.LKY; defaults to the key directory",
    )
    parser.add_argument(
        "--registration-password-file",
        help="read an enhanced-SSFS registration password from this protected file",
    )
    parser.add_argument(
        "--allow-mock-lps",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--key-mode",
        choices=tuple(mode.value for mode in KeyMode),
        help=(
            "master-key policy; defaults to individual (or RSEC_SSFS_KEYMODE); "
            "default must be selected explicitly for known no-.KEY stores"
        ),
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON where supported")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="initialize an empty store")
    init.add_argument(
        "--key-mode",
        dest="init_key_mode",
        choices=tuple(mode.value for mode in KeyMode),
        help="key policy for the new store; defaults to individual",
    )
    init.add_argument("--clear-key-file", action="store_true", help="write legacy type-1 key instead of type-2")
    init.add_argument(
        "--enhanced-fallback",
        action="store_true",
        help="write an enhanced standalone type-2 KEY plus portable LPS v2 LKY",
    )

    put = commands.add_parser("put", help="append or replace a record")
    put.add_argument("key")
    put.add_argument("value", nargs="?", help="UTF-8 value; omit when using --value-file")
    put.add_argument("--value-file", help="read bytes from a file, or '-' for standard input")
    put.add_argument("--plain", action="store_true", help="store without encryption")
    put.add_argument("--binary", action="store_true", help="mark value as binary")
    put.add_argument("--scc-text", action="store_true", help="encode text as SCC-compatible UTF-16LE binary")

    get = commands.add_parser("get", help="read a record")
    get.add_argument("key")
    get.add_argument("--output", help="write value to a file, or '-' for standard output")
    get.add_argument("--reveal", action="store_true", help="print a text value to standard output")
    get.add_argument("--scc-text", action="store_true", help="decode the value from SCC UTF-16LE")

    listing = commands.add_parser("list", help="list records without revealing values")
    listing.add_argument("--history", action="store_true", help="include defunct records")

    commands.add_parser("info", help="show paths, key mode, and record counts")

    validate = commands.add_parser("validate", help="validate record HMACs and encrypted payload hashes")
    validate.add_argument("--no-decrypt", action="store_true", help="only validate outer record HMACs")

    remove = commands.add_parser("remove", help="mark an active record as deleted")
    remove.add_argument("key")
    commands.add_parser("compact", help="remove defunct record history")

    change = commands.add_parser("changekey", help="reencrypt all encrypted records with a new key")
    change.add_argument("key", nargs="?", help="48 hexadecimal characters; random when omitted")
    change.add_argument("--clear-key-file", action="store_true", help="write legacy type-1 key instead of type-2")

    generate = commands.add_parser("generatekey", help="generate a random 24-byte master key")
    generate.add_argument("--raw", action="store_true", help="write raw bytes instead of hexadecimal")

    commands.add_parser("removelock", help="remove a stale SSFS .LCK file")

    inspect = commands.add_parser(
        "inspect",
        help="identify a DAT/KEY/LKY/LCK file without revealing values",
    )
    inspect.add_argument("file")
    inspect.add_argument(
        "--lenient",
        action="store_true",
        help="report damaged/unknown structure instead of failing",
    )

    scc_put = commands.add_parser("scc-put", help="store the SCC Java-keystore password")
    scc_put.add_argument("password", nargs="?", help="placeholder or real password")
    scc_put.add_argument("--value-file", help="read UTF-8 password text from a file or '-' for stdin")

    scc_get = commands.add_parser("scc-get", help="read the SCC Java-keystore password")
    scc_get.add_argument("--output", help="write UTF-8 text to a file or '-' for stdout")

    return parser


def _configured_store(args: argparse.Namespace) -> SSFSStore:
    sid = args.sid or os.environ.get("SAPSYSTEMNAME")
    data_path = args.data_path or os.environ.get("RSEC_SSFS_DATAPATH")
    key_path = args.key_path or os.environ.get("RSEC_SSFS_KEYPATH") or data_path
    lky_path = args.lky_path or os.environ.get("RSEC_SSFS_LKYPATH") or key_path
    if not sid:
        raise ValueError("SID is required via --sid or SAPSYSTEMNAME")
    if not data_path:
        raise ValueError("data path is required via --data-path or RSEC_SSFS_DATAPATH")
    global_key_mode = args.key_mode
    init_key_mode = getattr(args, "init_key_mode", None)
    if global_key_mode and init_key_mode and global_key_mode != init_key_mode:
        raise ValueError("conflicting global and init --key-mode values")
    key_mode = (
        init_key_mode
        or global_key_mode
        or os.environ.get("RSEC_SSFS_KEYMODE")
        or KeyMode.INDIVIDUAL.value
    )
    registration_password = None
    if args.registration_password_file:
        password_path = Path(args.registration_password_file)
        registration_password = password_path.read_bytes().rstrip(b"\r\n")
        if not registration_password:
            raise ValueError("registration-password file is empty")
    return SSFSStore(
        sid,
        data_path,
        key_path,
        lky_path=lky_path,
        key_mode=key_mode,
        registration_password=registration_password,
        allow_mock_lps=args.allow_mock_lps,
    )


def _read_value(value: Optional[str], value_file: Optional[str]) -> bytes:
    if value_file is not None:
        if value is not None:
            raise ValueError("provide either a positional value or --value-file, not both")
        return sys.stdin.buffer.read() if value_file == "-" else Path(value_file).read_bytes()
    if value is None:
        raise ValueError("a value or --value-file is required")
    return value.encode("utf-8")


def _write_value(value: bytes, destination: Optional[str]) -> None:
    if destination in (None, "-"):
        sys.stdout.buffer.write(value)
        if destination is None and not value.endswith(b"\n"):
            sys.stdout.buffer.write(b"\n")
        return
    path = Path(destination)
    path.write_bytes(value)
    os.chmod(path, 0o600)


def _key_from_hex(value: Optional[str]) -> bytes:
    if value is None:
        return secrets.token_bytes(24)
    try:
        key = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("master key must contain only hexadecimal characters") from exc
    if len(key) == 24:
        return key
    # SAP rsecssfx generatekey emits a 29-byte portable envelope: subtype 1,
    # the 24-byte SSFS master key, and a repeated two-byte check value.  The
    # native changekey command also accepts the raw 24-byte form.
    if len(key) == 29 and key[0] == 1 and key[25:27] == key[27:29]:
        return key[1:25]
    raise ValueError(
        "master key must be 48 hexadecimal characters or a 58-character SAP generatekey envelope"
    )


def _record_row(record, index: int) -> dict[str, object]:
    return {
        "index": index,
        "key": record.key_name,
        "status": "deleted" if record.deleted else "active",
        "storage": "plaintext" if record.plaintext else "encrypted",
        "binary": record.binary,
        "timestamp": record.timestamp,
        "user": record.user,
        "host": record.host,
        "integrity": record.sap_integrity_valid,
    }


def _dispatch(args: argparse.Namespace) -> int:
    if args.command == "generatekey":
        value = secrets.token_bytes(24)
        sys.stdout.buffer.write(value if args.raw else value.hex().upper().encode("ascii"))
        return 0

    if args.command == "inspect":
        result = inspect_ssfs_file(args.file, lenient=args.lenient)
        if args.json:
            print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        else:
            print(f"path: {result.path}")
            print(f"kind: {result.kind}")
            print(f"recognized: {result.recognized}")
            print(f"valid: {result.valid}")
            print(f"size: {result.size}")
            print(f"sha256: {result.sha256}")
            for key, value in result.details.items():
                print(f"{key}: {value}")
            if result.error:
                print(f"error: {result.error}")
        return 0 if result.valid else 3

    store = _configured_store(args)

    if args.command == "init":
        store.data_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        store.key_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        store.lky_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if (
            store.data_file.exists()
            or store.key_file.exists()
            or store.local_key_file.exists()
        ):
            raise ValueError(
                "store material already exists; use put or changekey instead of init"
            )
        if args.clear_key_file and args.enhanced_fallback:
            raise ValueError(
                "--clear-key-file and --enhanced-fallback are mutually exclusive"
            )
        if args.enhanced_fallback and store.configured_key_mode is not KeyMode.INDIVIDUAL:
            raise ValueError("--enhanced-fallback requires individual key mode")
        if store.configured_key_mode is KeyMode.INDIVIDUAL:
            key_file = (
                store.initialize_enhanced_key()
                if args.enhanced_fallback
                else store.initialize_individual_key(
                    key_type=1 if args.clear_key_file else 2
                )
            )
            print(f"Initialized {store.sid} with {key_file.protection} individual key")
        else:
            print(f"Initialized {store.sid} in DEFAULT-KEY OBFUSCATION mode (development only)")
        return 0

    if args.command == "put":
        value = _read_value(args.value, args.value_file)
        binary = args.binary
        if args.scc_text:
            value = value.decode("utf-8").encode("utf-16le")
            binary = True
        record = store.put(args.key, value, plaintext=args.plain, binary=binary)
        print(f"Stored {record.key_name}: {'plaintext' if record.plaintext else 'encrypted'}")
        return 0

    if args.command == "get":
        value = store.get(args.key)
        if args.scc_text:
            value = value.decode("utf-16le").encode("utf-8")
        if args.output is not None:
            _write_value(value, args.output)
        elif args.reveal:
            _write_value(value, None)
        else:
            record = store.get_record(args.key)
            print(
                f"Record {record.key_name}: {'plaintext' if record.plaintext else 'encrypted'}, "
                f"{len(value)} decoded bytes (use --reveal or --output to emit the value)"
            )
        return 0

    if args.command == "list":
        records = store.records(history=args.history)
        rows = [_record_row(record, index) for index, record in enumerate(records)]
        if args.json:
            print(json.dumps(rows, indent=2, sort_keys=True))
        else:
            for row in rows:
                binary = ", binary" if row["binary"] else ""
                print(f"{row['key']}\t{row['status']}\t{row['storage']}{binary}\tintegrity={row['integrity']}")
        return 0

    if args.command == "info":
        info = store.info()
        if args.json:
            print(json.dumps(info, indent=2, sort_keys=True))
        else:
            for key, value in info.items():
                print(f"{key}: {value}")
        return 0

    if args.command == "validate":
        results = store.validate(decrypt=not args.no_decrypt)
        if args.json:
            print(json.dumps([result.__dict__ for result in results], indent=2, sort_keys=True))
        else:
            for result in results:
                detail = f" ({result.error})" if result.error else ""
                print(f"{result.key_name}[{result.record_index}]: {'OK' if result.valid else 'INVALID'}{detail}")
        return 0 if all(result.valid for result in results) else 3

    if args.command == "remove":
        store.remove(args.key)
        print(f"Removed {args.key}")
        return 0

    if args.command == "compact":
        print(f"Removed {store.compact()} defunct record(s)")
        return 0

    if args.command == "changekey":
        key_file = store.change_key(_key_from_hex(args.key), key_type=1 if args.clear_key_file else 2)
        print(f"Changed master key using {key_file.protection}")
        return 0

    if args.command == "removelock":
        print("Removed stale lock" if store.remove_lock() else "No lock file exists")
        return 0

    if args.command == "scc-put":
        password = _read_value(args.password, args.value_file).decode("utf-8").rstrip("\r\n")
        put_scc_password(store, password)
        print(f"Stored {SCC_PASSWORD_RECORD}: encrypted SCC UTF-16LE binary")
        return 0

    if args.command == "scc-get":
        value = get_scc_password(store).encode("utf-8")
        if args.output is None:
            print(f"Decoded SCC password is {len(value)} UTF-8 bytes (use --output to emit it)")
        else:
            _write_value(value, args.output)
        return 0

    raise AssertionError(f"unhandled command {args.command}")


def main(argv: Optional[list[str]] = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return _dispatch(args)
    except (SSFSError, OSError, UnicodeError, ValueError) as exc:
        parser.exit(2, f"{parser.prog}: error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
