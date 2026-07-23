"""Read-only, non-secret inspection of SAP SSFS file-family members."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional, Union

from .auxiliary import LKY_PREAMBLE, LOCK_PREAMBLE, LocalKeyFile, LockFile
from .format import DATA_PREAMBLE, KEY_PREAMBLE, KeyFileMetadata, parse_records


@dataclass(frozen=True)
class FileInspection:
    """A JSON-friendly structural view which never contains decrypted values."""

    path: str
    size: int
    sha256: str
    kind: str
    recognized: bool
    valid: bool
    details: dict[str, object]
    error: Optional[str] = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _record_details(blob: bytes) -> dict[str, object]:
    records = parse_records(blob)
    return {
        "record_count": len(records),
        "active_count": sum(not record.deleted for record in records),
        "defunct_count": sum(record.deleted for record in records),
        "records": [
            {
                "index": index,
                "key": record.key_name,
                "timestamp": record.timestamp,
                "user": record.user,
                "host": record.host,
                "status": "defunct" if record.deleted else "active",
                "storage": "plaintext" if record.plaintext else "encrypted",
                "binary": record.binary,
                "stored_length": len(record.data),
                "integrity": record.sap_integrity_valid,
                "compacting_audit": record.is_compacting_audit,
            }
            for index, record in enumerate(records)
        ],
    }


def _key_details(blob: bytes) -> dict[str, object]:
    metadata = KeyFileMetadata.parse(blob)
    return {
        "key_type": metadata.key_type,
        "timestamp": metadata.timestamp,
        "user": metadata.user,
        "host": metadata.host,
        "protection": metadata.protection,
        "key_encryption_type": metadata.key_encryption_type,
        "global_key_mode": metadata.global_key_mode,
        "wrapped_length": metadata.wrapped_length,
        "crc_valid": metadata.crc_valid,
        "salt_length": len(metadata.salt),
    }


def _local_key_details(blob: bytes) -> dict[str, object]:
    local = LocalKeyFile.parse(blob)
    details: dict[str, object] = {
        "implementation": local.implementation_name,
        "timestamp": local.timestamp,
        "user": local.user,
        "host": local.host,
        "protected_length": len(local.protected_data),
        "crc_valid": True,
    }
    lps = local.lps
    if lps is not None:
        details.update(
            {
                "lps_version": lps.version,
                "lps_protection": lps.protection.name.lower(),
                "lps_context": lps.context.decode(
                    "ascii", errors="backslashreplace"
                ),
                "lps_restriction_length": len(lps.restriction),
                "lps_encrypted_key_length": len(lps.encrypted_key),
                "lps_encrypted_data_length": len(lps.encrypted_data),
                "lps_crc_valid": True,
            }
        )
    return details


def _lock_details(blob: bytes) -> dict[str, object]:
    lock = LockFile.parse(blob, strict=False)
    return {
        "file_type": lock.file_type,
        "lock_type": lock.lock_type,
        "timestamp": lock.timestamp,
        "user": lock.user,
        "host": lock.host,
        "canonical_control": lock.file_type == 0 and lock.lock_type == 0,
    }


def inspect_ssfs_file(
    path: Union[str, Path],
    *,
    lenient: bool = False,
) -> FileInspection:
    """Identify and parse one SSFS file without resolving or revealing a key.

    Strict mode raises format errors. Lenient mode returns the detected kind,
    prefix, digest, and parse error so an unknown or damaged artifact can be
    triaged without allowing it into operational store APIs.
    """

    source = Path(path)
    blob = source.read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if not blob and source.suffix.upper() in {".DAT", ".DA_"}:
        kind, parser = "data", _record_details
    elif blob.startswith(DATA_PREAMBLE):
        kind, parser = "data", _record_details
    elif blob.startswith(KEY_PREAMBLE):
        kind, parser = "key", _key_details
    elif blob.startswith(LKY_PREAMBLE):
        kind, parser = "local-key", _local_key_details
    elif blob.startswith(LOCK_PREAMBLE):
        kind, parser = "lock", _lock_details
    else:
        return FileInspection(
            str(source),
            len(blob),
            digest,
            "unknown",
            False,
            False,
            {"prefix_hex": blob[:16].hex()},
            "unrecognized SSFS preamble",
        )

    try:
        details = parser(blob)
    except Exception as exc:
        if not lenient:
            raise
        return FileInspection(
            str(source),
            len(blob),
            digest,
            kind,
            True,
            False,
            {"prefix_hex": blob[:16].hex()},
            str(exc),
        )
    return FileInspection(
        str(source),
        len(blob),
        digest,
        kind,
        True,
        True,
        details,
    )


__all__ = ["FileInspection", "inspect_ssfs_file"]
