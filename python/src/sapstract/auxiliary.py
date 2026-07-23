"""SAP SSFS lock and instance-local key-file codecs."""

from __future__ import annotations

import hmac
import os
import struct
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from .errors import IntegrityError, KeyFileError, UnsupportedFormatError
from .lps import (
    LPSBlob,
    LPSProtection,
    LPSProtector,
    LPSUnprotector,
    RestrictionValidator,
)

LOCK_PREAMBLE = b"RSecSSFsLock"
LKY_PREAMBLE = b"RSecSSFsLKY"
LOCK_FILE_SIZE = 70
LKY_HEADER_SIZE = 76
LKY_MAX_PROTECTED_SIZE = 0x8000
MOCK_BEGIN = b"LPSMOCKBEGIN"
MOCK_END = b"LPSMOCKEND"


def _encode_identity(value: str, length: int, *, label: str) -> bytes:
    encoded = value.encode("utf-8")
    if len(encoded) > length:
        raise ValueError(f"{label} is longer than {length} encoded bytes")
    if b"\x00" in encoded:
        raise ValueError(f"{label} must not contain NUL bytes")
    return encoded.ljust(length, b" ")


def _decode_identity(value: bytes, *, label: str) -> str:
    try:
        return value.rstrip(b" \x00").decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise IntegrityError(f"{label} is not valid UTF-8") from exc


@dataclass(frozen=True)
class LockFile:
    """Structured ``SSFS_<SID>.LCK`` metadata."""

    file_type: int
    lock_type: int
    timestamp: int
    user: str
    host: str

    @classmethod
    def parse(cls, blob: bytes, *, strict: bool = True) -> "LockFile":
        if len(blob) != LOCK_FILE_SIZE:
            raise IntegrityError(
                f"SSFS lock file must be {LOCK_FILE_SIZE} bytes, got {len(blob)}"
            )
        if blob[:12] != LOCK_PREAMBLE:
            raise IntegrityError("invalid SSFS lock-file preamble")
        if strict and blob[12:14] != b"\x00\x00":
            raise UnsupportedFormatError(
                f"unsupported SSFS lock control bytes {blob[12:14].hex()}"
            )
        return cls(
            file_type=blob[12],
            lock_type=blob[13],
            timestamp=struct.unpack(">Q", blob[14:22])[0],
            user=_decode_identity(blob[22:46], label="lock user"),
            host=_decode_identity(blob[46:70], label="lock host"),
        )

    @classmethod
    def load(cls, path: Path, *, strict: bool = True) -> "LockFile":
        try:
            return cls.parse(path.read_bytes(), strict=strict)
        except OSError as exc:
            raise IntegrityError(f"unable to read SSFS lock file {path}: {exc}") from exc

    @classmethod
    def create(
        cls,
        *,
        user: str,
        host: str,
        timestamp: Optional[int] = None,
    ) -> "LockFile":
        return cls(0, 0, int(time.time()) if timestamp is None else timestamp, user, host)

    def to_bytes(self) -> bytes:
        if not 0 <= self.file_type <= 0xFF or not 0 <= self.lock_type <= 0xFF:
            raise ValueError("SSFS lock control values must fit in one byte")
        return b"".join(
            (
                LOCK_PREAMBLE,
                bytes((self.file_type, self.lock_type)),
                struct.pack(">Q", self.timestamp),
                _encode_identity(self.user, 24, label="lock user"),
                _encode_identity(self.host, 24, label="lock host"),
            )
        )


@dataclass(frozen=True)
class LocalKeyFile:
    """Instance-local ``SSFS_<SID>.LKY`` wrapper.

    ``implementation`` 1 contains a real LPS container. Implementation 0 is
    SAP's built-in unit-test mock and can only be unlocked with
    ``allow_mock=True``.
    """

    implementation: int
    timestamp: int
    user: str
    host: str
    protected_data: bytes
    crc32: bytes

    @property
    def implementation_name(self) -> str:
        return {0: "sap-lps-mock", 1: "local-protected-storage"}.get(
            self.implementation, f"unknown-{self.implementation}"
        )

    @property
    def protection(self) -> Optional[LPSProtection]:
        """Return the real LPS protection selector, if this is a real LKY."""

        lps = self.lps
        return lps.protection if lps is not None else None

    @property
    def mock_protection_marker(self) -> Optional[bytes]:
        if self.implementation != 0 or not self.protected_data.startswith(MOCK_BEGIN):
            return None
        offset = len(MOCK_BEGIN)
        return self.protected_data[offset : offset + 1]

    @property
    def uses_fallback(self) -> bool:
        """Whether the local KEK uses portable fallback protection."""

        if self.implementation == 1:
            return self.protection is LPSProtection.FALLBACK
        return self.mock_protection_marker == b"F"

    @classmethod
    def parse(cls, blob: bytes) -> "LocalKeyFile":
        if len(blob) < LKY_HEADER_SIZE:
            raise KeyFileError(
                f"SSFS LKY file is shorter than its {LKY_HEADER_SIZE}-byte header"
            )
        if blob[:11] != LKY_PREAMBLE:
            raise KeyFileError("invalid SSFS LKY-file preamble")
        implementation = blob[11]
        if implementation not in (0, 1):
            raise UnsupportedFormatError(
                f"unsupported SSFS LKY implementation marker {implementation}"
            )
        protected_length = struct.unpack(">I", blob[68:72])[0]
        if protected_length > LKY_MAX_PROTECTED_SIZE:
            raise UnsupportedFormatError(
                f"SSFS LKY protected payload exceeds {LKY_MAX_PROTECTED_SIZE} bytes"
            )
        if len(blob) != LKY_HEADER_SIZE + protected_length:
            raise KeyFileError(
                "SSFS LKY declared protected length does not match the file size"
            )
        protected_data = blob[LKY_HEADER_SIZE:]
        expected_crc = zlib.crc32(blob[:72] + protected_data).to_bytes(4, "big")
        if not hmac.compare_digest(blob[72:76], expected_crc):
            raise KeyFileError("SSFS LKY-file CRC32 is invalid")
        return cls(
            implementation=implementation,
            timestamp=struct.unpack(">Q", blob[12:20])[0],
            user=_decode_identity(blob[20:44], label="LKY user"),
            host=_decode_identity(blob[44:68], label="LKY host"),
            protected_data=protected_data,
            crc32=blob[72:76],
        )

    @classmethod
    def load(cls, path: Path) -> "LocalKeyFile":
        try:
            return cls.parse(path.read_bytes())
        except OSError as exc:
            raise KeyFileError(f"unable to read SSFS LKY file {path}: {exc}") from exc

    @property
    def lps(self) -> Optional[LPSBlob]:
        return LPSBlob.parse(self.protected_data) if self.implementation == 1 else None

    def unprotect(
        self,
        *,
        expected_context: Optional[bytes] = None,
        lps_unprotector: Optional[LPSUnprotector] = None,
        restriction_validator: Optional[RestrictionValidator] = None,
        allow_mock: bool = False,
    ) -> bytes:
        if self.implementation == 1:
            clear = LPSBlob.parse(self.protected_data).decrypt(
                expected_context=expected_context,
                lps_unprotector=lps_unprotector,
                restriction_validator=restriction_validator,
            )
        else:
            if not allow_mock:
                raise UnsupportedFormatError(
                    "SAP LPS mock LKY files are test fixtures; pass allow_mock=True explicitly"
                )
            if (
                len(self.protected_data) < len(MOCK_BEGIN) + 1 + len(MOCK_END)
                or not self.protected_data.startswith(MOCK_BEGIN)
                or not self.protected_data.endswith(MOCK_END)
            ):
                raise KeyFileError("invalid SAP LPS mock payload")
            mode = self.protected_data[len(MOCK_BEGIN) : len(MOCK_BEGIN) + 1]
            if mode not in (b"F", b"S"):
                raise UnsupportedFormatError(
                    f"unsupported SAP LPS mock protection marker {mode!r}"
                )
            clear = self.protected_data[len(MOCK_BEGIN) + 1 : -len(MOCK_END)]

        if len(clear) != 25:
            raise KeyFileError(
                f"SSFS LKY must decode to a 25-byte key compound, got {len(clear)}"
            )
        if clear[0] != 1:
            raise UnsupportedFormatError(
                f"unsupported SSFS LKY key-encryption-key type {clear[0]}"
            )
        return clear[1:]

    @classmethod
    def create(
        cls,
        key_encryption_key: bytes,
        *,
        sid: str,
        user: str,
        host: str,
        protection: LPSProtection = LPSProtection.FALLBACK,
        restriction: bytes = b"",
        version: int = 2,
        timestamp: Optional[int] = None,
        lps_protector: Optional[LPSProtector] = None,
        random_bytes: Callable[[int], bytes] = os.urandom,
    ) -> "LocalKeyFile":
        if len(key_encryption_key) != 24:
            raise ValueError("SSFS key-encryption keys must be exactly 24 bytes")
        context = f"SSFS_{sid.upper()}".encode("ascii")
        protected = LPSBlob.protect(
            b"\x01" + key_encryption_key,
            context=context,
            protection=protection,
            restriction=restriction,
            version=version,
            lps_protector=lps_protector,
            random_bytes=random_bytes,
        ).to_bytes()
        provisional = cls(
            implementation=1,
            timestamp=int(time.time()) if timestamp is None else timestamp,
            user=user,
            host=host,
            protected_data=protected,
            crc32=b"",
        )
        content = provisional._header_without_crc() + protected
        return cls(
            implementation=1,
            timestamp=provisional.timestamp,
            user=user,
            host=host,
            protected_data=protected,
            crc32=zlib.crc32(content).to_bytes(4, "big"),
        )

    @classmethod
    def create_fallback(
        cls,
        key_encryption_key: bytes,
        *,
        sid: str,
        user: str,
        host: str,
        timestamp: Optional[int] = None,
        random_bytes: Callable[[int], bytes] = os.urandom,
    ) -> "LocalKeyFile":
        """Create a real LPS portable-fallback LKY."""

        return cls.create(
            key_encryption_key,
            sid=sid,
            user=user,
            host=host,
            protection=LPSProtection.FALLBACK,
            timestamp=timestamp,
            random_bytes=random_bytes,
        )

    def _header_without_crc(self) -> bytes:
        return b"".join(
            (
                LKY_PREAMBLE,
                bytes((self.implementation,)),
                struct.pack(">Q", self.timestamp),
                _encode_identity(self.user, 24, label="LKY user"),
                _encode_identity(self.host, 24, label="LKY host"),
                struct.pack(">I", len(self.protected_data)),
            )
        )

    def to_bytes(self) -> bytes:
        if len(self.protected_data) > LKY_MAX_PROTECTED_SIZE:
            raise ValueError(
                f"SSFS LKY protected payload exceeds {LKY_MAX_PROTECTED_SIZE} bytes"
            )
        header = self._header_without_crc()
        expected_crc = zlib.crc32(header + self.protected_data).to_bytes(4, "big")
        if self.crc32 and not hmac.compare_digest(self.crc32, expected_crc):
            raise KeyFileError("refusing to serialize an SSFS LKY with an invalid CRC32")
        return header + expected_crc + self.protected_data


__all__ = [
    "LKY_PREAMBLE",
    "LOCK_PREAMBLE",
    "LPSProtection",
    "LPSProtector",
    "LocalKeyFile",
    "LockFile",
]
