"""Binary codecs used by sapstract for SAP SSFS records and key files."""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
import zlib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable, Iterable, Optional, Union

from .auxiliary import LocalKeyFile
from .crypto import (
    DEFAULT_KEY_ENCRYPTION_KEY,
    RSEC_KEY_SIZE,
    record_hmac,
    rsec_decrypt,
    rsec_encrypt,
    unwrap_individual_key,
    wrap_individual_key,
)
from .errors import IntegrityError, KeyFileError, UnsupportedFormatError
from .lps import LPSUnprotector, RestrictionValidator

DATA_PREAMBLE = b"RSecSSFsData"
KEY_PREAMBLE = b"RSecSSFsKey"
LOCK_PREAMBLE = b"RSecSSFsLock"
COMPACTING_AUDIT_KEY = "RSECSSFS/COMPACTING_AUDIT"
RECORD_HEADER_SIZE = 176
MAX_RECORD_SIZE = 0x18150
PAYLOAD_HEADER_SIZE = 32
PAYLOAD_QUANTUM = 128
TYPE2_CONTROL = (b"\x00" * 37) + b"\x39"
TYPE2_CONTROL_SIZE = 38
TYPE2_ENCRYPTED_KEY_SIZE = 57
KEY_ENCRYPTION_COMPILED = 0
KEY_ENCRYPTION_ENHANCED = 1
KEY_GLOBAL_MODE_NAMES = {
    0: "enhanced-fallback-disallowed",
    1: "enhanced-fallback-allowed",
    3: "enhanced-standalone",
}


def _pad_field(value: str, length: int, *, name: str) -> bytes:
    encoded = value.encode("utf-8")
    if len(encoded) > length:
        raise ValueError(f"{name} is longer than {length} encoded bytes")
    if b"\x00" in encoded:
        raise ValueError(f"{name} must not contain NUL bytes")
    return encoded.ljust(length, b" ")


def _read_field(value: bytes) -> str:
    return value.rstrip(b" \x00").decode("utf-8", errors="strict")


def derive_registration_key(
    password: Union[str, bytes],
    salt: bytes,
) -> bytes:
    """Derive an enhanced-SSFS key-encryption key from a registration password."""

    if isinstance(password, str):
        try:
            password_bytes = password.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("SSFS registration passwords must contain ASCII only") from exc
    else:
        password_bytes = password
    if not password_bytes:
        raise ValueError("SSFS registration password must not be empty")
    if len(salt) != 32:
        raise ValueError("enhanced SSFS registration salts must be exactly 32 bytes")
    return hashlib.pbkdf2_hmac("sha1", password_bytes, salt, 10_000, dklen=24)


@dataclass(frozen=True)
class KeyFileMetadata:
    """Non-secret structural view of an SSFS ``.KEY`` file."""

    key_type: int
    timestamp: int
    user: str
    host: str
    key_encryption_type: Optional[int] = None
    global_key_mode: Optional[int] = None
    salt: bytes = b""
    wrapped_length: int = 0
    crc_valid: Optional[bool] = None

    @property
    def protection(self) -> str:
        if self.key_type == 1:
            return "clear"
        if self.key_type != 2:
            return f"unsupported-key-type-{self.key_type}"
        if self.key_encryption_type == KEY_ENCRYPTION_COMPILED:
            return "compiled-key-obfuscation"
        if self.key_encryption_type == KEY_ENCRYPTION_ENHANCED:
            return KEY_GLOBAL_MODE_NAMES.get(
                self.global_key_mode,
                f"enhanced-unknown-mode-{self.global_key_mode}",
            )
        return f"unsupported-key-encryption-{self.key_encryption_type}"

    @classmethod
    def parse(cls, blob: bytes) -> "KeyFileMetadata":
        if len(blob) < 12 or blob[:11] != KEY_PREAMBLE:
            raise KeyFileError("invalid SSFS key-file preamble")
        key_type = blob[11]
        if key_type == 1:
            if len(blob) != 92:
                raise KeyFileError(
                    f"type-1 SSFS key file must be 92 bytes, got {len(blob)}"
                )
            return cls(
                key_type=1,
                timestamp=struct.unpack(">Q", blob[36:44])[0],
                user=_read_field(blob[44:68]),
                host=_read_field(blob[68:92]),
            )
        if key_type != 2:
            # Unknown types do not have a sufficiently established layout to
            # claim timestamp/identity fields.
            return cls(key_type, 0, "", "")
        if len(blob) != 187:
            raise KeyFileError(
                f"type-2 SSFS key file must be 187 bytes, got {len(blob)}"
            )
        control = blob[68:106]
        encrypted_length = struct.unpack(">I", control[34:38])[0]
        expected_crc = zlib.crc32(blob[:126] + blob[130:]).to_bytes(4, "big")
        return cls(
            key_type=2,
            timestamp=struct.unpack(">Q", blob[12:20])[0],
            user=_read_field(blob[20:44]),
            host=_read_field(blob[44:68]),
            key_encryption_type=control[0],
            salt=control[1:33],
            global_key_mode=control[33],
            wrapped_length=encrypted_length,
            crc_valid=hmac.compare_digest(blob[126:130], expected_crc),
        )


@dataclass(frozen=True)
class KeyFile:
    """Decoded ``SSFS_<SID>.KEY`` file.

    Type 1 stores the 24-byte master key directly. Type 2 stores it using
    SAP's reversible compiled-key or enhanced key-encryption key. Enhanced
    keys can be resolved by a registration password or a matching ``.LKY``;
    host-bound LKY protection still requires its platform provider.
    """

    key_type: int
    master_key: bytes
    timestamp: int
    user: str
    host: str
    type2_control: bytes = b""
    key_mac: bytes = b""
    crc32: bytes = b""
    wrapped_key: bytes = b""
    key_encryption_type: int = KEY_ENCRYPTION_COMPILED
    salt: bytes = b""
    global_key_mode: int = 0
    key_encryption_key: bytes = field(default=b"", repr=False)

    @property
    def protection(self) -> str:
        if self.key_type == 1:
            return "clear"
        if self.key_encryption_type == KEY_ENCRYPTION_COMPILED:
            return "compiled-key-obfuscation"
        return KEY_GLOBAL_MODE_NAMES.get(
            self.global_key_mode,
            f"enhanced-unknown-mode-{self.global_key_mode}",
        )

    @classmethod
    def parse(
        cls,
        blob: bytes,
        *,
        registration_password: Optional[Union[str, bytes]] = None,
        local_key: Optional[Union[LocalKeyFile, bytes]] = None,
        expected_lps_context: Optional[bytes] = None,
        lps_unprotector: Optional[LPSUnprotector] = None,
        restriction_validator: Optional[RestrictionValidator] = None,
        allow_mock_lps: bool = False,
    ) -> "KeyFile":
        if len(blob) < 12 or blob[:11] != KEY_PREAMBLE:
            raise KeyFileError("invalid SSFS key-file preamble")
        key_type = blob[11]
        if key_type == 1:
            if len(blob) != 92:
                raise KeyFileError(f"type-1 SSFS key file must be 92 bytes, got {len(blob)}")
            return cls(
                key_type=1,
                master_key=blob[12:36],
                timestamp=struct.unpack(">Q", blob[36:44])[0],
                user=_read_field(blob[44:68]),
                host=_read_field(blob[68:92]),
            )
        if key_type == 2:
            if len(blob) != 187:
                raise KeyFileError(f"type-2 SSFS key file must be 187 bytes, got {len(blob)}")
            control = blob[68:106]
            wrapped = blob[130:187]
            encrypted_length = struct.unpack(">I", control[34:38])[0]
            if encrypted_length != TYPE2_ENCRYPTED_KEY_SIZE:
                raise KeyFileError(
                    "type-2 SSFS key-file encrypted length is "
                    f"{encrypted_length}, expected {TYPE2_ENCRYPTED_KEY_SIZE}"
                )

            key_encryption_type = control[0]
            salt = control[1:33]
            global_key_mode = control[33]
            if key_encryption_type == KEY_ENCRYPTION_COMPILED:
                if control != TYPE2_CONTROL:
                    raise UnsupportedFormatError(
                        "type-2 SSFS compiled-key control fields are not canonical"
                    )
                key_encryption_key = DEFAULT_KEY_ENCRYPTION_KEY
            elif key_encryption_type == KEY_ENCRYPTION_ENHANCED:
                if global_key_mode not in KEY_GLOBAL_MODE_NAMES:
                    raise UnsupportedFormatError(
                        f"unsupported enhanced SSFS global key mode {global_key_mode}"
                    )
                candidates: list[bytes] = []
                if registration_password is not None:
                    candidates.append(derive_registration_key(registration_password, salt))
                if local_key is not None:
                    local = (
                        LocalKeyFile.parse(local_key)
                        if isinstance(local_key, bytes)
                        else local_key
                    )
                    if global_key_mode == 0 and local.uses_fallback:
                        raise KeyFileError(
                            "enhanced SSFS global policy disallows fallback LPS, "
                            "but the supplied LKY uses fallback protection"
                        )
                    candidates.append(
                        local.unprotect(
                            expected_context=expected_lps_context,
                            lps_unprotector=lps_unprotector,
                            restriction_validator=restriction_validator,
                            allow_mock=allow_mock_lps,
                        )
                    )
                if not candidates:
                    raise KeyFileError(
                        "enhanced type-2 SSFS key requires a registration password or "
                        "matching SSFS_<SID>.LKY"
                    )
                key_encryption_key = candidates[0]
                for candidate in candidates[1:]:
                    if not hmac.compare_digest(candidate, key_encryption_key):
                        raise KeyFileError(
                            "registration password and LKY resolve to different "
                            "key-encryption keys"
                        )
            else:
                raise UnsupportedFormatError(
                    f"unsupported type-2 SSFS key-encryption type {key_encryption_type}"
                )
            expected_mac = hmac.new(
                key_encryption_key, blob[:106] + wrapped, hashlib.sha1
            ).digest()
            if not hmac.compare_digest(blob[106:126], expected_mac):
                raise KeyFileError("type-2 SSFS key-file HMAC-SHA1 is invalid")
            expected_crc = zlib.crc32(blob[:126] + wrapped).to_bytes(4, "big")
            if not hmac.compare_digest(blob[126:130], expected_crc):
                raise KeyFileError("type-2 SSFS key-file CRC32 is invalid")
            try:
                master_key = unwrap_individual_key(
                    wrapped, key_encryption_key=key_encryption_key
                )
            except ValueError as exc:
                raise KeyFileError("invalid wrapped master key") from exc
            return cls(
                key_type=2,
                master_key=master_key,
                timestamp=struct.unpack(">Q", blob[12:20])[0],
                user=_read_field(blob[20:44]),
                host=_read_field(blob[44:68]),
                type2_control=control,
                key_mac=blob[106:126],
                crc32=blob[126:130],
                wrapped_key=wrapped,
                key_encryption_type=key_encryption_type,
                salt=salt,
                global_key_mode=global_key_mode,
                key_encryption_key=key_encryption_key,
            )
        raise UnsupportedFormatError(
            f"unsupported SSFS key-file type {key_type}"
        )

    @classmethod
    def load(
        cls,
        path: Path,
        *,
        registration_password: Optional[Union[str, bytes]] = None,
        local_key: Optional[Union[LocalKeyFile, bytes]] = None,
        expected_lps_context: Optional[bytes] = None,
        lps_unprotector: Optional[LPSUnprotector] = None,
        restriction_validator: Optional[RestrictionValidator] = None,
        allow_mock_lps: bool = False,
    ) -> "KeyFile":
        try:
            return cls.parse(
                path.read_bytes(),
                registration_password=registration_password,
                local_key=local_key,
                expected_lps_context=expected_lps_context,
                lps_unprotector=lps_unprotector,
                restriction_validator=restriction_validator,
                allow_mock_lps=allow_mock_lps,
            )
        except OSError as exc:
            raise KeyFileError(f"unable to read key file {path}: {exc}") from exc

    @classmethod
    def create_with_registration_password(
        cls,
        master_key: bytes,
        registration_password: Union[str, bytes],
        *,
        user: str,
        host: str,
        timestamp: Optional[int] = None,
        allow_fallback_lps: bool = False,
        random_bytes: Callable[[int], bytes] = os.urandom,
    ) -> "KeyFile":
        """Create an enhanced KEY whose KEK is derived from a password.

        This creates the global KEY only. Registering an instance still means
        protecting the resulting KEK in a matching local LKY through SAP or
        :meth:`LocalKeyFile.create`.
        """

        salt = random_bytes(32)
        if len(salt) != 32:
            raise ValueError("random source returned the wrong registration-salt length")
        key_encryption_key = derive_registration_key(registration_password, salt)
        return cls.create(
            master_key,
            user=user,
            host=host,
            timestamp=timestamp,
            key_encryption_key=key_encryption_key,
            registration_salt=salt,
            global_key_mode=1 if allow_fallback_lps else 0,
            random_bytes=random_bytes,
        )

    @classmethod
    def create(
        cls,
        master_key: bytes,
        *,
        user: str,
        host: str,
        timestamp: Optional[int] = None,
        key_type: int = 2,
        key_encryption_key: Optional[bytes] = None,
        registration_salt: Optional[bytes] = None,
        global_key_mode: int = 0,
        random_bytes: Callable[[int], bytes] = os.urandom,
    ) -> "KeyFile":
        if len(master_key) != RSEC_KEY_SIZE:
            raise ValueError("SSFS master keys must be exactly 24 bytes")
        timestamp = int(time.time()) if timestamp is None else timestamp
        if key_type == 1:
            return cls(1, master_key, timestamp, user, host)
        if key_type == 2:
            if key_encryption_key is None:
                resolved_kek = DEFAULT_KEY_ENCRYPTION_KEY
                control = TYPE2_CONTROL
                encryption_type = KEY_ENCRYPTION_COMPILED
                salt = b"\x00" * 32
                mode = 0
            else:
                if len(key_encryption_key) != RSEC_KEY_SIZE:
                    raise ValueError("SSFS key-encryption keys must be exactly 24 bytes")
                if registration_salt is None or len(registration_salt) != 32:
                    raise ValueError(
                        "enhanced SSFS key files require a 32-byte registration salt"
                    )
                if global_key_mode not in KEY_GLOBAL_MODE_NAMES:
                    raise ValueError(
                        f"unsupported enhanced SSFS global key mode {global_key_mode}"
                    )
                resolved_kek = key_encryption_key
                salt = registration_salt
                mode = global_key_mode
                encryption_type = KEY_ENCRYPTION_ENHANCED
                control = (
                    bytes((encryption_type,))
                    + salt
                    + bytes((mode,))
                    + struct.pack(">I", TYPE2_ENCRYPTED_KEY_SIZE)
                )
            wrapped = wrap_individual_key(
                master_key,
                key_encryption_key=resolved_kek,
                random_bytes=random_bytes,
            )
            return cls(
                2,
                master_key,
                timestamp,
                user,
                host,
                type2_control=control,
                wrapped_key=wrapped,
                key_encryption_type=encryption_type,
                salt=salt,
                global_key_mode=mode,
                key_encryption_key=resolved_kek,
            )
        raise UnsupportedFormatError(f"cannot create SSFS key type {key_type}")

    def to_bytes(self) -> bytes:
        if len(self.master_key) != RSEC_KEY_SIZE:
            raise KeyFileError("decoded master key is not 24 bytes")
        if self.key_type == 1:
            return b"".join(
                (
                    KEY_PREAMBLE,
                    b"\x01",
                    self.master_key,
                    struct.pack(">Q", self.timestamp),
                    _pad_field(self.user, 24, name="key-file user"),
                    _pad_field(self.host, 24, name="key-file host"),
                )
            )
        if self.key_type == 2:
            control = self.type2_control or TYPE2_CONTROL
            key_encryption_key = (
                self.key_encryption_key
                or (
                    DEFAULT_KEY_ENCRYPTION_KEY
                    if self.key_encryption_type == KEY_ENCRYPTION_COMPILED
                    else b""
                )
            )
            if len(key_encryption_key) != RSEC_KEY_SIZE:
                raise KeyFileError(
                    "enhanced type-2 SSFS key cannot be serialized without its "
                    "24-byte key-encryption key"
                )
            wrapped = self.wrapped_key or wrap_individual_key(
                self.master_key,
                key_encryption_key=key_encryption_key,
            )
            if len(control) != TYPE2_CONTROL_SIZE or len(wrapped) != TYPE2_ENCRYPTED_KEY_SIZE:
                raise KeyFileError("invalid type-2 SSFS key-file field lengths")
            if self.key_encryption_type == KEY_ENCRYPTION_COMPILED:
                if control != TYPE2_CONTROL:
                    raise KeyFileError("invalid compiled-key type-2 control fields")
            elif (
                control[0] != KEY_ENCRYPTION_ENHANCED
                or control[1:33] != self.salt
                or control[33] != self.global_key_mode
                or struct.unpack(">I", control[34:38])[0] != TYPE2_ENCRYPTED_KEY_SIZE
            ):
                raise KeyFileError("invalid enhanced type-2 control fields")
            header = b"".join(
                (
                    KEY_PREAMBLE,
                    b"\x02",
                    struct.pack(">Q", self.timestamp),
                    _pad_field(self.user, 24, name="key-file user"),
                    _pad_field(self.host, 24, name="key-file host"),
                    control,
                )
            )
            key_mac = hmac.new(
                key_encryption_key, header + wrapped, hashlib.sha1
            ).digest()
            crc32 = zlib.crc32(header + key_mac + wrapped).to_bytes(4, "big")
            return header + key_mac + crc32 + wrapped
        raise UnsupportedFormatError(f"cannot encode SSFS key type {self.key_type}")


@dataclass(frozen=True)
class DecryptedPayload:
    preamble: bytes
    value: bytes
    padding: bytes
    digest: bytes

    @classmethod
    def parse(cls, blob: bytes) -> "DecryptedPayload":
        if len(blob) < PAYLOAD_HEADER_SIZE:
            raise IntegrityError("decrypted SSFS payload is shorter than 32 bytes")
        length = struct.unpack(">I", blob[8:12])[0]
        value_end = PAYLOAD_HEADER_SIZE + length
        if value_end > len(blob):
            raise IntegrityError("decrypted SSFS payload declares an impossible value length")
        expected = hashlib.sha1(blob[:12] + blob[32:]).digest()
        if not hmac_compare(blob[12:32], expected):
            raise IntegrityError("decrypted SSFS payload SHA-1 is invalid (wrong key or tampering)")
        return cls(blob[:8], blob[32:value_end], blob[value_end:], blob[12:32])

    @classmethod
    def create(
        cls,
        value: bytes,
        *,
        random_bytes: Callable[[int], bytes] = os.urandom,
    ) -> "DecryptedPayload":
        total = PAYLOAD_HEADER_SIZE + len(value)
        padded_total = ((total + PAYLOAD_QUANTUM - 1) // PAYLOAD_QUANTUM) * PAYLOAD_QUANTUM
        if padded_total == 0:
            padded_total = PAYLOAD_QUANTUM
        preamble = random_bytes(8)
        padding = random_bytes(padded_total - total)
        length = struct.pack(">I", len(value))
        digest = hashlib.sha1(preamble + length + value + padding).digest()
        return cls(preamble, value, padding, digest)

    def to_bytes(self) -> bytes:
        return self.preamble + struct.pack(">I", len(self.value)) + self.digest + self.value + self.padding


@dataclass(frozen=True)
class CompactingAudit:
    """Decoded payload of SAP's internal compacting-audit record."""

    timestamp: int
    user: str
    host: str
    removed_total: int
    removed_last: int

    @classmethod
    def parse(cls, blob: bytes) -> "CompactingAudit":
        if len(blob) != 64:
            raise IntegrityError(f"compacting-audit payload must be 64 bytes, got {len(blob)}")
        return cls(
            timestamp=struct.unpack(">Q", blob[:8])[0],
            user=_read_field(blob[8:32]),
            host=_read_field(blob[32:56]),
            removed_total=struct.unpack(">I", blob[56:60])[0],
            removed_last=struct.unpack(">I", blob[60:64])[0],
        )

    def to_bytes(self) -> bytes:
        return b"".join(
            (
                struct.pack(">Q", self.timestamp),
                _pad_field(self.user, 24, name="compacting-audit user"),
                _pad_field(self.host, 24, name="compacting-audit host"),
                struct.pack(">I", self.removed_total),
                struct.pack(">I", self.removed_last),
            )
        )


def hmac_compare(left: bytes, right: bytes) -> bool:
    # Kept local to make all integrity comparisons constant-time without a
    # third-party package.
    import hmac

    return hmac.compare_digest(left, right)


@dataclass(frozen=True)
class Record:
    key_name: str
    timestamp: int
    user: str
    host: str
    deleted: bool
    plaintext: bool
    binary: bool
    data: bytes
    mac: bytes = b""
    record_type: int = 1
    filler1: bytes = b"\x00" * 7
    filler2: bytes = b"\x00" * 9

    @classmethod
    def parse(cls, blob: bytes) -> "Record":
        if len(blob) < RECORD_HEADER_SIZE:
            raise IntegrityError("SSFS record is shorter than its 176-byte header")
        if blob[:12] != DATA_PREAMBLE:
            raise IntegrityError("invalid SSFS data-record preamble")
        declared = struct.unpack(">I", blob[12:16])[0]
        if declared != len(blob):
            raise IntegrityError(f"SSFS record length is {declared}, received {len(blob)}")
        if not RECORD_HEADER_SIZE <= declared <= MAX_RECORD_SIZE:
            raise UnsupportedFormatError(f"unsupported SSFS record length {declared}")
        if blob[16] != 1:
            raise UnsupportedFormatError(f"unsupported SSFS record type {blob[16]}")
        if blob[17:24] != b"\x00" * 7:
            raise UnsupportedFormatError("SSFS record has non-zero reserved record-header bytes")
        if any(flag not in (0, 1) for flag in blob[144:147]):
            raise UnsupportedFormatError("SSFS record has a non-Boolean status flag")
        key_name = _read_field(blob[24:88])
        filler2 = blob[147:156]
        is_compacting_audit = (
            key_name == COMPACTING_AUDIT_KEY
            and blob[144:147] == b"\x00\x01\x01"
            and filler2 == b"\x01" + (b"\x00" * 8)
            and len(blob[176:]) == 64
        )
        if filler2 != b"\x00" * 9 and not is_compacting_audit:
            raise UnsupportedFormatError("SSFS record has unsupported data-header control bytes")
        return cls(
            key_name=key_name,
            timestamp=struct.unpack(">Q", blob[88:96])[0],
            user=_read_field(blob[96:120]),
            host=_read_field(blob[120:144]),
            deleted=bool(blob[144]),
            plaintext=bool(blob[145]),
            binary=bool(blob[146]),
            data=blob[176:],
            mac=blob[156:176],
            record_type=blob[16],
            filler1=blob[17:24],
            filler2=filler2,
        )

    @property
    def is_compacting_audit(self) -> bool:
        return (
            self.key_name == COMPACTING_AUDIT_KEY
            and not self.deleted
            and self.plaintext
            and self.binary
            and self.filler2 == b"\x01" + (b"\x00" * 8)
            and len(self.data) == 64
        )

    @property
    def compacting_audit(self) -> Optional[CompactingAudit]:
        return CompactingAudit.parse(self.data) if self.is_compacting_audit else None

    @property
    def integrity_valid(self) -> bool:
        return hmac_compare(self.mac, record_hmac(self._authenticated_bytes()))

    @property
    def historical_integrity_valid(self) -> bool:
        """Validate the way SAP validates defunct record history.

        SAP marks an old version defunct by changing byte 0x90 from zero to
        one without replacing the original MAC. Therefore a deleted record is
        authentic when its MAC validates after restoring that byte to the
        former active value.
        """
        if not self.deleted:
            return self.integrity_valid
        former_active = replace(self, deleted=False)
        return hmac_compare(self.mac, record_hmac(former_active._authenticated_bytes()))

    @property
    def sap_integrity_valid(self) -> bool:
        return self.integrity_valid or self.historical_integrity_valid

    def _data_header_without_mac(self) -> bytes:
        return b"".join(
            (
                _pad_field(self.key_name, 64, name="record key"),
                struct.pack(">Q", self.timestamp),
                _pad_field(self.user, 24, name="record user"),
                _pad_field(self.host, 24, name="record host"),
                bytes((int(self.deleted), int(self.plaintext), int(self.binary))),
                self.filler2,
            )
        )

    def _authenticated_bytes(self) -> bytes:
        return self._data_header_without_mac() + self.data

    def to_bytes(self) -> bytes:
        total_length = RECORD_HEADER_SIZE + len(self.data)
        if total_length > MAX_RECORD_SIZE:
            raise ValueError(f"record exceeds SAP's {MAX_RECORD_SIZE}-byte limit")
        # Preserve the active-state MAC when serializing a defunct version;
        # this is the history representation emitted by SAP rsecssfx.
        if self.deleted and self.mac and self.historical_integrity_valid:
            mac = self.mac
        else:
            mac = record_hmac(self._authenticated_bytes())
        return b"".join(
            (
                DATA_PREAMBLE,
                struct.pack(">I", total_length),
                bytes((self.record_type,)),
                self.filler1,
                self._data_header_without_mac(),
                mac,
                self.data,
            )
        )

    def with_deleted(self, deleted: bool = True) -> "Record":
        return replace(self, deleted=deleted)

    def decrypt_value(self, master_key: bytes) -> bytes:
        if not self.sap_integrity_valid:
            raise IntegrityError(f"record {self.key_name!r} has an invalid HMAC-SHA1")
        if self.plaintext:
            return self.data
        if len(self.data) == 0 or len(self.data) % PAYLOAD_QUANTUM:
            raise IntegrityError(
                f"record {self.key_name!r} has a non-canonical encrypted payload length"
            )
        try:
            payload = DecryptedPayload.parse(rsec_decrypt(self.data, master_key))
        except ValueError as exc:
            raise IntegrityError(f"record {self.key_name!r} cannot be decrypted") from exc
        return payload.value

    @classmethod
    def create(
        cls,
        key_name: str,
        value: bytes,
        *,
        master_key: Optional[bytes] = None,
        plaintext: bool = False,
        binary: bool = False,
        user: str,
        host: str,
        timestamp: Optional[int] = None,
        random_bytes: Callable[[int], bytes] = os.urandom,
    ) -> "Record":
        timestamp = int(time.time()) if timestamp is None else timestamp
        _pad_field(key_name, 64, name="record key")
        if plaintext:
            encoded = value
        else:
            if master_key is None:
                raise ValueError(
                    "master_key is required for encrypted records; pass a store-resolved key "
                    "or DEFAULT_DATA_KEY explicitly for a known default-key store"
                )
            encoded = rsec_encrypt(
                DecryptedPayload.create(value, random_bytes=random_bytes).to_bytes(), master_key
            )
        record = cls(
            key_name=key_name,
            timestamp=timestamp,
            user=user,
            host=host,
            deleted=False,
            plaintext=plaintext,
            binary=binary,
            data=encoded,
        )
        # Parse the result once to make construction obey the same invariants as
        # untrusted input and to retain the computed MAC.
        return cls.parse(record.to_bytes())


def parse_records(blob: bytes) -> list[Record]:
    records: list[Record] = []
    offset = 0
    while offset < len(blob):
        if len(blob) - offset < 16:
            raise IntegrityError(f"trailing {len(blob) - offset} bytes after the last SSFS record")
        if blob[offset : offset + 12] != DATA_PREAMBLE:
            raise IntegrityError(f"invalid SSFS record preamble at offset 0x{offset:x}")
        length = struct.unpack(">I", blob[offset + 12 : offset + 16])[0]
        if length < RECORD_HEADER_SIZE or length > MAX_RECORD_SIZE:
            raise IntegrityError(f"invalid SSFS record length {length} at offset 0x{offset:x}")
        end = offset + length
        if end > len(blob):
            raise IntegrityError(f"truncated SSFS record at offset 0x{offset:x}")
        records.append(Record.parse(blob[offset:end]))
        offset = end
    return records


def serialize_records(records: Iterable[Record]) -> bytes:
    return b"".join(record.to_bytes() for record in records)
