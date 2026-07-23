"""High-level sapstract SSFS store API with locked, recoverable mutations."""

from __future__ import annotations

import getpass
import os
import re
import shutil
import socket
import stat
import tempfile
import time
from contextlib import AbstractContextManager
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Iterable, Optional, Union

from .auxiliary import LocalKeyFile, LockFile
from .crypto import DEFAULT_DATA_KEY
from .errors import (
    IntegrityError,
    KeyFileError,
    KeyModeError,
    LockError,
    RecordNotFoundError,
)
from .format import (
    COMPACTING_AUDIT_KEY,
    CompactingAudit,
    KeyFile,
    KeyFileMetadata,
    Record,
    parse_records,
    serialize_records,
)
from .lps import LPSUnprotector, RestrictionValidator

_SID_PATTERN = re.compile(r"^[A-Za-z0-9]{1,32}$")


class KeyMode(str, Enum):
    """Master-key selection policy for :class:`SSFSStore`.

    ``INDIVIDUAL`` is the safe default and requires a valid
    ``SSFS_<SID>.KEY`` before encrypted data can be read or written.
    ``DEFAULT`` explicitly opts into SAP's compiled default data key and
    refuses to operate when an individual key file is present.
    """

    INDIVIDUAL = "individual"
    DEFAULT = "default"

    @classmethod
    def parse(cls, value: Union["KeyMode", str]) -> "KeyMode":
        """Normalize a public key-mode argument or raise a clear error."""

        if isinstance(value, cls):
            return value
        try:
            return cls(value)
        except (TypeError, ValueError) as exc:
            choices = ", ".join(mode.value for mode in cls)
            raise ValueError(f"key_mode must be one of: {choices}") from exc


def _identity(value: str) -> str:
    encoded = value.encode("utf-8", errors="replace")[:24]
    return encoded.decode("utf-8", errors="ignore")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write(path: Path, content: bytes, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        finally:
            raise


def _backup(source: Path, destination: Path) -> None:
    if not source.exists():
        return
    shutil.copyfile(source, destination)
    os.chmod(destination, stat.S_IRUSR | stat.S_IWUSR)
    with destination.open("rb") as stream:
        os.fsync(stream.fileno())
    _fsync_directory(destination.parent)


class StoreLock(AbstractContextManager["StoreLock"]):
    """Cooperative lock using SAP's conventional ``.LCK`` path."""

    def __init__(self, path: Path, *, user: str, host: str) -> None:
        self.path = path
        self.user = user
        self.host = host
        self._held = False

    def __enter__(self) -> "StoreLock":
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        content = LockFile.create(user=self.user, host=self.host).to_bytes()
        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise LockError(f"SSFS lock already exists: {self.path}") from exc
        try:
            os.write(descriptor, content)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_directory(self.path.parent)
        self._held = True
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self._held:
            self.path.unlink(missing_ok=True)
            _fsync_directory(self.path.parent)
            self._held = False


@dataclass(frozen=True)
class ValidationResult:
    key_name: str
    record_index: int
    deleted: bool
    encrypted: bool
    binary: bool
    valid: bool
    error: Optional[str] = None


class SSFSStore:
    """A SAP SSFS data/key pair.

    The class supports the RSEC format represented by the supplied SAP 753
    tool: plaintext and encrypted records, default-key SCC stores, clear
    type-1 keys, compiled type-2 keys, and enhanced type-2 keys resolved
    through a registration password or ``.LKY`` Local Protected Storage.
    """

    def __init__(
        self,
        sid: str,
        data_path: Union[str, os.PathLike[str]],
        key_path: Optional[Union[str, os.PathLike[str]]] = None,
        *,
        lky_path: Optional[Union[str, os.PathLike[str]]] = None,
        key_mode: Union[KeyMode, str] = KeyMode.INDIVIDUAL,
        registration_password: Optional[Union[str, bytes]] = None,
        lps_unprotector: Optional[LPSUnprotector] = None,
        restriction_validator: Optional[RestrictionValidator] = None,
        allow_mock_lps: bool = False,
        user: Optional[str] = None,
        host: Optional[str] = None,
    ) -> None:
        if not _SID_PATTERN.fullmatch(sid):
            raise ValueError("SID must contain 1-32 ASCII letters or digits")
        self.sid = sid.upper()
        self.data_directory = Path(data_path)
        self.key_directory = Path(key_path) if key_path is not None else self.data_directory
        self.lky_directory = Path(lky_path) if lky_path is not None else self.key_directory
        self._configured_key_mode = KeyMode.parse(key_mode)
        self._registration_password = registration_password
        self._lps_unprotector = lps_unprotector
        self._restriction_validator = restriction_validator
        self._allow_mock_lps = allow_mock_lps
        self.user = _identity(user if user is not None else getpass.getuser())
        self.host = _identity(host if host is not None else socket.gethostname())

    @property
    def data_file(self) -> Path:
        return self.data_directory / f"SSFS_{self.sid}.DAT"

    @property
    def data_backup_file(self) -> Path:
        return self.data_directory / f"SSFS_{self.sid}.DA_"

    @property
    def key_file(self) -> Path:
        return self.key_directory / f"SSFS_{self.sid}.KEY"

    @property
    def key_backup_file(self) -> Path:
        return self.key_directory / f"SSFS_{self.sid}.KE_"

    @property
    def local_key_file(self) -> Path:
        return self.lky_directory / f"SSFS_{self.sid}.LKY"

    @property
    def lock_file(self) -> Path:
        return self.data_directory / f"SSFS_{self.sid}.LCK"

    @property
    def configured_key_mode(self) -> KeyMode:
        """Return the caller-selected key policy."""

        return self._configured_key_mode

    @property
    def key_mode(self) -> str:
        """Describe the effective key state without selecting key bytes."""

        if self._configured_key_mode is KeyMode.DEFAULT:
            if self.key_file.exists():
                return "default-key-conflict"
            return "default-key-obfuscation"
        if not self.key_file.exists():
            return "individual-key-missing"
        metadata = KeyFileMetadata.parse(self.key_file.read_bytes())
        return f"individual-{metadata.protection}"

    def load_key_file(self) -> KeyFile:
        try:
            blob = self.key_file.read_bytes()
        except OSError as exc:
            raise KeyFileError(f"unable to read key file {self.key_file}: {exc}") from exc
        metadata = KeyFileMetadata.parse(blob)
        local_key = None
        if metadata.key_encryption_type == 1 and self.local_key_file.exists():
            local_key = LocalKeyFile.load(self.local_key_file)
        return KeyFile.parse(
            blob,
            registration_password=self._registration_password,
            local_key=local_key,
            expected_lps_context=f"SSFS_{self.sid}".encode("ascii"),
            lps_unprotector=self._lps_unprotector,
            restriction_validator=self._restriction_validator,
            allow_mock_lps=self._allow_mock_lps,
        )

    def master_key(self) -> bytes:
        """Resolve the master key according to the explicit key policy.

        Merely omitting ``SSFS_<SID>.KEY`` never enables the compiled default
        key. Callers opening a known default-key store must construct the store
        with ``key_mode=KeyMode.DEFAULT`` (or ``"default"``).
        """

        if self._configured_key_mode is KeyMode.DEFAULT:
            if self.key_file.exists():
                raise KeyModeError(
                    "default-key mode was requested but an individual key file exists: "
                    f"{self.key_file}"
                )
            return DEFAULT_DATA_KEY
        if not self.key_file.exists():
            raise KeyFileError(
                f"individual key file is missing: {self.key_file}; "
                "use key_mode='default' only for a known default-key store"
            )
        return self.load_key_file().master_key

    def load_records(self) -> list[Record]:
        if not self.data_file.exists():
            return []
        try:
            return parse_records(self.data_file.read_bytes())
        except OSError as exc:
            raise IntegrityError(f"unable to read SSFS data file {self.data_file}: {exc}") from exc

    def validate(self, *, decrypt: bool = True) -> list[ValidationResult]:
        records = self.load_records()
        master_key = self.master_key() if decrypt else None
        results: list[ValidationResult] = []
        for index, record in enumerate(records):
            error: Optional[str] = None
            valid = record.sap_integrity_valid
            if not valid:
                error = "record HMAC-SHA1 mismatch"
            elif decrypt and not record.plaintext:
                try:
                    assert master_key is not None
                    record.decrypt_value(master_key)
                except IntegrityError as exc:
                    valid = False
                    error = str(exc)
            results.append(
                ValidationResult(
                    record.key_name,
                    index,
                    record.deleted,
                    not record.plaintext,
                    record.binary,
                    valid,
                    error,
                )
            )
        return results

    def _require_valid(self, records: Iterable[Record], master_key: bytes) -> None:
        for record in records:
            if not record.sap_integrity_valid:
                raise IntegrityError(f"refusing mutation: record {record.key_name!r} has an invalid HMAC")
            if not record.plaintext:
                record.decrypt_value(master_key)

    def records(self, *, history: bool = False) -> list[Record]:
        records = [record for record in self.load_records() if not record.is_compacting_audit]
        if history:
            return records
        active: dict[str, Record] = {}
        for record in records:
            if record.deleted:
                active.pop(record.key_name, None)
            else:
                active[record.key_name] = record
        return list(active.values())

    def get_record(self, key_name: str) -> Record:
        for record in reversed(self.load_records()):
            if record.key_name == key_name and not record.deleted and not record.is_compacting_audit:
                return record
        raise RecordNotFoundError(key_name)

    def get(self, key_name: str) -> bytes:
        return self.get_record(key_name).decrypt_value(self.master_key())

    def put(
        self,
        key_name: str,
        value: Union[bytes, str],
        *,
        plaintext: bool = False,
        binary: bool = False,
        text_encoding: str = "utf-8",
    ) -> Record:
        if isinstance(value, str):
            value = value.encode(text_encoding)
        with StoreLock(self.lock_file, user=self.user, host=self.host):
            records = self.load_records()
            master_key = self.master_key()
            self._require_valid(records, master_key)
            records = [
                record.with_deleted() if record.key_name == key_name and not record.deleted else record
                for record in records
            ]
            new_record = Record.create(
                key_name,
                value,
                master_key=master_key,
                plaintext=plaintext,
                binary=binary,
                user=self.user,
                host=self.host,
            )
            records.append(new_record)
            self._write_records(records)
            return new_record

    def remove(self, key_name: str) -> None:
        with StoreLock(self.lock_file, user=self.user, host=self.host):
            records = self.load_records()
            master_key = self.master_key()
            self._require_valid(records, master_key)
            target = None
            for index in range(len(records) - 1, -1, -1):
                if (
                    records[index].key_name == key_name
                    and not records[index].deleted
                    and not records[index].is_compacting_audit
                ):
                    target = index
                    break
            if target is None:
                raise RecordNotFoundError(key_name)
            records[target] = records[target].with_deleted()
            self._write_records(records)

    def compact(self) -> int:
        with StoreLock(self.lock_file, user=self.user, host=self.host):
            records = self.load_records()
            master_key = self.master_key()
            self._require_valid(records, master_key)
            visible = [record for record in records if not record.is_compacting_audit]
            compacted = [record for record in visible if not record.deleted]
            removed = len(visible) - len(compacted)
            if removed:
                previous_audits = [
                    record.compacting_audit
                    for record in records
                    if record.is_compacting_audit and record.compacting_audit is not None
                ]
                previous_total = previous_audits[-1].removed_total if previous_audits else 0
                audit_timestamp = int(time.time())
                audit = CompactingAudit(
                    timestamp=audit_timestamp,
                    user=self.user,
                    host=self.host,
                    removed_total=previous_total + removed,
                    removed_last=removed,
                )
                audit_record = Record.create(
                    COMPACTING_AUDIT_KEY,
                    audit.to_bytes(),
                    plaintext=True,
                    binary=True,
                    user=self.user,
                    host=self.host,
                    timestamp=audit_timestamp,
                )
                audit_record = replace(
                    audit_record,
                    filler2=b"\x01" + (b"\x00" * 8),
                    mac=b"",
                )
                compacted.append(Record.parse(audit_record.to_bytes()))
                self._write_records(compacted)
            return removed

    def initialize_individual_key(
        self, master_key: Optional[bytes] = None, *, key_type: int = 2
    ) -> KeyFile:
        if self.key_file.exists():
            raise KeyFileError(f"key file already exists: {self.key_file}")
        if self.local_key_file.exists():
            raise KeyFileError(
                f"local key material exists without a matching key file: "
                f"{self.local_key_file}"
            )
        if self.data_file.exists() and self.data_file.stat().st_size:
            return self.change_key(master_key, key_type=key_type)
        with StoreLock(self.lock_file, user=self.user, host=self.host):
            if self.key_file.exists():
                raise KeyFileError(f"key file already exists: {self.key_file}")
            if self.data_file.exists() and self.data_file.stat().st_size:
                raise KeyFileError(
                    "data appeared while initializing the key; rerun changekey to convert it safely"
                )
            master_key = os.urandom(24) if master_key is None else master_key
            key_file = KeyFile.create(master_key, user=self.user, host=self.host, key_type=key_type)
            _atomic_write(self.key_file, key_file.to_bytes())
            self._configured_key_mode = KeyMode.INDIVIDUAL
            return key_file

    def initialize_enhanced_key(
        self,
        master_key: Optional[bytes] = None,
        *,
        key_encryption_key: Optional[bytes] = None,
    ) -> KeyFile:
        """Create a portable enhanced standalone ``.KEY``/``.LKY`` pair.

        The LKY uses real LPS v2 fallback protection and is accepted by SAP's
        standalone LPS mode. It is portable compatibility protection, not a
        host-bound DPAPI or TPM credential.
        """

        if self.key_file.exists():
            raise KeyFileError(f"key file already exists: {self.key_file}")
        if self.local_key_file.exists():
            raise KeyFileError(f"local key file already exists: {self.local_key_file}")
        if self.data_file.exists() and self.data_file.stat().st_size:
            raise KeyFileError(
                "enhanced initialization requires an empty/new store; open the "
                "existing key mode and rotate it instead"
            )
        with StoreLock(self.lock_file, user=self.user, host=self.host):
            if self.key_file.exists() or self.local_key_file.exists():
                raise KeyFileError("key material appeared while initializing the store")
            master_key = os.urandom(24) if master_key is None else master_key
            key_encryption_key = (
                os.urandom(24)
                if key_encryption_key is None
                else key_encryption_key
            )
            if len(master_key) != 24:
                raise ValueError("SSFS master keys must be exactly 24 bytes")
            if len(key_encryption_key) != 24:
                raise ValueError("SSFS key-encryption keys must be exactly 24 bytes")
            local_key = LocalKeyFile.create_fallback(
                key_encryption_key,
                sid=self.sid,
                user=self.user,
                host=self.host,
            )
            key_file = KeyFile.create(
                master_key,
                user=self.user,
                host=self.host,
                key_encryption_key=key_encryption_key,
                registration_salt=os.urandom(32),
                global_key_mode=3,
            )
            _atomic_write(self.local_key_file, local_key.to_bytes())
            try:
                _atomic_write(self.key_file, key_file.to_bytes())
            except BaseException:
                self.local_key_file.unlink(missing_ok=True)
                _fsync_directory(self.local_key_file.parent)
                raise
            self._configured_key_mode = KeyMode.INDIVIDUAL
            return key_file

    def change_key(self, master_key: Optional[bytes] = None, *, key_type: int = 2) -> KeyFile:
        new_key = os.urandom(24) if master_key is None else master_key
        if len(new_key) != 24:
            raise ValueError("new SSFS master key must be exactly 24 bytes")
        with StoreLock(self.lock_file, user=self.user, host=self.host):
            records = self.load_records()
            old_key_file = (
                self.load_key_file()
                if self._configured_key_mode is KeyMode.INDIVIDUAL
                else None
            )
            old_key = (
                old_key_file.master_key
                if old_key_file is not None
                else self.master_key()
            )
            self._require_valid(records, old_key)
            reencrypted: list[Record] = []
            for record in records:
                if record.plaintext:
                    reencrypted.append(record)
                    continue
                value = record.decrypt_value(old_key)
                rewritten = Record.create(
                    record.key_name,
                    value,
                    master_key=new_key,
                    plaintext=False,
                    binary=record.binary,
                    user=record.user,
                    host=record.host,
                    timestamp=record.timestamp,
                )
                if record.deleted:
                    rewritten = rewritten.with_deleted()
                reencrypted.append(rewritten)
            create_options: dict[str, object] = {}
            if (
                key_type == 2
                and old_key_file is not None
                and old_key_file.key_encryption_type == 1
            ):
                create_options = {
                    "key_encryption_key": old_key_file.key_encryption_key,
                    "registration_salt": old_key_file.salt,
                    "global_key_mode": old_key_file.global_key_mode,
                }
            key_file = KeyFile.create(
                new_key,
                user=self.user,
                host=self.host,
                key_type=key_type,
                **create_options,
            )

            # SAP itself uses .DA_/.KE_ recovery files because replacing two
            # files cannot be a single filesystem transaction.
            _backup(self.data_file, self.data_backup_file)
            _backup(self.key_file, self.key_backup_file)
            _atomic_write(self.data_file, serialize_records(reencrypted))
            _atomic_write(self.key_file, key_file.to_bytes())
            self._configured_key_mode = KeyMode.INDIVIDUAL
            return key_file

    def _write_records(self, records: Iterable[Record]) -> None:
        _backup(self.data_file, self.data_backup_file)
        _atomic_write(self.data_file, serialize_records(records))

    def remove_lock(self) -> bool:
        if not self.lock_file.exists():
            return False
        self.lock_file.unlink()
        _fsync_directory(self.lock_file.parent)
        return True

    def info(self) -> dict[str, object]:
        records = self.load_records()
        visible = [record for record in records if not record.is_compacting_audit]
        audits = [
            record.compacting_audit
            for record in records
            if record.is_compacting_audit and record.compacting_audit is not None
        ]
        last_audit = audits[-1] if audits else None
        key_metadata = (
            KeyFileMetadata.parse(self.key_file.read_bytes())
            if self.key_file.exists()
            else None
        )
        local_key = (
            LocalKeyFile.load(self.local_key_file)
            if self.local_key_file.exists()
            else None
        )
        lock = LockFile.load(self.lock_file) if self.lock_file.exists() else None
        result: dict[str, object] = {
            "sid": self.sid,
            "data_file": str(self.data_file),
            "data_file_exists": self.data_file.exists(),
            "key_file": str(self.key_file),
            "key_file_exists": self.key_file.exists(),
            "key_mode": self.key_mode,
            "key_type": key_metadata.key_type if key_metadata else None,
            "key_protection": key_metadata.protection if key_metadata else None,
            "key_crc_valid": key_metadata.crc_valid if key_metadata else None,
            "lky_file": str(self.local_key_file),
            "lky_file_exists": local_key is not None,
            "lky_implementation": (
                local_key.implementation_name if local_key is not None else None
            ),
            "records_total": len(visible),
            "records_active": len(self.records()),
            "compacted": last_audit is not None,
            "records_removed_by_compacting": last_audit.removed_total if last_audit else 0,
            "lock_file": str(self.lock_file),
            "locked": lock is not None,
            "lock_timestamp": lock.timestamp if lock else None,
            "lock_user": lock.user if lock else None,
            "lock_host": lock.host if lock else None,
        }
        if local_key is not None and local_key.lps is not None:
            result.update(
                {
                    "lps_version": local_key.lps.version,
                    "lps_protection": local_key.lps.protection.name.lower(),
                    "lps_context": local_key.lps.context.decode(
                        "ascii", errors="backslashreplace"
                    ),
                    "lps_restricted": bool(local_key.lps.restriction),
                }
            )
        return result
