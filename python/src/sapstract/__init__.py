"""sapstract: dependency-free SAP Secure Storage in the File System support."""

from .auxiliary import LocalKeyFile, LockFile
from .errors import (
    IntegrityError,
    KeyFileError,
    KeyModeError,
    LockError,
    RecordNotFoundError,
    SSFSError,
    UnsupportedFormatError,
)
from .format import (
    CompactingAudit,
    DecryptedPayload,
    KeyFile,
    KeyFileMetadata,
    Record,
    derive_registration_key,
    parse_records,
    serialize_records,
)
from .inspection import FileInspection, inspect_ssfs_file
from .lps import (
    LPSBlob,
    LPSProtection,
    LPSProtector,
    LPSUnprotector,
    RestrictionValidator,
)
from .scc import (
    SCC_PASSWORD_RECORD,
    decode_scc_password,
    encode_scc_password,
    get_scc_password,
    put_scc_password,
)
from .store import KeyMode, SSFSStore, ValidationResult

__all__ = [
    "CompactingAudit",
    "DecryptedPayload",
    "FileInspection",
    "IntegrityError",
    "KeyFile",
    "KeyFileMetadata",
    "KeyFileError",
    "KeyMode",
    "KeyModeError",
    "LPSBlob",
    "LPSProtection",
    "LPSProtector",
    "LPSUnprotector",
    "LocalKeyFile",
    "LockError",
    "LockFile",
    "Record",
    "RecordNotFoundError",
    "RestrictionValidator",
    "SCC_PASSWORD_RECORD",
    "SSFSError",
    "SSFSStore",
    "UnsupportedFormatError",
    "ValidationResult",
    "decode_scc_password",
    "derive_registration_key",
    "encode_scc_password",
    "get_scc_password",
    "inspect_ssfs_file",
    "parse_records",
    "put_scc_password",
    "serialize_records",
]

__version__ = "0.2.0"
