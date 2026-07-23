"""Exceptions raised by :mod:`sapstract`."""


class SSFSError(Exception):
    """Base class for SSFS errors."""


class UnsupportedFormatError(SSFSError):
    """The input uses a format or protection mechanism not implemented here."""


class IntegrityError(SSFSError):
    """An authenticated field, payload hash, or structural invariant is invalid."""


class KeyFileError(SSFSError):
    """A key file is missing, malformed, or cannot unlock the data."""


class KeyModeError(KeyFileError):
    """The configured key mode conflicts with the available store material."""


class RecordNotFoundError(SSFSError, KeyError):
    """The requested active record is not present."""


class LockError(SSFSError):
    """The store is already locked by another writer."""
