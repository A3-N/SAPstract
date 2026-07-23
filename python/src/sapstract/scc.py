"""SAP Cloud Connector conventions built on sapstract's SSFS store API.

Cloud Connector stores its Java-keystore password under a fixed record name as
encrypted binary Java-character bytes. The supplied little-endian SCC package
represents those characters as UTF-16LE.
"""

from __future__ import annotations

from .format import Record
from .store import SSFSStore

SCC_PASSWORD_RECORD = "CLOUD_CONN/JAVA_KEYSTORE_PASSWORD"


def encode_scc_password(password: str) -> bytes:
    """Encode a Python string using the SCC Java ``char[]`` convention."""

    if not isinstance(password, str):
        raise TypeError("SCC passwords must be provided as str")
    return password.encode("utf-16le")


def decode_scc_password(value: bytes) -> str:
    """Decode SCC Java ``char[]`` bytes into a Python string."""

    return value.decode("utf-16le")


def put_scc_password(store: SSFSStore, password: str) -> Record:
    """Store an encrypted SCC Java-keystore password in ``store``."""

    return store.put(
        SCC_PASSWORD_RECORD,
        encode_scc_password(password),
        plaintext=False,
        binary=True,
    )


def get_scc_password(store: SSFSStore) -> str:
    """Return the decoded SCC Java-keystore password from ``store``."""

    return decode_scc_password(store.get(SCC_PASSWORD_RECORD))
