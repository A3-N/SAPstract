# Operations runbook

No SAP binary, SSFS store, key file, registration password, or generated
validation artifact is included in the source repository. Create and protect
stores only in an appropriate deployment environment.

## Deployment checklist

1. Stop every writer to the target store, including SCC and scheduled SAP
   maintenance.
2. Verify no `SSFS_<SID>.LCK` exists. Investigate rather than deleting an
   unexplained lock.
3. Provision the intended secret through protected standard input.
4. If the record protects a Java PKCS#12/JKS file, change that keystore to the
   exact same password in the same maintenance window.
5. Run `validate` and record only its non-secret result.
6. On a supported target, run native `rsecssfx list` or start SCC and confirm it
   opens the keystore without wrong-key errors.
7. Install `.DAT`, `.KEY`, and any instance-local `.LKY` as the correct matched
   set, mode `0600`, owned by the service user. Use mode `0700` parent
   directories. Do not distribute one instance's host-bound LKY as a portable
   key.
8. Avoid baking either file into a public image layer. Prefer runtime secret
   mounts.
9. Protect `.DA_`, `.KE_`, and retired LKY/registration material exactly like
   live material.

## Open and inspect enhanced SSFS

Use the same path split as SAP:

```sh
sapstract \
  --sid DEV \
  --data-path /global/ssfs/data \
  --key-path /global/ssfs/key \
  --lky-path /instance-local/ssfs \
  info

sapstract --json inspect /instance-local/ssfs/SSFS_DEV.LKY
```

`info` and `inspect` show protection metadata without decrypting record values.
Normal `validate`, `get`, and mutations resolve a usable `.LKY` automatically.
If the instance has not been registered, put the registration password in a
mode-`0600` file and use:

```sh
sapstract \
  --sid DEV \
  --data-path /global/ssfs/data \
  --key-path /global/ssfs/key \
  --lky-path /instance-local/ssfs \
  --registration-password-file /run/secrets/ssfs-registration-password \
  validate
```

Do not pass registration passwords as positional command arguments. For actual
SAP lifecycle operations, prefer official `rsecssfx register`/`changekey` on
the target instance. A password-derived KEK is available in process memory
during the operation.

For development-only interoperability setup:

```sh
sapstract \
  --sid DEV --data-path data --key-path key --lky-path local \
  init --enhanced-fallback
```

This emits SAP-readable enhanced mode-3 standalone material. SAP's own help
labels standalone setup as test/demo functionality. Portable fallback LPS does
not provide DPAPI/TPM host binding.

## Write a generic secret

```sh
printf %s "$DEV_SECRET_FROM_SECRET_MANAGER" | \
sapstract \
  --sid DEV \
  --data-path /secure/data \
  --key-path /separate/secure/key \
  put DEV/PASSWORD --value-file -
```

Do not literally use a shell environment variable if the local platform exposes
process environments to other users. A secret-manager pipe or protected
temporary file may be safer for that platform.

## Write an SCC secret

```sh
secret_source_command | \
sapstract \
  --key-mode default \
  --sid SCC \
  --data-path /opt/sap/scc/scc_config \
  --key-path /opt/sap/scc/scc_config \
  scc-put --value-file -
```

`scc-put` removes trailing CR/LF characters from textual file/stdin input,
encodes the remaining Unicode string as UTF-16LE, marks it binary, and encrypts
it. Ensure the secret source does not intentionally require a terminal newline.

## Move SCC away from default-key mode

First confirm that the target SCC version can use an individual SSFS key. The
supplied `SecStoreAccess` exposes a native `changeKey()` path.

```sh
sapstract \
  --key-mode default \
  --sid SCC \
  --data-path /opt/sap/scc/scc_config \
  --key-path /opt/sap/scc/scc_config \
  changekey
```

This creates `SSFS_SCC.KEY`, re-encrypts encrypted current and historical
records, and leaves recovery copies. The `SSFSStore` instance changes to
individual mode after a successful conversion; subsequent CLI invocations must
omit `--key-mode default`. Validate with the exact target SCC build before
deleting recovery files.

## Validate without disclosure

```sh
sapstract \
  --sid SID \
  --data-path /secure/data \
  --key-path /secure/key \
  validate
```

Exit status is zero only when every record passes. Status `3` means at least one
record failed validation. Configuration, I/O, unsupported-format, and CLI errors
exit with status `2`.

Use `validate --no-decrypt` only for forensic triage where the key is
unavailable. It verifies the fixed-key outer HMAC but cannot establish that
encrypted data is readable with the selected master key.

## Rotation and crash recovery

During `changekey`, `.DAT` and `.KEY` cannot be replaced atomically as a pair.
The writer keeps:

- `.DA_`: data before the operation;
- `.KE_`: key before the operation, when one existed.

If validation fails after an interrupted rotation:

1. Stop all writers.
2. Make forensic copies of live and recovery files without changing them.
3. Test candidate `.DAT`/`.KEY` pairs in an isolated directory.
4. Select the pair for which every encrypted record passes its inner SHA-1.
5. Atomically install that matching pair and validate again.
6. Start the application only after its native reader succeeds.

Do not combine the newest `.DAT` with whichever `.KEY` happens to exist; their
timestamps are informational and do not prove a match.

For an already-open enhanced store, Python preserves the enhanced KEK, salt,
and global LPS policy while rotating the data master key. It does not replace
the LKY. Creating or changing DPAPI/TPM registrations remains a platform/SAP
administration operation.

## History and retention

`put` replacement and `remove` retain prior values as defunct records. Use:

```sh
sapstract --sid SID --data-path /secure/data --key-path /secure/key list --history
sapstract --sid SID --data-path /secure/data --key-path /secure/key compact
```

Compaction changes only the live `.DAT` and creates `.DA_`, so old records still
exist in the recovery copy. Backups, filesystem snapshots, and image layers may
also retain them. Follow the platform's secret-retention and media-sanitization
policy.

An effective compaction also creates or replaces the internal
`RSECSSFS/COMPACTING_AUDIT` record. `list` hides this implementation record,
`validate` checks it, and `info` reports its cumulative removal count. SAP's
native `list -withHistory` renders the same information under `Compacting Audit`.

## Lock recovery

Only use `removelock` after checking:

- no SCC/native SAP/Python process is active;
- the lock's timestamp and owner are stale;
- there is no ongoing deployment on another host sharing the filesystem;
- live and recovery pairs validate.

A removed live lock can permit two writers and corrupt or lose updates.
`info` now parses and reports that timestamp, user, and host; it still never
decides staleness for you.

## Monitoring guidance

Monitor non-secret facts only:

- validation success/failure and exit status;
- presence and age of `.LCK`;
- expected owner/mode for directories and all five file suffixes;
- unexpected growth in defunct-record count;
- successful native-reader startup after rotation.

Never log decrypted values, master keys, raw `.DAT`/`.KEY` content, `--reveal`
output, or secret-manager command lines.
