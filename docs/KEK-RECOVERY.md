# Recovering a wrapped KEK hierarchy

Issue #153 criterion 6. The restore path below is exercised by
`crates/ironauth-store/tests/kek_recovery.rs`: its steps are these steps, in this order, so a
change to one that is not made to the other fails the suite.

## What the hierarchy is

```
master key            held OUTSIDE the database (KMS, secret manager, env)
  -> tenant KEK       one per tenant and environment, sealed under the master
     -> record DEK    sealed under the KEK
        -> ciphertext the sealed row
```

Two consequences follow, and both matter more than the procedure:

**A backup of the KEK rows carries nothing readable.** Every blob in it is sealed under a key
that is not in the database. That is what makes the backup safe to store beside the data.

**The master key is the one thing whose loss is unrecoverable.** No quantity of database
backups substitutes for it. `a_backup_of_the_hierarchy_is_useless_without_the_master_key`
asserts this rather than leaving it as advice: it restores a complete, correct backup under a
different master and gets an error.

## Backup

Export the whole row, not just the blob:

```sql
SELECT id, tenant_id, environment_id, version, master_key_id, wrapped_kek, status
FROM tenant_keks ORDER BY id;
```

The wrap AAD binds the scope, the version and the master key id, so a restore that put the
blob back under a different version produces a row that exists and cannot be opened. That
failure looks like a successful restore until somebody reads a secret.

Verify the export is not empty blobs before trusting it. A backup of zero-length
`wrapped_kek` values restores rows, passes a row count, and recovers nothing.

## Restore

1. Confirm which master key id the rows name. `master_key_id` is in the export; the key
   itself must be available to the process before the restore is worth starting.
2. Insert the rows back exactly as exported, all seven columns.
3. **Read a secret.** This is the step people skip. A restore is not verified by the rows
   being present; it is verified by the hierarchy opening. `open_secret` on any scope that had
   one is the cheapest possible check and it is the only one that distinguishes a recovered
   database from a database full of unopenable blobs.

## What this does NOT recover

**A lost master key.** Nothing does. The hierarchy is unrecoverable and the sealed data with
it.

**A crypto-shred, and that is deliberate.** A shred overwrites `wrapped_kek` with an empty
blob so a tenant's data becomes permanently unreadable. A backup taken BEFORE a shred would
undo it, which makes backup retention part of the shred guarantee rather than an operational
detail: a shred is only as final as the oldest backup that predates it.

`restoring_a_shredded_kek_does_not_resurrect_it` pins the half the code controls, that
restoring the post-shred row does not make the data readable. The half it cannot control is
yours: age out or re-key backups that predate a shred, and record that in whatever promises
the deployment makes about erasure.

## After a master key rotation

`ironauth storage rekey` rewraps every KEK under a new master. A backup taken before that
rotation names the OLD master in `master_key_id` and can only be restored with the old master
key available. Keep both keys until every backup naming the old one has aged out, or the
backup is a set of rows nothing can open.
