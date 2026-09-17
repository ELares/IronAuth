# Recovering a wrapped KEK hierarchy

Issue #153 criteria 4 and 6.

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

```
ironauth storage kek-backup --url DSN --out keks.json
```

It prints a MANIFEST line. Store it somewhere the backup file is not.

### Why this is a command and not a SELECT

This section used to give you the SQL. An adversarial review pasted that SELECT into the three
roles a deployment actually has and measured:

```
owner = Ok(3 rows)    app = Ok(0 rows)    control = Ok(0 rows)
```

`tenant_keks` has FORCE ROW LEVEL SECURITY, and the application role is the one your
`database.url` names. The query returned **zero rows and no error**, and an empty export
passes every downstream check there is: it matches its own row count, it digests to its own
manifest, and "check the blobs are not empty" is vacuously true when there are no blobs. You
would find out during the key loss the backup was taken for.

`kek-backup` refuses that connection instead of exporting what it can see, and refuses to
write an empty file at all.

### Why the manifest is separate

A manifest kept beside the rows it describes is damaged by the same transfer that damages
them. Keeping it in a ticket, a password manager, or a different bucket is the whole point:
it is a claim recorded at backup time and checked at restore time, against a file that
travelled on its own.

`kek-restore` will not run without it. A restore that checks a backup against a manifest
computed from that same backup passes for any file, including one that lost every row.

### What is in the file

All NINE columns, not the seven an earlier version of this document listed. The two that were
missing:

- `created_at` has a `now()` DEFAULT, so an export that omits it stamps every KEK in the
  deployment with the restore date.
- `destroyed_at` is the crypto-shred instant, and the migration that added it calls the
  destroyed row "retained as evidence". Without it a restored shredded row still says the key
  was destroyed and no longer says WHEN, which is the answer an erasure attestation needs.

The wrap AAD binds the scope, the version and the master key id, so a restore that put the
blob back under a different version produces a row that exists and cannot be opened.

## Restore

```
ironauth storage kek-restore --url DSN --in keks.json --manifest 'rows=42 sha256=...'
```

1. **Have the right master key.** `master_key_id` is in the file. The key itself must be
   available to the process before the restore is worth starting.
2. **Run the command.** It verifies before it writes anything, and then writes in ONE
   transaction, so the database ends up in the old state or the new one and never in between.
   A row already present and byte-identical is counted, not rewritten, so re-running an
   interrupted restore converges. A row present with DIFFERENT contents stops the restore
   without writing: the database may have moved on since the backup, and overwriting could
   undo a crypto-shred.
3. **Read a secret on EVERY scope you expected to recover, not one of them.** This is the step
   people skip, and doing it on one scope is not the check. A review aborted a restore after
   one row of four and then satisfied the old wording verbatim by picking the scope that
   happened to land; the rest of the tenants stayed unreadable and surfaced one at a time as
   each signed in.
4. **Confirm nothing came back `destroyed` that you expected to recover.** A read consults
   neither the completeness of the row set nor `tenant_keks.status`, so a restore whose rows
   all say `destroyed` decrypts perfectly and then fails the next write with an encryption
   error, because `active_kek_version()` returns `None`. A review demonstrated exactly that.

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

### Empty blobs are not a corruption signal

An earlier version of this document told you to distrust an export whose `wrapped_kek` values
are empty. That was wrong and it was dangerous in both directions. An empty blob is the
legitimate post-shred state, which this same document says two paragraphs above, and which
`a_shredded_row_is_a_valid_thing_to_back_up` asserts. Acting on the old rule during an
incident meant either discarding a correct backup, or reaching for an older one that predates
the shred and resurrecting key material for a tenant the deployment promised to erase.

If you want to know whether a backup is sound, check it against its manifest. That is what the
manifest is for.

## After a master key rotation

`ironauth storage rekey` rewraps every KEK under a new master. A backup taken before that
rotation names the OLD master in `master_key_id` and can only be restored with the old master
key available. Keep both keys until every backup naming the old one has aged out, or the
backup is a set of rows nothing can open.

**A rotation to a different SECRET is refused by default**, and the refusal is not about
backups. `storage rekey` rewraps keys and rebuilds none of the fifteen blind indexes derived
from the master secret: login handles, external ids, trait logins, flexible and routing
identifiers, recovery codes, invitations, organisation contact emails, email and SMS factor
recipients, message recipients, and the risk-signal, abuse, SSF-stream and migration-record
subjects. After such a rotation every one of them is computed under a key nothing derives any
more, and the failure is silent: an identifier lookup misses and reports an unknown user, so
existing accounts stop resolving at login while re-registering the same address creates a
second user past the unique index.

There is no index-rebuild tool in the tree today. `--i-will-rebuild-lookups` exists for an
operator who has one of their own; without it, the rotation that is supported is a change of
NAME with the same secret, which moves rows to a new generation and leaves every lookup intact.
