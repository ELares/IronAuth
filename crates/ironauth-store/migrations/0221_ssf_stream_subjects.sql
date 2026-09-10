-- Shared Signals: the subjects a stream has asked to be told about (issue #143).
--
-- SSF 1.0 sections 8.1.4 and 8.1.5 let a receiver add and remove SUBJECTS on its own stream, so
-- a transmitter can send one receiver events about the twelve people it administers rather than
-- about everyone in the environment. This is where that list lives.
--
-- THE SUBJECT IS PII, AND IT IS SEALED. An RFC 9493 subject identifier in the `email` format
-- names a real address, and `iss_sub` names a real account. 0217 learned this the hard way: it
-- stored a signed token in the clear and justified it with a reason that turned out to be
-- false. There is no such reason here either, so the identifier is sealed under the
-- environment's active DEK exactly as `messages.recipient_sealed` is.
--
-- AND IT IS ALSO A LOOKUP KEY, which sealing alone cannot serve: a removal names a subject and
-- has to find its row, and a fan-out asks whether a subject is on the list. A deterministic
-- seal would answer that and leak equality across rows to anyone holding the ciphertext. So the
-- key is a BLIND INDEX -- an HMAC under the per-tenant key, the shape 0154 uses for a message
-- recipient -- and the seal carries the value itself.
--
-- BOUNDED PER STREAM, by `ssf.max_subjects_per_stream` rather than by a constant. A subject
-- list is receiver-chosen storage the fan-out reads on every event, so an unbounded one is both
-- unbounded rows and unbounded work per signal, and reaching the bound REFUSES rather than
-- evicting: a receiver silently stopping being told about a subject it added is a delivery gap
-- it cannot detect. It is configuration and not a constant for a reason that is about testing
-- rather than deployment: a bound no test can approach without ten thousand inserts is a bound
-- nothing drives, and the first version of this shipped exactly that.
--
-- ONE ROW PER (STREAM, SUBJECT), keyed on the blind index rather than the address. Adding a
-- subject twice is the same row, which is what makes `add` idempotent: SSF has a transmitter
-- answer a repeated add with the same success, not a conflict.
--
-- AN EMPTY LIST MEANS "EVERYTHING", NOT "NOTHING", and that is a decision this table cannot
-- express on its own -- it is the absence of rows either way. It is stated here because the
-- fan-out that reads this list lands with the CAEP and RISC vocabularies (issue #144), and a
-- reader arriving then needs to know which way the default runs: a stream that has never called
-- add-subject is one whose receiver has expressed no filter, and SSF's `default_subjects` is
-- how a transmitter would advertise the other choice. This build advertises no
-- `default_subjects`, because advertising one would be a claim about a fan-out that does not
-- exist yet.

CREATE TABLE ssf_stream_subjects (
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The stream that asked. CASCADE: a deleted stream's filter is not a thing to keep, and the
    -- rows name people.
    stream_id      text        NOT NULL,
    -- The HMAC of the canonical rendering, under the per-tenant blind-index key. This is the
    -- lookup key and the primary key; it is not reversible.
    subject_bidx   bytea       NOT NULL,
    -- The RFC 9493 format the receiver used, in the clear. It is a vocabulary term rather than
    -- a value, so it names no one, and an operator asking "which formats is this receiver
    -- filtering by" can be answered without opening anything.
    subject_format text        NOT NULL,
    -- The rendered identifier, sealed. AAD-bound to the row's whole primary key, so a
    -- ciphertext lifted from one row does not open in another.
    subject_sealed bytea       NOT NULL,
    -- Which DEK sealed it, so a rotation cannot strand a filter mid-life.
    pii_dek_version integer    NOT NULL,
    -- Whether the RECEIVER says it has verified this subject belongs to it (SSF 1.0 section
    -- 8.1.4's `verified`, which defaults to true when omitted). Recorded rather than acted on:
    -- it is the receiver's assertion about its own records, and a transmitter that treated it
    -- as permission would be taking the receiver's word for who it may be told about.
    verified       boolean     NOT NULL DEFAULT true,
    added_at       timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, environment_id, stream_id, subject_bidx),

    CONSTRAINT ssf_stream_subjects_bidx_nonempty CHECK (octet_length(subject_bidx) > 0),
    -- A BOUND ON THE STORED BLOB, sized as 0217 sizes its own: the plaintext bound plus room
    -- for the AEAD nonce and tag. `SsfStreamSubjectRepo::add` refuses a rendering over
    -- `MAX_SUBJECT_BYTES` (1024) before sealing it, and a seal is the plaintext plus 28 bytes,
    -- so this ceiling is that with slack rather than the same number.
    --
    -- THE TWO NUMBERS MUST NOT BE EQUAL, which was the first version's mistake: the surface
    -- bounded the PLAINTEXT at 2048 while this bounded the CIPHERTEXT at 2048, so a rendering
    -- of 2021 to 2048 bytes passed the door and violated this CHECK, answering 500 for a
    -- request the endpoint had accepted.
    --
    -- THE FLOOR IS 29 AND NOT 1, because a seal cannot be shorter: twelve bytes of nonce,
    -- sixteen of tag, and at least one of ciphertext. `BETWEEN 1 AND ...` is a bound satisfied
    -- by values no correct writer can produce, which is no bound at all.
    CONSTRAINT ssf_stream_subjects_sealed_bounded
        CHECK (octet_length(subject_sealed) BETWEEN 29 AND 1280),
    -- The three formats this build renders, which `SsfSubjectFormat` also constrains. Here as
    -- well because a format the code cannot render is a row nothing can ever match.
    CONSTRAINT ssf_stream_subjects_format_known
        CHECK (subject_format IN ('email', 'iss_sub', 'opaque')),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    FOREIGN KEY (stream_id) REFERENCES ssf_streams (id) ON DELETE CASCADE
);

-- ONE STREAM'S SUBJECTS, which is the fan-out's read: given an event about a subject, which of
-- this environment's streams asked for it. The blind index is in the key already, so this
-- serves the listing and the per-stream count.
CREATE INDEX ssf_stream_subjects_by_stream_idx
    ON ssf_stream_subjects (tenant_id, environment_id, stream_id, added_at);

ALTER TABLE ssf_stream_subjects ENABLE ROW LEVEL SECURITY;
ALTER TABLE ssf_stream_subjects FORCE ROW LEVEL SECURITY;

CREATE POLICY ssf_stream_subjects_scope ON ssf_stream_subjects
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- THE DATA PLANE OWNS IT, because add and remove are request paths. DELETE is the removal, and
-- there is no UPDATE: a subject's rendering is fixed by its blind index, so changing one is
-- removing a row and adding another. `verified` is the only thing that could sensibly be
-- updated, and a repeated add is how a receiver changes it, which the INSERT handles.
GRANT SELECT, INSERT, DELETE ON ssf_stream_subjects TO ironauth_app;
GRANT UPDATE (verified) ON ssf_stream_subjects TO ironauth_app;
-- The CONTROL plane reads them: an operator asking why a receiver is not getting an event
-- wants to see whether it ever asked about that subject.
GRANT SELECT ON ssf_stream_subjects TO ironauth_control;
