-- Passphrase becomes a server-verified gate: the blob is not released (nor burned)
-- until the client proves knowledge of the passphrase. Fresh start authorised:
-- pre-gate secrets carry no verifier and cannot be upgraded.
DELETE FROM secrets;

ALTER TABLE secrets ADD COLUMN verifier_hash BLOB;
ALTER TABLE secrets ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE secrets ADD COLUMN locked_until TEXT;
