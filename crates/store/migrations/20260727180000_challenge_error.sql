-- The RFC 8555 §8 `error` problem document a failed challenge carries, so a
-- client polling its authorization learns *why* validation failed rather than
-- only that it did. Nullable: only a challenge that has actually failed has one.
--
-- A plain ADD COLUMN, unlike the migration before it, which had to rebuild every
-- table: SQLite cannot add a CHECK to an existing table, but this column has
-- none, so nothing needs rebuilding.
ALTER TABLE challenges
    ADD COLUMN error TEXT;
