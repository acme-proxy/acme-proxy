-- RFC 9773 §5's "has not already been marked as replaced by a different Order
-- that is not `invalid`", enforced by the database rather than only by a read.
--
-- `check_replaces` runs that read in `post_new_order`, but the read and the
-- INSERT that follows it are two different transactions. Two newOrder requests
-- naming the same predecessor could therefore both find nothing and both
-- persist, and the plain `idx_orders_replaces` index had nothing to say about
-- it. The handler's check stays — it is what produces a 409 with a message
-- naming the conflicting order — and this is the backstop underneath it.
--
-- Partial on `status != 'invalid'`, matching `find_by_replaces`'s own
-- predicate: an order that falls to `invalid` drops out of the index and frees
-- its predecessor to be claimed again, which is exactly what makes a retry
-- after a failed replacement work.

-- `CREATE UNIQUE INDEX` fails outright on pre-existing duplicates, and a failed
-- migration is a server that will not start — so any duplicate claims already
-- in the table have to be settled first. The earliest claimant keeps the field;
-- the losers only stop advertising a `replaces` they were never entitled to.
-- Their orders and certificates are untouched.
--
-- Keyed on `rowid` rather than `created_at`: two orders created in the same
-- second would tie, both would survive the UPDATE, and the CREATE below would
-- then fail — which is the one outcome this statement exists to prevent.
-- `rowid` is unique and insertion-ordered, so it means the same thing without
-- the tie.
UPDATE orders
   SET replaces = NULL
 WHERE replaces IS NOT NULL
   AND status != 'invalid'
   AND rowid NOT IN (
       SELECT MIN(rowid) FROM orders
        WHERE replaces IS NOT NULL
          AND status != 'invalid'
        GROUP BY profile, replaces
   );

DROP INDEX IF EXISTS idx_orders_replaces;

CREATE UNIQUE INDEX idx_orders_replaces_claim
    ON orders (profile, replaces)
 WHERE replaces IS NOT NULL AND status != 'invalid';
