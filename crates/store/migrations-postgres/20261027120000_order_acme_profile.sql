-- The ACME profile an order is issued under. The reasoning is in the SQLite
-- twin, migrations/20261027120000_order_acme_profile.sql.
ALTER TABLE orders ADD COLUMN profile text;
