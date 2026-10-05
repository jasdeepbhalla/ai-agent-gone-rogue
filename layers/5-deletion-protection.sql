-- Layer 5. Infrastructure deletion protection.
-- Installed by `rogue mode hardened`. Engine level, independent of who is asking.
-- Even a superuser connection cannot DROP the table while this trigger exists.

create or replace function block_destructive() returns event_trigger as $f$
begin
  raise exception 'deletion protection: destructive DDL is not permitted on production';
end $f$ language plpgsql;

drop event trigger if exists no_destructive_ddl;
create event trigger no_destructive_ddl on sql_drop
  execute function block_destructive();

-- The infrastructure half of this layer, from rogue and deploy.yaml:
--
--   aws rds modify-db-instance --deletion-protection        (the database itself)
--   S3 Object Lock, COMPLIANCE mode                         (the backups, see layer 6)
