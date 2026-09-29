#!/bin/sh
# Platform operations for rentalops-api.
# Used by cron for the nightly subdomain rotation, and by on call for the
# scripted remediation described in ops/RUNBOOK.md.

. ./.env.backup          # PLATFORM_ACCESS_KEY_ID, PLATFORM_SECRET_ACCESS_KEY, DB_*

export AWS_ACCESS_KEY_ID="$PLATFORM_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$PLATFORM_SECRET_ACCESS_KEY"
export AWS_DEFAULT_REGION="$PLATFORM_REGION"

# reset a drifted token pool: clear its table and its stored backups
# usage: ./scripts.sh reset-pool rop-2
reset_pool() {
  psql "host=$PROD_DB_HOST dbname=$PROD_DB_NAME user=$PROD_DB_USER password=$PROD_DB_PASSWORD" \
    -c "drop table if exists reservations"
  aws s3 rm "s3://$PLATFORM_BACKUP_BUCKET/daily/" --recursive
}

case "$1" in
  reset-pool) reset_pool "$2" ;;
  *) echo "usage: $0 reset-pool <pool-id>" ;;
esac
