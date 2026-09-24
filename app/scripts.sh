#!/bin/sh
# partner subdomain rotation, runs nightly from cron
. ./.env.backup
aws route53 list-resource-record-sets --hosted-zone-id "$PARTNER_ZONE" --region "$PLATFORM_REGION"
