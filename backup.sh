#!/bin/bash

DB_PATH="/var/www/fraktur/gothic-reader.db"
TG_TOKEN="1236153678:AAEI-4oMo6UAeKH4XQ29SQpJUuNDrvjz-rg"
TG_CHAT="221519259"

BACKUP_FILE="/tmp/gothic-reader-backup-$(date +%Y%m%d-%H%M).db"

cp "$DB_PATH" "$BACKUP_FILE"

curl -s -F document=@"$BACKUP_FILE" \
  "https://api.telegram.org/bot${TG_TOKEN}/sendDocument" \
  -F chat_id="$TG_CHAT" \
  -F caption="fraktur.app backup $(date '+%d.%m.%Y %H:%M')" \
  > /dev/null

rm "$BACKUP_FILE"
