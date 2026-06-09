#!/bin/bash

DB_PATH="/var/www/fraktur/gothic_reader.db"
TG_TOKEN="8839507772:AAGR_THA7lxBTliab9Zktrv7QE2vY1kaO8M"
TG_CHAT="221519259"

BACKUP_FILE="/tmp/gothic-reader-backup-$(date +%Y%m%d-%H%M).db"

cp "$DB_PATH" "$BACKUP_FILE"

curl -s -F document=@"$BACKUP_FILE" \
  "https://api.telegram.org/bot${TG_TOKEN}/sendDocument" \
  -F chat_id="$TG_CHAT" \
  -F caption="fraktur.app backup $(date '+%d.%m.%Y %H:%M')" \
  > /dev/null

rm "$BACKUP_FILE"
