#!/bin/bash
#
# Deploy Silverline-API Plugin per rsync
# Voraussetzung: rsync + SSH (WSL, Git Bash mit rsync, oder Cygwin)
#
# Infomaniak: SSH = gleicher Host wie FTP (y12er.ftp.infomaniak.com)
# Nutzung:
#   ./deploy.sh         = Deploy ausführen
#   ./deploy.sh --dry   = Nur anzeigen, was übertragen würde
#

SSH_USER="y12er_it-pin"
SSH_HOST="y12er.ftp.infomaniak.com"
REMOTE_DIR="/home/clients/cd018176a9efb9d6ecf8a0ae8be5e651/sites/mysilverline.it-pin.ch/wp-content/plugins/silverline-api"

DRY_RUN=""
[[ "$1" == "--dry" ]] && DRY_RUN="--dry-run -v"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_DIR="${SCRIPT_DIR}/"

echo "Deploy: $LOCAL_DIR -> ${SSH_USER}@${SSH_HOST}:${REMOTE_DIR}"
[[ -n "$DRY_RUN" ]] && echo "(Dry-Run - nichts wird geändert)"
echo "---"

rsync -avz --progress $DRY_RUN --exclude '.git' --exclude '.gitignore' --exclude '.DS_Store' --exclude 'Thumbs.db' --exclude '*.Save.php' --exclude 'silverline-api copy.php' --exclude '*.log' --exclude '.env' --exclude '.env.*' --exclude '.vscode' --delete "$LOCAL_DIR" "${SSH_USER}@${SSH_HOST}:${REMOTE_DIR}/"

echo "---"
echo "Deploy fertig."
