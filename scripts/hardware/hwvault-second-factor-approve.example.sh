#!/usr/bin/env bash
set -euo pipefail

# Example second-factor approval hook.
# Replace this with your real second-device approval flow.
# Contract:
# - Read HWVAULT_2FA_ACTION and HWVAULT_2FA_SECRET_ID
# - Exit 0 to approve, non-zero to deny

ACTION="${HWVAULT_2FA_ACTION:-unknown}"
SECRET_ID="${HWVAULT_2FA_SECRET_ID:-unknown}"

# Example placeholder: require explicit local confirmation.
echo "2FA approval required: action=$ACTION secret_id=$SECRET_ID" >&2
read -r -p "Approve? [y/N] " ans
if [[ "${ans,,}" == "y" ]]; then
  exit 0
fi
exit 1
