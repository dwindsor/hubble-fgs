#!/usr/bin/env bash
# Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Isovalent Inc and its suppliers, if any. The intellectual and technical
# concepts contained herein are proprietary to Isovalent Inc and its suppliers
# and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law.  Dissemination of this information
# or reproduction of this material is strictly forbidden unless prior written
# permission is obtained from Isovalent Inc.

set -eo pipefail

# Log function to prepend timestamps to messages
log() {
  echo "$(date +'%Y-%m-%d %H:%M:%S') - $1"
}

# --- Default values ---
DEFAULT_SSH_USER="root"
REMOTE_IP=""
SSH_USER=""

FWA_SERVICE_NAME="fwa"

# --- Usage function ---
usage() {
  echo "Usage: $0 -i <remote_ip_address> [-u <ssh_user>] [-p <ssh_password>]"
  echo ""
  echo "Options:"
  echo "  -i, --ip         REMOTE_IP_ADDRESS   The IP address of the remote system (required)."
  echo "  -u, --user       SSH_USER            The SSH username (default: '${DEFAULT_SSH_USER}')."
  echo "  -p, --password   SSH_PASSWORD        The SSH password (required)."
  echo "  -h, --help                           Display this help message and exit."
  echo ""
  echo "Example: $0 -i 192.168.1.100 -p secret"
  echo "Example: $0 --ip 192.168.1.100 --user admin --password 'secret'"
}

# --- Script Start ---
log "Script started."

# --- Argument Parsing ---
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -i|--ip)
            if [[ -z "$2" || "$2" == -* ]]; then log "ERROR: --ip flag requires an argument."; usage; exit 1; fi
            REMOTE_IP="$2"
            shift # past argument
            shift # past value
            ;;
        -u|--user)
            if [[ -z "$2" || "$2" == -* ]]; then log "ERROR: --user flag requires an argument."; usage; exit 1; fi
            SSH_USER="$2"
            shift # past argument
            shift # past value
            ;;
        -p|--password)
            if [[ -z "$2" || "$2" == -* ]]; then log "ERROR: --password flag requires an argument."; usage; exit 1; fi
            SSH_PASSWORD="$2"
            shift # past argument
            shift # past value
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            log "ERROR: Unknown parameter passed: $1"
            usage # usage function now exits
            exit 1
            ;;
    esac
done

# Assign defaults if not provided
SSH_USER="${SSH_USER:-$DEFAULT_SSH_USER}"

# Check if IP address is provided
if [ -z "${REMOTE_IP}" ]; then
  log "ERROR: Remote IP address is required. Use -i or --ip flag."
  usage # usage function now exits
  exit 1
fi

# Check if SSH password is provided
if [ -z "${SSH_PASSWORD}" ]; then
  log "ERROR: SSH password is required. Use -p or --password flag."
  usage # usage function now exits
  exit 1
fi

log "Target remote host: ${REMOTE_IP}"
log "SSH user: ${SSH_USER}"
log "Service to restart: ${FWA_SERVICE_NAME}"

# Construct SSH connection string
SSH_EXEC="ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5"
SSH_TARGET="${SSH_USER}@${REMOTE_IP}"

# Commands to be executed remotely
STOP_COMMAND="LD_LIBRARY_PATH=/platform/lib:/nic/lib /nic/bin/sysmgrctl stop-service ${FWA_SERVICE_NAME}"
START_COMMAND="LD_LIBRARY_PATH=/platform/lib:/nic/lib /nic/bin/sysmgrctl start-service ${FWA_SERVICE_NAME}"

log "Attempting to stop service '${FWA_SERVICE_NAME}' on ${SSH_TARGET}..."
if ! sshpass -p "${SSH_PASSWORD}" ${SSH_EXEC} "${SSH_TARGET}" "${STOP_COMMAND}"; then
    log "ERROR: Failed to stop service '${FWA_SERVICE_NAME}' on ${SSH_TARGET}. Check SSH connectivity and permissions."
    log "Script finished with error."
    exit 1
fi
log "Service '${FWA_SERVICE_NAME}' stopped successfully on ${SSH_TARGET}."

log "Waiting 5 seconds for the service to stabilize..."
sleep 5

log "Attempting to start service '${FWA_SERVICE_NAME}' on ${SSH_TARGET}..."
if ! sshpass -p "${SSH_PASSWORD}" ${SSH_EXEC} "${SSH_TARGET}" "${START_COMMAND}"; then
    log "ERROR: Failed to start service '${FWA_SERVICE_NAME}' on ${SSH_TARGET}."
    log "Script finished with error."
    exit 1
fi
log "Service '${FWA_SERVICE_NAME}' started successfully on ${SSH_TARGET}."

log "Script finished successfully."
exit 0
