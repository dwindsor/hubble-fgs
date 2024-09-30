#!/usr/bin/env bash

set -u

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

TARBALL_PATH="$1"
TARBALL_NAME=$(basename "$TARBALL_PATH" .tar.gz)
TRACINGPOLICY_FILE="tcp.yaml"

EC2_KEY="/home/ak/sonar/anna-test.pem"
EC2_USER="ec2-user"
EC2_HOSTS=(
  "35.83.187.211" # i-0253b7303f3310eef
  "44.243.158.61" # i-037a0769c49adcf2d
)

if [ -z "$TARBALL_PATH" ]; then
  echo "Usage: $0 <path to tarball printed by \`make tarball\`>"
  exit 1
fi

for EC2_HOST in "${EC2_HOSTS[@]}"; do
  echo "Deploying to $EC2_HOST..."

  # copy tarball
  ssh -i "$EC2_KEY" "$EC2_USER@$EC2_HOST" "test -f $TARBALL_NAME.tar.gz"
  if [ $? -ne 0 ]; then
    scp -i "$EC2_KEY" "$TARBALL_PATH" "$EC2_USER@$EC2_HOST:"
    if [ $? -ne 0 ]; then
      echo "Error: Failed to copy tarball to $EC2_HOST."
      continue
    fi
  fi

  # copy tracingpolicy
  ssh -i "$EC2_KEY" "$EC2_USER@$EC2_HOST" "test -f $TRACINGPOLICY_FILE"
  if [ $? -ne 0 ]; then
    scp -i "$EC2_KEY" "$SCRIPT_DIR/$TRACINGPOLICY_FILE" "$EC2_USER@$EC2_HOST:"
    if [ $? -ne 0 ]; then
      echo "Error: Failed to copy tracingpolicy to $EC2_HOST."
      continue
    fi
  fi

  ssh -i "$EC2_KEY" "$EC2_USER@$EC2_HOST" << EOF
    set -e

    sudo bash -c "echo true > /etc/tetragon/tetragon.conf.d/enable-aws-sonar"
    sudo bash -c "echo us-west-2 > /etc/tetragon/tetragon.conf.d/aws-sonar-region"

    tar -xvf "$TARBALL_NAME.tar.gz"
    sudo $TARBALL_NAME/uninstall.sh
    sudo $TARBALL_NAME/install.sh

    sleep 1
    tetra tracingpolicy add "$TRACINGPOLICY_FILE"

    rm "$TARBALL_NAME.tar.gz"
    rm -r "$TARBALL_NAME"
EOF

  if [ $? -eq 0 ]; then
    echo "Deployment to $EC2_HOST complete."
  else
    echo "Error: Failed to run on $EC2_HOST."
  fi
done
