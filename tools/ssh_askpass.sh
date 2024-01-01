#!/bin/bash

if [ "$1" = "env" ]; then
  #  $(tools/ssh_askpass.sh env)
  echo export SSH_ASKPASS_REQUIRE=force
  echo export SSH_ASKPASS=`pwd`/$0
else
  env > /tmp/askpass.env

  # Please type 'yes', 'no' or the fingerprint:
  if [[ "$1" == *"Please"* ]]; then
    echo yes
    exit 0
  fi

  echo $1 > /tmp/askpass.cli
  echo $* >> /tmp/askpass.cli

  if [ "$1" = "Please type 'yes', 'no' or the fingerprint:" ]; then
    echo yes
    exit 0
  fi

  # build@localhost's password:

  # curl -H Metadata-Flavor:Google http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/identity?audience=ssh://
  curl -H Metadata-Flavor:Google http://127.0.0.1:15014/computeMetadata/v1/instance/service-accounts/default/identity?audience=ssh:// -s -qqq

fi

