#!/bin/bash


# Use the Openssh or dropbear in 'mesh' mode.

# Common CLI args:
# -N'' - no pass
# -C - comment
# -f ca - file holding the private keys
# -q - quiet

# WIP: Start a SSHD in 'mesh gateway' or 'waypoint' mode.
#
# Unlike regular sshd, it runs as a user (not root) and uses
# certificates.
function ssh_gate() {
  CFG=${CFG:-${HOME}/.ssh}
  sshd
}

function sshc() {
  local dest=$1
  CFG=${CFG:-${HOME}/.ssh}
  ssh $dest
}

CMD=$1
shift
$CMD $*
