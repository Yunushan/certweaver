#!/bin/sh
# Keep inherited Git environment from disabling the managed transport policy.
set -eu
unset GIT_SSL_NO_VERIFY GIT_CONFIG_PARAMETERS GIT_CONFIG_COUNT
unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE
unset GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
export GIT_TERMINAL_PROMPT=0
exec /usr/bin/git -c core.hooksPath=/dev/null -c core.fsmonitor=false \
  -c protocol.file.allow=never -c http.sslVerify=true "$@"
