#!/bin/sh
# Minimal entrypoint: same argument handling and umask as the official one,
# but the image already runs as the unprivileged "redis" user (USER redis),
# so the root -> setpriv/chown branch (util-linux, findutils, coreutils) is not needed.
set -e
if [ "${1#-}" != "$1" ] || [ "${1%.conf}" != "$1" ]; then
	set -- redis-server "$@"
fi
um="$(umask)"
if [ "$um" = '0022' ]; then
	umask 0077
fi
exec "$@"
