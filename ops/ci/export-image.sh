#!/bin/sh
set -eu
service=postfix
revision=${CI_COMMIT_SHA:?}
[ "${#revision}" = 40 ]
case "$revision" in *[!0-9a-f]*) exit 1;; esac
test "$(id -u)" = 1001
inbox="/var/spool/ac-mail-images/$service/inbox"
archive="$inbox/$revision.tar"
umask 077
temporary=$(mktemp "$inbox/.export.XXXXXXXX")
trap 'rm -f -- "$temporary"' EXIT
/usr/local/bin/podman --remote=false save --format docker-archive   --output "$temporary" "localhost/$service-ac:$revision"
mv -f -- "$temporary" "$archive"
sudo -n "/usr/local/sbin/ac-$service-import" "$revision"
rm -f -- "$archive"
