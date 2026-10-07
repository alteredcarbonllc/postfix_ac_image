#!/bin/sh
set -eu
service=postfix
[ "${CI_REPO:-}" = "alteredcarbonllc/postfix_ac_image" ]
[ "${CI_COMMIT_BRANCH:-}" = main ]
case "${CI_PIPELINE_EVENT:-}" in push|manual) ;; *) exit 1;; esac
revision=${CI_COMMIT_SHA:?}
[ "${#revision}" = 40 ]
case "$revision" in *[!0-9a-f]*) exit 1;; esac
test "$(id -u)" = 1001
test "$(git rev-parse HEAD)" = "$revision"
test -z "$(git status --porcelain)"
pod() { /usr/local/bin/podman --remote=false "$@"; }
test "$(pod info --format '{{.Host.Security.Rootless}}')" = true
image="localhost/$service-ac:$revision"
fixture="localhost/$service-ci-fixture:$revision"
if ! pod image exists "$image"; then
    pod build --network=slirp4netns       --label "org.opencontainers.image.revision=$revision"       -f Containerfile.ci -t "$image" .
fi
if ! pod image exists "$fixture"; then
    pod build --network=slirp4netns       -f ops/ci/fixtures/Containerfile -t "$fixture" .
fi
python3 ops/ci/test-image.py "$image" "$fixture" "$revision"
sh ops/ci/export-image.sh
echo "MAIL_CANDIDATE_READY: $service $revision; production unchanged"
