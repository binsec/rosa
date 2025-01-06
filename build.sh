#!/usr/bin/env bash

## Build Docker image for the ROSA toolchain.
## The name of the Docker image is specified by the IMAGE file.
## The version of the Docker image is specified by the VERSION file.


set -e

# The command `git submodule status` displays the list of registered submodules in the current
# repo. If a submodule is not cloned/uninitialized, its corresponding line in the command's output
# is prefixed with a '-'. So, by looking at the first byte, we can tell if any submodule is not
# cloned and stop the build.
status_list=$(git submodule status --recursive | cut -b 1)
for status in $status_list
do
    if [ "$status" == "-" ]
    then
        echo "At least one submodule is uninitialized; stopping build." 1>&2
        echo "Run \`git submodule update --init --recursive\` at the root of the repo." 1>&2
        exit 1
    fi
done

docker build -t $(cat IMAGE):$(cat VERSION) . --label "version=$(cat VERSION)"
