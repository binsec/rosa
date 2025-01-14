#!/usr/bin/env bash

## Run a Docker container with the ROSA toolchain image.
## The name of the Docker image is specified by the IMAGE file.
## The version of the Docker image is specified by the VERSION file.


set -e

docker run -ti --rm -p 4000:4000 $(cat IMAGE):$(cat VERSION)
