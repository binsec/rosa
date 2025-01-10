#!/usr/bin/env bash

## Start up the Docker container.


set -e

# Start up the documentation server.
# TODO: replace this with [hyper](https://hyper.rs/) or something.
nohup python3 -m http.server -d /root/rosa/doc/book 4000 &
echo "Go to http://localhost:4000 to see the ROSA documentation."
# Start an interactive session.
bash
