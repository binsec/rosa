#!/usr/bin/env bash

## Start up the Docker container.


set -e

# Start up the documentation server.
nohup simple-http-server -i -p 4000 &
echo "Go to http://localhost:4000 to see the ROSA documentation."
# Start an interactive session.
bash
