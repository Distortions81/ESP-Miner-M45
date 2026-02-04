#!/usr/bin/env bash
set -euo pipefail

sudo rm -rf /home/dist/github/ESP-Miner/build

docker run --rm -it \
  -v /home/dist/github/ESP-Miner:/home/dist/github/ESP-Miner:rw \
  -w /home/dist/github/ESP-Miner \
  --user root \
  espressif/idf:release-v5.5 \
  bash -lc "apt-get update && apt-get install -y curl ca-certificates openjdk-17-jre-headless && \
            curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
            apt-get install -y nodejs && \
            git config --global --add safe.directory /opt/esp/idf/components/openthread/openthread && \
            git config --global --add safe.directory /home/dist/github/ESP-Miner && \
            idf.py fullclean && \
            idf.py build"
