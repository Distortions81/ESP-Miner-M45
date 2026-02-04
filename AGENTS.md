# ESP-Miner Agent Notes

## Repo Layout (quick map)
- `components/`: main ESP-IDF components (including `components/stratum`).
- `test/`: unit test app (builds a test firmware image).
- `test-ci/`: CI test app.
- `tools/dockerbuild.py`: helper for running builds in Docker/Podman.
- `quick-linux-build.sh`: Docker build script for the main app.
- `doc/unit_testing.md`: unit testing instructions.

## Build (main firmware)
### Docker (recommended)
- Uses `espressif/idf:release-v5.5` in `quick-linux-build.sh`.
- Run from repo root:

```bash
./quick-linux-build.sh
```

### Docker via helper (custom command)
```bash
./tools/dockerbuild.py idf.py build
```

## Unit Tests (ESP32S3 target)
Tests are built into a firmware image and run **on device** (not on host).

### Build unit test firmware (Docker)
```bash
# Build only the stratum tests
./tools/dockerbuild.py --workspace ~/github/ESP-Miner/test \
  idf.py -DTEST_COMPONENTS=stratum build
```

This produces `test/build/unit_test_stratum.bin`.
If your repo is in a different location, update the `--workspace` path accordingly.

### Flash + monitor (requires device)
See `doc/unit_testing.md` for full details. Quick outline:
- Flashing the unit test image **replaces** the normal firmware.
- Use `idf.py -p /dev/ttyACM0 flash` (or the `esptool` command in the doc).
- Monitor with `idf.py -p /dev/ttyACM0 monitor`.

## Common Pitfalls
- `idf.py -T ...` is **not** a valid option; use `-DTEST_COMPONENTS=stratum` with the test app.
- Unit tests don’t run on the host; they run on the ESP32 after flashing.
- Docker runs should not require a TTY; avoid `-it` when running non-interactively.

## Useful Paths
- Stratum parser: `components/stratum/stratum_api.c`
- Stratum tests: `components/stratum/test/test_stratum_json.c`
