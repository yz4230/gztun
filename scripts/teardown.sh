#!/bin/bash
set -euo pipefail

ip link del gztun0 || true
ip link del dummy0 || true
