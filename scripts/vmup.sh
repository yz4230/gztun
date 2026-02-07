#!/bin/bash
set -euxo pipefail

vagrant up
vagrant ssh-config --host vm >ssh-config
