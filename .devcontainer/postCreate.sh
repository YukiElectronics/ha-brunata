#!/usr/bin/env bash

set -e

git config --global --add safe.directory $PWD

sudo pre-commit install -c .github/pre-commit.yml
