#!/bin/bash
# this only used on linux x86
rm -rf target
cargo build --target=x86_64-unknown-linux-gnu --release -vv
