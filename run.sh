#!/bin/bash

cd geth
sudo docker compose up -d

cd ../client
cargo test
