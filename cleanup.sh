#!/bin/bash

cd geth
sudo docker compose down

cd ../client
cargo clean
