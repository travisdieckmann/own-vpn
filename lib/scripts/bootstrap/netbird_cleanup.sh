#!/usr/bin/bash

cd /opt/vpn

docker-compose down
rm -f .env Caddyfile dashboard.env docker-compose.yml management.json turnserver.conf zdb.env zitadel.env peer.json
rm -f machinekey/zitadel-admin-sa.token
rm -rf data/netbird_management/*
rm -rf data/netbird_zdb_data/*
rm -rf data/netbird_zitadel_certs/*