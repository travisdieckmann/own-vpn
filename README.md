# own-vpn
The most secure VPN is the one you run yourself.

## Configuration Cleanup
```bash
docker-compose down
rm -f .env Caddyfile dashboard.env docker-compose.yml management.json turnserver.conf zdb.env zitadel.env peer.json
rm -f machinekey/zitadel-admin-sa.token
rm -rf data/netbird_management/*
rm -rf data/netbird_zdb_data/*
rm -rf data/netbird_zitadel_certs/*
```

#### ToDo
- Avoid Service User token expiration
  - Rerun python on a cron to test when token expires?

## CDK Info
This is a blank project for CDK development with TypeScript.

The `cdk.json` file tells the CDK Toolkit how to execute your app.

## Useful commands

* `npm run build`   compile typescript to js
* `npm run watch`   watch for changes and compile
* `npm run test`    perform the jest unit tests
* `npx cdk deploy`  deploy this stack to your default AWS account/region
* `npx cdk diff`    compare deployed stack with current state
* `npx cdk synth`   emits the synthesized CloudFormation template
