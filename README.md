# Roadrunner

Roadrunner is an ACME client to provide certificates in a idempotent way to a number of services on a system.

Similar to certbot in functionality but different in configuration and operation - Roadrunner is configured with a YAML file and will keep certificates up to date without involving `CRON` and is configured more closely to cert-manager with a separation of ACME Issuers/Solvers and requested Certificates.