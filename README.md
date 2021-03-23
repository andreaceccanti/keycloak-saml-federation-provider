# Keycloak SAML federation provider

This repo provides an initial implementation for support of SAML federations in
Keycloak.

## Build instructions

This build relies on changes not yet merged upstream. 
To have the required dependencies, checkout this branch:

https://github.com/eosc-kc/keycloak/tree/metadata-enchancments

and install it locally:

```
mvn install -DskipTests
```

