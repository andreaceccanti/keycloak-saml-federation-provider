# Keycloak SAML federation provider

This repo provides an initial implementation for support of SAML federations in
Keycloak.

## Build instructions

This build relies on changes not yet merged upstream. 
To have the required dependencies, checkout this branch:

https://github.com/enricovianello/keycloak/tree/cnafsd

and install it locally:

```
mvn install -DskipTests -DskipTestsuite
```

## Create needed Docker image

Clone official docker containers repository:

```
git clone git@github.com:keycloak/keycloak-containers
cd keycloak-containers
```

Build `cnafsd/eosc-kc` image:

```
cd server
docker build -e KEYCLOAK_VERSION=16.0.0-SNAPSHOT --build-arg GIT_REPO=enricovianello/keycloak --build-arg GIT_BRANCH=cnafsd -t cnafsd/eosc-kc .
```

## Run compose file locally

Package this source module:

```
mvn clean package
```

and then run your compose:

```
cd compose
docker-compose up
```
