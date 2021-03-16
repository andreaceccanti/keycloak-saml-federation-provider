FROM cnafsd/kc:latest

ADD standalone.xml /opt/jboss/keycloak/standalone/configuration/
RUN mkdir -p /opt/jboss/keycloak/modules/it/infn/sd/keycloak-saml-metadata-store/main
ADD module.xml /opt/jboss/keycloak/modules/it/infn/sd/keycloak-saml-metadata-store/main

