FROM cnafsd/kc:latest

ADD standalone.xml /opt/jboss/keycloak/standalone/configuration/
RUN mkdir -p /opt/jboss/keycloak/modules/it/infn/cnaf/sd/kc/keycloak-saml-federation-provider/main
ADD module.xml /opt/jboss/keycloak/modules/it/infn/cnaf/sd/kc/keycloak-saml-federation-provider/main

