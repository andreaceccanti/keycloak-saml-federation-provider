package it.infn.cnaf.sd.kc.wayf.resources;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class SAMLAggregateWayfResourceFactory implements RealmResourceProviderFactory {

  public static final String ID = "saml-wayf";

  @Override
  public RealmResourceProvider create(KeycloakSession session) {
    return new SAMLAggregateWayfRealmResourceProvider(session);
  }

  @Override
  public void init(Scope config) {
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
  }

  @Override
  public void close() {
  }

  @Override
  public String getId() {
    return ID;
  }

}
