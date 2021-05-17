package it.infn.cnaf.sd.kc.wayf.resources;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class SAMLAggregateWayfRealmResourceProvider implements RealmResourceProvider {

  private final KeycloakSession session;

  SAMLAggregateWayfRealmResourceProvider(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public void close() {
  }

  @Override
  public Object getResource() {
    return new SAMLAggregateWayfRealmResource(session);
  }

}
