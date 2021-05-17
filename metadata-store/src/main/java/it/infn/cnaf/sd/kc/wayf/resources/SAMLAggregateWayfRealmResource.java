package it.infn.cnaf.sd.kc.wayf.resources;

import javax.ws.rs.Path;

import org.keycloak.models.KeycloakSession;

public class SAMLAggregateWayfRealmResource {

  private final KeycloakSession session;

  public SAMLAggregateWayfRealmResource(KeycloakSession session) {
    this.session = session;
  }

  @Path("")
  public SAMLAggregateWayfResource getWayfResource() {
    return new SAMLAggregateWayfResource(session);
  }
}
