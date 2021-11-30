package it.infn.cnaf.sd.kc.samlaggregate.resources;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class SAMLAggregateBrokerResourceProviderFactory implements RealmResourceProviderFactory {

  public static final String ID = "saml-aggregate-broker";

  @Override
  public RealmResourceProvider create(KeycloakSession session) {
    return new SAMLAggregateBrokerResource(session);
  }

  @Override
  public void init(Scope config) {
    // TODO Auto-generated method stub
    
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    // TODO Auto-generated method stub
    
  }

  @Override
  public void close() {
    // TODO Auto-generated method stub
    
  }

  @Override
  public String getId() {
    return ID;
  }

}
