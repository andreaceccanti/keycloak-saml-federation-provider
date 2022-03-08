package it.infn.cnaf.sd.kc.spi.impl;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

import it.infn.cnaf.sd.kc.spi.SAMLAggregateFederatedIdentityServiceProvider;
import it.infn.cnaf.sd.kc.spi.SAMLAggregateFederatedIdentityServiceProviderFactory;

public class SAMLAggregateFederatedIdentityServiceProviderFactoryImpl
    implements SAMLAggregateFederatedIdentityServiceProviderFactory {

  @Override
  public SAMLAggregateFederatedIdentityServiceProvider create(KeycloakSession session) {
    return new SAMLAggregateFederatedIdentityServiceProviderImpl(session);
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
    return "SAMLAggregateFederatedIdentityServiceImpl";
  }

}
