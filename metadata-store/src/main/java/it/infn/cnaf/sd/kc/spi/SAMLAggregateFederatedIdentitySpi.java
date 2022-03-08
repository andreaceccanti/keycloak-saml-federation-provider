package it.infn.cnaf.sd.kc.spi;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

public class SAMLAggregateFederatedIdentitySpi implements Spi {

  @Override
  public boolean isInternal() {
    return false;
  }

  @Override
  public String getName() {
    return "SAMLAggregateFederatedIdentity";
  }

  @Override
  public Class<? extends Provider> getProviderClass() {
    return SAMLAggregateFederatedIdentityServiceProvider.class;
  }

  @Override
  @SuppressWarnings("rawtypes")
  public Class<? extends ProviderFactory> getProviderFactoryClass() {
    return SAMLAggregateFederatedIdentityServiceProviderFactory.class;
  }

}
