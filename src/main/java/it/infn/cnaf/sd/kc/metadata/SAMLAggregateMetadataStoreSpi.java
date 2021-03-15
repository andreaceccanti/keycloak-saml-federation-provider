package it.infn.cnaf.sd.kc.metadata;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

public class SAMLAggregateMetadataStoreSpi implements Spi {

  public static final String NAME = "saml-aggregate-metadata-store";

  @Override
  public boolean isInternal() {
    return false;
  }

  @Override
  public String getName() {
    return NAME;
  }

  @Override
  public Class<? extends Provider> getProviderClass() {
    return SAMLAggregateMetadataStoreProvider.class;
  }

  @SuppressWarnings("rawtypes")
  @Override
  public Class<? extends ProviderFactory> getProviderFactoryClass() {
    return SAMLAggregateMetadataStoreProviderFactory.class;
  }



}
