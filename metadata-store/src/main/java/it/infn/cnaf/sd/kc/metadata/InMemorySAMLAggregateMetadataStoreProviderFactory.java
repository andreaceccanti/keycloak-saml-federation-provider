package it.infn.cnaf.sd.kc.metadata;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class InMemorySAMLAggregateMetadataStoreProviderFactory
    implements SAMLAggregateMetadataStoreProviderFactory {

  public static final String ID = "in-memory-saml-md";

  private volatile InMemorySAMLAggregateMetadataStoreProvider INSTANCE;

  @Override
  public SAMLAggregateMetadataStoreProvider create(KeycloakSession session) {

    if (INSTANCE == null) {
      INSTANCE = new InMemorySAMLAggregateMetadataStoreProvider(session);
    }
    return INSTANCE;
  }

  @Override
  public void init(Scope config) {
    System.out.println("init InMemorySAMLAggregateMetadataStoreProviderFactory");
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    System.out.println("postInit InMemorySAMLAggregateMetadataStoreProviderFactory");
  }

  @Override
  public void close() {
    // nothing to do here
  }

  @Override
  public String getId() {
    return ID;
  }

}
