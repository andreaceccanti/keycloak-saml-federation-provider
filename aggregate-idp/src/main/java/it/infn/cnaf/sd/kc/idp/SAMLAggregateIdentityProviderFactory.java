package it.infn.cnaf.sd.kc.idp;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class SAMLAggregateIdentityProviderFactory
    extends AbstractIdentityProviderFactory<SAMLAggregateIdentityProvider> {

  public static final String PROVIDER_ID = "saml-aggregate";
  public static final String PROVIDER_NAME = "SAML v2.0 Aggregate";

  private KeycloakSessionFactory sessionFactory;

  public SAMLAggregateIdentityProviderFactory() {
    // empty on purpose
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    this.sessionFactory = factory;
  }

  @Override
  public String getName() {
    return PROVIDER_NAME;
  }

  @SuppressWarnings("unchecked")
  @Override
  public SAMLAggregateIdentityProviderConfig createConfig() {
    SAMLAggregateIdentityProviderConfig config = new SAMLAggregateIdentityProviderConfig();
    config.setSessionFactory(sessionFactory);
    return config;
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public SAMLAggregateIdentityProvider create(KeycloakSession session,
      IdentityProviderModel model) {


    SAMLAggregateIdentityProviderConfig config = new SAMLAggregateIdentityProviderConfig(model);

    return new SAMLAggregateIdentityProvider(session, config);
  }

}
