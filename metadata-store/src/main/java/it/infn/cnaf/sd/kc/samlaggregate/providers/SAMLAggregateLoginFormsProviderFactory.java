package it.infn.cnaf.sd.kc.samlaggregate.providers;

import org.keycloak.Config.Scope;
import org.keycloak.forms.login.LoginFormsProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class SAMLAggregateLoginFormsProviderFactory implements LoginFormsProviderFactory {

  @Override
  public SAMLAggregateLoginFormsProvider create(KeycloakSession session) {
    return new SAMLAggregateLoginFormsProvider(session);
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
    return "samlaggregate-login-forms-provider";

  }

}
