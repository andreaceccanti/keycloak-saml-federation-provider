package it.infn.cnaf.sd.kc.samlaggregate.providers;

import org.keycloak.Config.Scope;
import org.keycloak.forms.login.LoginFormsProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.theme.FreeMarkerUtil;

public class SAMLAggregateLoginFormsProviderFactory implements LoginFormsProviderFactory {

  private FreeMarkerUtil freeMarker;

  @Override
  public SAMLAggregateLoginFormsProvider create(KeycloakSession session) {
    return new SAMLAggregateLoginFormsProvider(session, freeMarker);
  }

  @Override
  public void init(Scope config) {
    freeMarker = new FreeMarkerUtil();
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
  }

  @Override
  public void close() {
    freeMarker = null;
  }

  @Override
  public String getId() {
    return "samlaggregate-login-forms-provider";

  }

}
