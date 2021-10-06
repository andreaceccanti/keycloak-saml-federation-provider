package it.infn.cnaf.sd.kc.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class SamlFederationAuthenticator implements Authenticator {

  private static final Logger LOG = Logger.getLogger(SamlFederationAuthenticator.class);

  @Override
  public void close() {
    // TODO Auto-generated method stub
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    // TODO Auto-generated method stub

  }

  @Override
  public void action(AuthenticationFlowContext context) {
    // TODO Auto-generated method stub

  }

  @Override
  public boolean requiresUser() {
    // TODO Auto-generated method stub
    return false;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    // TODO Auto-generated method stub
    return false;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    // TODO Auto-generated method stub

  }

}
