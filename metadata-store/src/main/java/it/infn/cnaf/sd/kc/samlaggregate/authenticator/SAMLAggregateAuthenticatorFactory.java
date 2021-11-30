package it.infn.cnaf.sd.kc.samlaggregate.authenticator;

import java.util.List;

import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class SAMLAggregateAuthenticatorFactory implements AuthenticatorFactory {

  protected static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES =
      {AuthenticationExecutionModel.Requirement.REQUIRED,
          AuthenticationExecutionModel.Requirement.ALTERNATIVE,
          AuthenticationExecutionModel.Requirement.DISABLED};

  public static final String PROVIDER_ID = "saml-aggregate-authenticator";

  @Override
  public Authenticator create(KeycloakSession session) {
    return new SAMLAggregateAuthenticator();
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
    return PROVIDER_ID;
  }

  @Override
  public String getDisplayType() {
    return "SAML Aggregate Authenticator";
  }

  @Override
  public String getReferenceCategory() {
    return null;
  }

  @Override
  public boolean isConfigurable() {
    return false;
  }

  @Override
  public Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public String getHelpText() {
    return "Redirects to SAML WAYF or Identity Provider specified with idp query parameter";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return null;
  }

}
