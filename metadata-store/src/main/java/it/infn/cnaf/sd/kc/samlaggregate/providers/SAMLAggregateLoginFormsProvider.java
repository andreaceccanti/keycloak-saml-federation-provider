package it.infn.cnaf.sd.kc.samlaggregate.providers;

import javax.ws.rs.core.Response;

import org.keycloak.forms.login.LoginFormsPages;
import org.keycloak.forms.login.freemarker.FreeMarkerLoginFormsProvider;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resources.LoginActionsService;

import it.infn.cnaf.sd.kc.samlaggregate.resources.SAMLAggregateBrokerResource;

public class SAMLAggregateLoginFormsProvider extends FreeMarkerLoginFormsProvider {

  public SAMLAggregateLoginFormsProvider(KeycloakSession session) {
    super(session);
  }

  @Override
  protected Response createResponse(LoginFormsPages page) {
    switch (page) {
      case LOGIN:
      case LOGIN_IDP_LINK_CONFIRM:
      case LOGIN_UPDATE_PROFILE:
        if (isSAMLAggregateLoginSession()) {
          actionUri =
            SAMLAggregateBrokerResource.firstBrokerLoginProcessor(session.getContext().getUri())
              .queryParam(LoginActionsService.SESSION_CODE, accessCode)
              .queryParam(Constants.EXECUTION, execution)
              .queryParam(Constants.CLIENT_ID, authenticationSession.getClient().getClientId())
              .queryParam(Constants.TAB_ID, authenticationSession.getTabId())
              .build(realm.getName());
        }
        break;
      default:
        break;
    }
    return super.createResponse(page);
  }

  private boolean isSAMLAggregateLoginSession() {
    return authenticationSession.getAuthNote("IS_SAML_AGGREGATE") != null;
  }
}
