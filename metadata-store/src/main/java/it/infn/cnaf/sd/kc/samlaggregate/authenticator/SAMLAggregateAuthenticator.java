package it.infn.cnaf.sd.kc.samlaggregate.authenticator;

import static it.infn.cnaf.sd.kc.wayf.resources.SAMLAggregateWayfResource.ENTITY_ID_PARAM;
import static it.infn.cnaf.sd.kc.wayf.resources.SAMLAggregateWayfResource.RETURN_PARAM;

import java.net.URI;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.resources.RealmsResource;

import it.infn.cnaf.sd.kc.samlaggregate.resources.SAMLAggregateBrokerResource;
import it.infn.cnaf.sd.kc.wayf.resources.SAMLAggregateWayfResource;

public class SAMLAggregateAuthenticator implements Authenticator {

  public final String SAML_AGGREGATE_AUTH_PROVIDER = "samlaggregate";
  public final String SAML_AGGREGATE_AUTH_IDP = "idp";

  private static final Logger LOG = Logger.getLogger(SAMLAggregateAuthenticator.class);

  @Override
  public void authenticate(AuthenticationFlowContext context) {

    if (hasProvider(context)) {
      String provider = getProvider(context);
      if (hasIdp(context)) {
        String idp = getIdp(context);
        // Redirect to SAML aggregate login end-point with IDP
        redirectToBrokerLogin(context, provider, idp);
      } else {
        // Redirect to WAYF: which is your PROVIDER's IDP?
        redirectToWayf(context, provider);
      }
    } else {
      // nothing to do
      context.attempted();
    }
  }

  private boolean hasProvider(AuthenticationFlowContext context) {
    return context.getUriInfo().getQueryParameters().containsKey(SAML_AGGREGATE_AUTH_PROVIDER);
  }

  private String getProvider(AuthenticationFlowContext context) {
    return context.getUriInfo().getQueryParameters().getFirst(SAML_AGGREGATE_AUTH_PROVIDER);
  }

  private boolean hasIdp(AuthenticationFlowContext context) {
    return context.getUriInfo().getQueryParameters().containsKey(SAML_AGGREGATE_AUTH_IDP);
  }

  private String getIdp(AuthenticationFlowContext context) {
    return context.getUriInfo().getQueryParameters().getFirst(SAML_AGGREGATE_AUTH_IDP);
  }

  protected void redirectToWayf(AuthenticationFlowContext context, String provider) {

    UriBuilder uriBuilder = UriBuilder.fromUri(context.getUriInfo().getBaseUri())
      .path(RealmsResource.class)
      .path(RealmsResource.class, "getRealmResource")
      .path("saml-wayf")
      .path(SAMLAggregateWayfResource.class, "discover");
    uriBuilder.queryParam(ENTITY_ID_PARAM, getEntityId(context));

    URI redirectUri = UriBuilder.fromUri(context.getUriInfo().getBaseUri())
        .path(RealmsResource.class)
        .path(RealmsResource.class, "getRealmResource")
        .path("saml-aggregate-broker")
        .path(SAMLAggregateBrokerResource.class, "login")
        .build(context.getRealm().getName(), provider);

    uriBuilder.queryParam(RETURN_PARAM, redirectUri);

    URI location = uriBuilder.build(context.getRealm().getName(), provider);
    Response response = Response.seeOther(location).build();
    context.forceChallenge(response);
  }

  private String getEntityId(AuthenticationFlowContext context) {
    return context.getHttpRequest().getUri().getBaseUri().toString();
  }

  private void redirectToBrokerLogin(AuthenticationFlowContext context, String provider, String idp) {

    UriBuilder uriBuilder = UriBuilder.fromUri(context.getUriInfo().getBaseUri())
        .path(RealmsResource.class)
        .path(RealmsResource.class, "getRealmResource")
        .path("saml-aggregate-broker")
        .path(SAMLAggregateBrokerResource.class, "login");

    URI location = uriBuilder.queryParam("idp", idp).build(context.getRealm().getName(), provider);

    Response response = Response.seeOther(location).build();
    context.forceChallenge(response);
  }

  @Override
  public void action(AuthenticationFlowContext context) {

  }

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

  }

  @Override
  public void close() {

  }
}
