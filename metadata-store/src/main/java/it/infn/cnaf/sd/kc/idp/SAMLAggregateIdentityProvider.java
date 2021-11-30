package it.infn.cnaf.sd.kc.idp;

import java.net.URI;
import java.util.UUID;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.IdentityProviderDataMarshaller;
import org.keycloak.broker.saml.SAMLDataMarshaller;
import org.keycloak.constants.ServiceUrlConstants;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.utils.PkceUtils;
import org.keycloak.saml.validators.DestinationValidator;
import org.keycloak.services.managers.AuthenticationManager;

import it.infn.cnaf.sd.kc.metadata.SAMLIdpDescriptor;


public class SAMLAggregateIdentityProvider
    extends AbstractIdentityProvider<SAMLAggregateIdentityProviderConfig> {

  protected static final Logger logger =
      Logger.getLogger(SAMLAggregateIdentityProviderConfig.class);

  private final String PKCE_METHOD = "S256";
  private final String RESPONSE_TYPE = "code";
  private final String SCOPE = "openid";

  private DestinationValidator destinationValidator;

  public SAMLAggregateIdentityProvider(KeycloakSession session,
      SAMLAggregateIdentityProviderConfig config, DestinationValidator destinationValidator) {
    super(session, config);
    this.destinationValidator = destinationValidator;
  }

  @Override
  public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {

    return Response.ok(identity.getToken()).build();
  }

  @Override
  public Response performLogin(AuthenticationRequest request) {

    String state = UUID.randomUUID().toString();
    String codeVerifier = PkceUtils.generateCodeVerifier();
    String codeChallenge = PkceUtils.encodeCodeChallenge(codeVerifier, PKCE_METHOD);
    String clientId = request.getSession().getContext().getClient().getClientId();
    String redirectUri = UriBuilder.fromUri(request.getUriInfo().getBaseUri())
      .path(ServiceUrlConstants.ACCOUNT_SERVICE_PATH)
      .build(request.getRealm().getName())
      .toString();

    URI authUri = UriBuilder.fromPath(ServiceUrlConstants.AUTH_PATH)
      .queryParam("samlaggregate", getConfig().getAlias())
      .queryParam(OAuth2Constants.CODE_CHALLENGE, codeChallenge)
      .queryParam(OAuth2Constants.CODE_CHALLENGE_METHOD, PKCE_METHOD)
      .queryParam(OAuth2Constants.CLIENT_ID, clientId)
      .queryParam(OAuth2Constants.STATE, state)
      .queryParam(OAuth2Constants.SCOPE, SCOPE)
      .queryParam(OAuth2Constants.RESPONSE_TYPE, RESPONSE_TYPE)
      .queryParam(OAuth2Constants.REDIRECT_URI, redirectUri)
      .build(request.getRealm().getName());

    return Response.temporaryRedirect(authUri).build();
  }

  @Override
  public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {

    String idp = (String) session.getAttribute("idp");

    SAMLIdpDescriptor descriptor = null;
    return new SAMLAggregateEndpoint(realm, this, getConfig(), callback, descriptor,
        destinationValidator);
  }

//  @Override
//  public IdentityProviderDataMarshaller getMarshaller() {
//    return new SAMLDataMarshaller();
//  }

}
