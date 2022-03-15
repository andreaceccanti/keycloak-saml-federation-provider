package it.infn.cnaf.sd.kc.idp;

import java.net.URI;
import java.util.Optional;
import java.util.UUID;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityProviderDataMarshaller;
import org.keycloak.broker.saml.SAMLDataMarshaller;
import org.keycloak.constants.AdapterConstants;
import org.keycloak.constants.ServiceUrlConstants;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.utils.PkceUtils;
import org.keycloak.saml.SignatureAlgorithm;
import org.keycloak.saml.validators.DestinationValidator;
import org.keycloak.sessions.AuthenticationSessionModel;

import it.infn.cnaf.sd.kc.metadata.SAMLAggregateMetadataStoreProvider;
import it.infn.cnaf.sd.kc.metadata.SAMLIdpDescriptor;
import it.infn.cnaf.sd.kc.samlaggregate.authenticator.SAMLAggregateAuthenticator;
import it.infn.cnaf.sd.kc.spi.FederatedIdentityRepresentation;
import it.infn.cnaf.sd.kc.spi.SAMLAggregateFederatedIdentityServiceProvider;


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

    SAMLAggregateMetadataStoreProvider md =
        session.getProvider(SAMLAggregateMetadataStoreProvider.class);
    md.parseMetadata(session.getContext().getRealm(), config.getAlias(), config.getMetadataUrl());
  }

  @Override
  public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {

    return Response.ok(identity.getToken()).build();
  }

  @Override
  public Response performLogin(AuthenticationRequest request) {

    return doRedirectionToWayf(request);
  }

  private Response doRedirectionToWayf(AuthenticationRequest request) {

    String state = UUID.randomUUID().toString();
    String codeVerifier = PkceUtils.generateCodeVerifier();
    String codeChallenge = PkceUtils.encodeCodeChallenge(codeVerifier, PKCE_METHOD);
    String clientId = request.getSession().getContext().getClient().getClientId();
    String redirectUri = UriBuilder.fromUri(request.getUriInfo().getBaseUri())
      .path(ServiceUrlConstants.ACCOUNT_SERVICE_PATH)
      .build(request.getRealm().getName())
      .toString();

    URI authUri = UriBuilder.fromPath(ServiceUrlConstants.AUTH_PATH)
      .queryParam(AdapterConstants.KC_IDP_HINT, getConfig().getAlias())
      .queryParam(OAuth2Constants.CODE_CHALLENGE, codeChallenge)
      .queryParam(OAuth2Constants.CODE_CHALLENGE_METHOD, PKCE_METHOD)
      .queryParam(OAuth2Constants.CLIENT_ID, clientId)
      .queryParam(OAuth2Constants.STATE, state)
      .queryParam(OAuth2Constants.SCOPE, SCOPE)
      .queryParam(OAuth2Constants.RESPONSE_TYPE, RESPONSE_TYPE)
      .queryParam(OAuth2Constants.REDIRECT_URI, redirectUri)
      .queryParam(SAMLAggregateAuthenticator.SAML_AGGREGATE_AUTH_PROVIDER, getConfig().getAlias())
      .build(request.getRealm().getName());

    return Response.temporaryRedirect(authUri).build();
  }

  @Override
  public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {

    String entityId = (String) session.getAttribute("idp");

    SAMLAggregateMetadataStoreProvider md =
        session.getProvider(SAMLAggregateMetadataStoreProvider.class);
    Optional<SAMLIdpDescriptor> descriptor =
        md.lookupIdpByEntityId(realm, getConfig().getAlias(), entityId);
    if (descriptor.isEmpty()) {
      throw new RuntimeException("descriptor not found");
    }
    return new SAMLAggregateEndpoint(realm, this, getConfig(), callback, destinationValidator,
        descriptor.get());
  }

  public SignatureAlgorithm getSignatureAlgorithm() {
    String alg = getConfig().getSignatureAlgorithm();
    if (alg != null) {
      SignatureAlgorithm algorithm = SignatureAlgorithm.valueOf(alg);
      if (algorithm != null)
        return algorithm;
    }
    return SignatureAlgorithm.RSA_SHA256;
  }


  @Override
  public IdentityProviderDataMarshaller getMarshaller() {
    return new SAMLDataMarshaller();
  }

  @Override
  public void authenticationFinished(AuthenticationSessionModel authSession,
      BrokeredIdentityContext context) {

    String realmId = authSession.getRealm().getId();
    String entityId = String.valueOf(context.getContextData().get("ENTITY_ID"));
    String providerId = getConfig().getProviderId();
    String userId = authSession.getAuthenticatedUser().getId();

    SAMLAggregateFederatedIdentityServiceProvider fis =
        session.getProvider(SAMLAggregateFederatedIdentityServiceProvider.class);

    if (fis.findFederatedIdentity(userId, providerId, entityId) != null) {
      return;
    }

    FederatedIdentityRepresentation fi = new FederatedIdentityRepresentation();
    fi.setRealmId(realmId);
    fi.setIdentityProvider(providerId);
    fi.setFederatedEntityId(entityId);
    fi.setUserId(userId);
    fi.setFederatedUserId(context.getBrokerUserId());
    fi.setFederatedUsername(context.getUsername());

    fis.addFederatedIdentity(fi);

  }

  @Override
  public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm,
      BrokeredIdentityContext context) {

    String entityId = (String) session.getAttribute("idp");
    context.getContextData().put("ENTITY_ID", entityId);

  }

  @Override
  public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user,
      BrokeredIdentityContext context) {

  }

  @Override
  public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user,
      BrokeredIdentityContext context) {

  }
}
