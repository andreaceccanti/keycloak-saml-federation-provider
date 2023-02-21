package it.infn.cnaf.sd.kc.idp;

import static it.infn.cnaf.sd.kc.samlaggregate.resources.SAMLAggregateBrokerResource.SESSION_SAML_AGGREGATE_ENTITY_ID_ATTRIBUTE;
import static it.infn.cnaf.sd.kc.samlaggregate.resources.SAMLAggregateBrokerResource.SESSION_SAML_AGGREGATE_ENTITY_ID_CLIENT_NOTE;
import static it.infn.cnaf.sd.kc.wayf.resources.SAMLAggregateWayfResource.ENTITY_ID_PARAM;
import static it.infn.cnaf.sd.kc.wayf.resources.SAMLAggregateWayfResource.RETURN_PARAM;

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
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AuthnStatementType;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.assertion.SubjectType;
import org.keycloak.dom.saml.v2.protocol.ResponseType;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.Constants;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.utils.PkceUtils;
import org.keycloak.saml.SignatureAlgorithm;
import org.keycloak.saml.validators.DestinationValidator;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.sessions.AuthenticationSessionModel;

import it.infn.cnaf.sd.kc.metadata.SAMLAggregateMetadataStoreProvider;
import it.infn.cnaf.sd.kc.metadata.SAMLIdpDescriptor;
import it.infn.cnaf.sd.kc.samlaggregate.authenticator.SAMLAggregateAuthenticator;
import it.infn.cnaf.sd.kc.samlaggregate.resources.SAMLAggregateBrokerResource;
import it.infn.cnaf.sd.kc.samlaggregate.resources.SAMLAggregateBrokerResource.RequestType;
import it.infn.cnaf.sd.kc.wayf.resources.SAMLAggregateWayfResource;


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

    URI redirectUri = UriBuilder.fromUri(request.getUriInfo().getBaseUri())
        .path(RealmsResource.class)
        .path(RealmsResource.class, "getRealmResource")
        .path("saml-aggregate-broker")
        .path(SAMLAggregateBrokerResource.class, "login")
        .build(session.getContext().getRealm().getName(), getConfig().getAlias());

    URI location = UriBuilder.fromUri(request.getUriInfo().getBaseUri())
      .path(RealmsResource.class)
      .path(RealmsResource.class, "getRealmResource")
      .path("saml-wayf")
      .path(SAMLAggregateWayfResource.class, "discover")
      .queryParam(ENTITY_ID_PARAM, request.getUriInfo().getBaseUri().toString())
      .queryParam(RETURN_PARAM, redirectUri)
      .build(session.getContext().getRealm().getName(), getConfig().getAlias());

    return Response.temporaryRedirect(location).build();

    
//    String state = request.getAuthenticationSession().getClientNote(OAuth2Constants.STATE);
//    String codeChallenge = request.getAuthenticationSession().getClientNote(OAuth2Constants.CODE_CHALLENGE);
//    String codeChallengeMethod = request.getAuthenticationSession().getClientNote(OAuth2Constants.CODE_CHALLENGE_METHOD);
//    String clientId = request.getAuthenticationSession().getClient().getClientId();
//    String redirectUri = getSamlAggregateBrokerAuthenticateRedirectUri();
//    String responseType = request.getAuthenticationSession().getClientNote(OAuth2Constants.RESPONSE_TYPE);
//    String scope = request.getAuthenticationSession().getClientNote(OAuth2Constants.SCOPE);
//
//    UriBuilder builder = UriBuilder.fromPath(ServiceUrlConstants.AUTH_PATH)
//        .queryParam(AdapterConstants.KC_IDP_HINT, getConfig().getAlias())
//        .queryParam(OAuth2Constants.CODE_CHALLENGE, codeChallenge)
//        .queryParam(OAuth2Constants.CODE_CHALLENGE_METHOD, codeChallengeMethod)
//        .queryParam(OAuth2Constants.CLIENT_ID, clientId)
//        .queryParam(OAuth2Constants.STATE, state)
//        .queryParam(OAuth2Constants.SCOPE, scope)
//        .queryParam(OAuth2Constants.RESPONSE_TYPE, responseType)
//        .queryParam(OAuth2Constants.REDIRECT_URI, redirectUri)
//        .queryParam(SAMLAggregateAuthenticator.SAML_AGGREGATE_AUTH_PROVIDER, getConfig().getAlias());
//
//    URI authUri = builder.build(request.getRealm().getName());

//    return Response.temporaryRedirect(authUri).build();
  }

  private String getSamlAggregateBrokerAuthenticateRedirectUri() {
    UriBuilder builder = UriBuilder.fromUri(session.getContext().getAuthServerUrl())
        .path(RealmsResource.class)
        .path(RealmsResource.class, "getRealmResource")
        .path("saml-aggregate-broker")
        .path(SAMLAggregateBrokerResource.class, "authenticate");
      return builder.build(session.getContext().getRealm().getName()).toString();
  }

  @Override
  public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {

    String entityId = (String) session.getAttribute(SESSION_SAML_AGGREGATE_ENTITY_ID_ATTRIBUTE);
    String link = (String) session.getAttribute("link");

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

    session.removeAttribute(SESSION_SAML_AGGREGATE_ENTITY_ID_ATTRIBUTE);
    authSession.removeClientNote(SESSION_SAML_AGGREGATE_ENTITY_ID_CLIENT_NOTE);

    ResponseType responseType = (ResponseType) context.getContextData().get(SAMLAggregateEndpoint.SAML_LOGIN_RESPONSE);
    AssertionType assertion = (AssertionType) context.getContextData().get(SAMLAggregateEndpoint.SAML_ASSERTION);
    SubjectType subject = assertion.getSubject();
    SubjectType.STSubType subType = subject.getSubType();
    if (subType != null) {
        NameIDType subjectNameID = (NameIDType) subType.getBaseID();
        authSession.setUserSessionNote(SAMLAggregateEndpoint.SAML_FEDERATED_SUBJECT_NAMEID, subjectNameID.serializeAsString());
    }
    AuthnStatementType authn = (AuthnStatementType) context.getContextData().get(SAMLAggregateEndpoint.SAML_AUTHN_STATEMENT);
    if (authn != null && authn.getSessionIndex() != null) {
        authSession.setUserSessionNote(SAMLAggregateEndpoint.SAML_FEDERATED_SESSION_INDEX, authn.getSessionIndex());
    }
    if (authSession.getRedirectUri().endsWith("account/identity")) {
       // linking
       authSession.setUserSessionNote(Details.IDENTITY_PROVIDER, null);
    } else {
       // login
       authSession.setUserSessionNote(Details.IDENTITY_PROVIDER, context.getIdpConfig().getAlias());
       authSession.setUserSessionNote(Details.IDENTITY_PROVIDER_USERNAME, context.getUsername());
       authSession.setUserSessionNote(SAMLAggregateEndpoint.SAML_FEDERATED_SESSION_ENTITY_ID, responseType.getIssuer().getValue());
    }
  }

  @Override
  public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm,
      BrokeredIdentityContext context) {

    String entityId = (String) session.getAttribute(SESSION_SAML_AGGREGATE_ENTITY_ID_ATTRIBUTE);
    // context.getContextData().put("ENTITY_ID", entityId);
    context.getAuthenticationSession()
      .setClientNote(SESSION_SAML_AGGREGATE_ENTITY_ID_CLIENT_NOTE, entityId);

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
