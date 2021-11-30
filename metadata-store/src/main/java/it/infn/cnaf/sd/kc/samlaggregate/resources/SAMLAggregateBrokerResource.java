package it.infn.cnaf.sd.kc.samlaggregate.resources;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Iterator;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.Response.Status;

import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.OAuthErrorException;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.provider.IdentityProviderFactory;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.broker.saml.SAMLEndpoint;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.constants.ServiceUrlConstants;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.dom.saml.v2.protocol.StatusResponseType;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.Constants;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.AuthenticationFlowResolver;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.saml.JaxrsSAML2BindingBuilder;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.protocol.saml.SamlSessionUtils;
import org.keycloak.protocol.saml.preprocessor.SamlAuthenticationPreprocessor;
import org.keycloak.saml.SAML2AuthnRequestBuilder;
import org.keycloak.saml.SAML2NameIDPolicyBuilder;
import org.keycloak.saml.common.constants.GeneralConstants;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.services.resources.account.AccountFormService;
import org.keycloak.services.util.AuthenticationFlowURLHelper;
import org.keycloak.services.util.CacheControlUtil;
import org.keycloak.services.validation.Validation;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

import com.google.common.base.Strings;

import it.infn.cnaf.sd.kc.metadata.SAMLAggregateMetadataStoreProvider;
import it.infn.cnaf.sd.kc.metadata.SAMLIdpDescriptor;

public class SAMLAggregateBrokerResource
    implements RealmResourceProvider, IdentityProvider.AuthenticationCallback {

  protected static final Logger LOG = Logger.getLogger(SAMLAggregateBrokerResource.class);

  @Context
  private HttpRequest request;

  @Context
  private HttpHeaders headers;

  private KeycloakSession session;

  private EventBuilder event;

  public SAMLAggregateBrokerResource(KeycloakSession session) {
    this.session = session;
    this.event = new EventBuilder(session.getContext().getRealm(), session,
        session.getContext().getConnection());
  }

  @GET
  @Path("{provider}/login")
  @Produces(MediaType.TEXT_HTML)
  public Response login(final @PathParam("provider") String provider,
      final @QueryParam("idp") String idp) throws URISyntaxException, SAMLAggregateBrokerException {

    if (Strings.isNullOrEmpty(idp)) {
      return redirectToWAYF(provider);
    }

    RealmModel realm = session.getContext().getRealm();
    String issuerURL = getEntityId(provider);

    IdentityProviderModel identityProviderModel = realm.getIdentityProviderByAlias(provider);
    if (identityProviderModel == null) {
      throw new SAMLAggregateBrokerException("Identity Provider [" + provider + "] not found.");
    }
    if (identityProviderModel.isLinkOnly()) {
      throw new SAMLAggregateBrokerException(
          "Identity Provider [" + provider + "] is not allowed to perform a login.");
    }
    // identityProviderModel.getConfig();

    // SAMLAggregateIdentityProviderConfig config = identityProvider.;
    // if (identityProviderModel.getConfig() instanceof SAMLAggregateIdentityProviderConfig) {
    // config = (SAMLAggregateIdentityProviderConfig) identityProviderModel.getConfig();
    // } else {
    // throw new SAMLAggregateBrokerException("Invalid Identity Provider Config");
    // }

    // to-do get it from config
    String nameIDPolicyFormat = JBossSAMLURIConstants.NAMEID_FORMAT_PERSISTENT.get();

    String assertionConsumerServiceUrl = getRedirectUri(provider, idp);

    SAMLIdpDescriptor idpDescr = getIdentityProviderFromEntityId(realm, provider, idp);

    String protocolBinding = JBossSAMLURIConstants.SAML_HTTP_REDIRECT_BINDING.get();
    if (idpDescr.isPostBindingResponse()) {
      protocolBinding = JBossSAMLURIConstants.SAML_HTTP_POST_BINDING.get();
    }

    String destinationUrl = idpDescr.getSingleSignOnServiceUrl();

    Boolean isForceAuthn = false; // to-do use config.isForceAuthn();
    boolean postBinding = idpDescr.isPostBindingResponse();

    try {

      // UriInfo uriInfo = request.getUriInfo();

      SAML2AuthnRequestBuilder authnRequestBuilder =
          new SAML2AuthnRequestBuilder().assertionConsumerUrl(assertionConsumerServiceUrl)
            .destination(destinationUrl)
            .issuer(issuerURL)
            .forceAuthn(isForceAuthn)
            .protocolBinding(protocolBinding)
            .nameIdPolicy(SAML2NameIDPolicyBuilder.format(nameIDPolicyFormat));
      JaxrsSAML2BindingBuilder binding = new JaxrsSAML2BindingBuilder(session);

      AuthnRequestType authnRequest = authnRequestBuilder.createAuthnRequest();
      // for(Iterator<SamlAuthenticationPreprocessor> it =
      // SamlSessionUtils.getSamlAuthenticationPreprocessorIterator(session); it.hasNext(); ) {
      // authnRequest = it.next().beforeSendingLoginRequest(authnRequest,
      // request.getAuthenticationSession());
      // }

      if (authnRequest.getDestination() != null) {
        destinationUrl = authnRequest.getDestination().toString();
      }

      // Save the current RequestID in the Auth Session as we need to verify it against the ID
      // returned from the IdP
      // request.getAuthenticationSession().setClientNote(SamlProtocol.SAML_REQUEST_ID,
      // authnRequest.getID());

      if (postBinding) {
        return binding.postBinding(authnRequestBuilder.toDocument()).request(destinationUrl);
      } else {
        return binding.redirectBinding(authnRequestBuilder.toDocument()).request(destinationUrl);
      }
    } catch (Exception e) {
      throw new IdentityBrokerException("Could not create authentication request.", e);
    }

    // return Response.ok("Got idp " + idp).build();
  }

  private Response redirectToWAYF(String provider) {
    // TODO Auto-generated method stub
    return null;
  }

  private String getRedirectUri(String providerAlias, String idp) {

    return UriBuilder.fromUri(session.getContext().getAuthServerUrl())
      .path(RealmsResource.class)
      .path(RealmsResource.class, "getRealmResource")
      .path("saml-aggregate-broker")
      .path(SAMLAggregateBrokerResource.class, "authenticate")
      .queryParam("idp", idp)
      .build(session.getContext().getRealm().getName(), providerAlias)
      .toString();
  }

  private String getEntityId(String providerAlias) {

    return UriBuilder.fromUri(session.getContext().getAuthServerUrl())
      .path("realms")
      .path(session.getContext().getRealm().getName())
      .path(providerAlias)
      .build()
      .toString();
  }

  private SAMLIdpDescriptor getIdentityProviderFromEntityId(RealmModel realm, String providerAlias,
      String entityId) throws SAMLAggregateBrokerException {

    SAMLAggregateMetadataStoreProvider md =
        session.getProvider(SAMLAggregateMetadataStoreProvider.class);

    Optional<SAMLIdpDescriptor> result = md.lookupIdpByEntityId(realm, providerAlias, entityId);

    if (!result.isPresent()) {
      throw new SAMLAggregateBrokerException(
          "Could not create authentication request. entity_id " + entityId + " not found.");
    }

    return result.get();
  }

  @Path("{provider}/authenticate")
  public Object authenticate(@PathParam("provider") String providerAlias, @QueryParam("idp") String idp) {
    IdentityProvider<?> identityProvider;

    try {
      identityProvider = getIdentityProvider(session, providerAlias);
    } catch (IdentityBrokerException e) {
      throw new NotFoundException(e.getMessage());
    }

    session.setAttribute("idp", idp);

    Object callback = identityProvider.callback(session.getContext().getRealm(), this, event);
    ResteasyProviderFactory.getInstance().injectProperties(callback);
    return callback;
  }

  public static IdentityProvider<?> getIdentityProvider(KeycloakSession session, String alias) {
    IdentityProviderModel identityProviderModel = session.getContext().getRealm().getIdentityProviderByAlias(alias);

    if (identityProviderModel != null) {
      IdentityProviderFactory<?> providerFactory =
          getIdentityProviderFactory(session, identityProviderModel);

      if (providerFactory == null) {
        throw new IdentityBrokerException(
            "Could not find factory for identity provider [" + alias + "].");
      }

      return providerFactory.create(session, identityProviderModel);
    }

    throw new IdentityBrokerException("Identity Provider [" + alias + "] not found.");
  }

  public static IdentityProviderFactory<?> getIdentityProviderFactory(KeycloakSession session,
      IdentityProviderModel model) {
    return Stream
      .concat(
          session.getKeycloakSessionFactory().getProviderFactoriesStream(IdentityProvider.class),
          session.getKeycloakSessionFactory()
            .getProviderFactoriesStream(SocialIdentityProvider.class))
      .filter(providerFactory -> Objects.equals(providerFactory.getId(), model.getProviderId()))
      .map(IdentityProviderFactory.class::cast)
      .findFirst()
      .orElse(null);
  }

  @Override
  public void close() {}

  @Override
  public Object getResource() {
    return this;
  }

  @Override
  public AuthenticationSessionModel getAndVerifyAuthenticationSession(String encodedCode) {

    LOG.info("getAndVerifyAuthenticationSession(" + encodedCode + ")");
    return null;
  }

  @Override
  public Response authenticated(BrokeredIdentityContext context) {

    LOG.info("authenticated(" + context.toString() + ")");
    return null;

//    IdentityProviderModel identityProviderConfig = context.getIdpConfig();
//    AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
//    RealmModel realmModel = session.getContext().getRealm();
//
//    String providerId = identityProviderConfig.getAlias();
//    if (!identityProviderConfig.isStoreToken()) {
//      context.setToken(null);
//    }
//
//    StatusResponseType loginResponse =
//        (StatusResponseType) context.getContextData().get(SAMLEndpoint.SAML_LOGIN_RESPONSE);
//    if (loginResponse != null) {
//      for (Iterator<SamlAuthenticationPreprocessor> it =
//          SamlSessionUtils.getSamlAuthenticationPreprocessorIterator(session); it.hasNext();) {
//        loginResponse =
//            it.next().beforeProcessingLoginResponse(loginResponse, authenticationSession);
//      }
//    }
//
//    session.getContext().setClient(authenticationSession.getClient());
//
//    context.getIdp().preprocessFederatedIdentity(session, realmModel, context);
//    KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();
//    realmModel.getIdentityProviderMappersByAliasStream(context.getIdpConfig().getAlias())
//      .forEach(mapper -> {
//        IdentityProviderMapper target = (IdentityProviderMapper) sessionFactory
//          .getProviderFactory(IdentityProviderMapper.class, mapper.getIdentityProviderMapper());
//        target.preprocessFederatedIdentity(session, realmModel, mapper, context);
//      });
//
//    FederatedIdentityModel federatedIdentityModel = new FederatedIdentityModel(providerId,
//        context.getId(), context.getUsername(), context.getToken());
//
//    this.event.event(EventType.IDENTITY_PROVIDER_LOGIN)
//      .detail(Details.REDIRECT_URI, authenticationSession.getRedirectUri())
//      .detail(Details.IDENTITY_PROVIDER, providerId)
//      .detail(Details.IDENTITY_PROVIDER_USERNAME, context.getUsername());
//
//    UserModel federatedUser =
//        this.session.users().getUserByFederatedIdentity(realmModel, federatedIdentityModel);
//    boolean shouldMigrateId = false;
//    // try to find the user using legacy ID
//    if (federatedUser == null && context.getLegacyId() != null) {
//      federatedIdentityModel =
//          new FederatedIdentityModel(federatedIdentityModel, context.getLegacyId());
//      federatedUser =
//          this.session.users().getUserByFederatedIdentity(realmModel, federatedIdentityModel);
//      shouldMigrateId = true;
//    }
//
//    // Check if federatedUser is already authenticated (this means linking social into existing
//    // federatedUser account)
//    UserSessionModel userSession =
//        new AuthenticationSessionManager(session).getUserSession(authenticationSession);
//    if (shouldPerformAccountLinking(authenticationSession, userSession, providerId)) {
//      return performAccountLinking(authenticationSession, userSession, context,
//          federatedIdentityModel, federatedUser);
//    }
//
//    if (federatedUser == null) {
//
//      LOG.debugf("Federated user not found for provider '%s' and broker username '%s'",
//          providerId, context.getUsername());
//
//      String username = context.getModelUsername();
//      if (username == null) {
//        if (realmModel.isRegistrationEmailAsUsername()
//            && !Validation.isBlank(context.getEmail())) {
//          username = context.getEmail();
//        } else if (context.getUsername() == null) {
//          username = context.getIdpConfig().getAlias() + "." + context.getId();
//        } else {
//          username = context.getUsername();
//        }
//      }
//      username = username.trim();
//      context.setModelUsername(username);
//
//      SerializedBrokeredIdentityContext ctx0 =
//          SerializedBrokeredIdentityContext.readFromAuthenticationSession(authenticationSession,
//              AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);
//      if (ctx0 != null) {
//        SerializedBrokeredIdentityContext ctx1 =
//            SerializedBrokeredIdentityContext.serialize(context);
//        ctx1.saveToAuthenticationSession(authenticationSession,
//            AbstractIdpAuthenticator.NESTED_FIRST_BROKER_CONTEXT);
//        LOG.warnv("Nested first broker flow detected: {0} -> {1}", ctx0.getIdentityProviderId(),
//            ctx1.getIdentityProviderId());
//        LOG.debug("Resuming last execution");
//        URI redirect =
//            new AuthenticationFlowURLHelper(session, realmModel, session.getContext().getUri())
//              .getLastExecutionUrl(authenticationSession);
//        return Response.status(Status.FOUND).location(redirect).build();
//      }
//
//      LOG.debug("Redirecting to flow for firstBrokerLogin");
//
//      boolean forwardedPassiveLogin = "true"
//        .equals(authenticationSession.getAuthNote(AuthenticationProcessor.FORWARDED_PASSIVE_LOGIN));
//      // Redirect to firstBrokerLogin after successful login and ensure that previous authentication
//      // state removed
//      AuthenticationProcessor.resetFlow(authenticationSession,
//          LoginActionsService.FIRST_BROKER_LOGIN_PATH);
//
//      // Set the FORWARDED_PASSIVE_LOGIN note (if needed) after resetting the session so it is not
//      // lost.
//      if (forwardedPassiveLogin) {
//        authenticationSession.setAuthNote(AuthenticationProcessor.FORWARDED_PASSIVE_LOGIN, "true");
//      }
//
//      SerializedBrokeredIdentityContext ctx = SerializedBrokeredIdentityContext.serialize(context);
//      ctx.saveToAuthenticationSession(authenticationSession,
//          AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);
//
//      URI redirect = LoginActionsService.firstBrokerLoginProcessor(session.getContext().getUri())
//        .queryParam(Constants.CLIENT_ID, authenticationSession.getClient().getClientId())
//        .queryParam(Constants.TAB_ID, authenticationSession.getTabId())
//        .build(realmModel.getName());
//      return Response.status(302).location(redirect).build();
//
//    } else {
//      Response response = validateUser(authenticationSession, federatedUser, realmModel);
//      if (response != null) {
//        return response;
//      }
//
//      updateFederatedIdentity(context, federatedUser);
//      if (shouldMigrateId) {
//        migrateFederatedIdentityId(context, federatedUser);
//      }
//      authenticationSession.setAuthenticatedUser(federatedUser);
//
//      return finishOrRedirectToPostBrokerLogin(authenticationSession, context, false);
//    }
  }

  @Override
  public Response cancelled() {

    AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();

    Response accountManagementFailedLinking =
        checkAccountManagementFailedLinking(authSession, Messages.CONSENT_DENIED);
    if (accountManagementFailedLinking != null) {
      return accountManagementFailedLinking;
    }

    return browserAuthentication(authSession, null);
  }

  @Override
  public Response error(String message) {

    AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();

    Response accountManagementFailedLinking =
        checkAccountManagementFailedLinking(authSession, message);
    if (accountManagementFailedLinking != null) {
      return accountManagementFailedLinking;
    }

    Response passiveLoginErrorReturned = checkPassiveLoginError(authSession, message);
    if (passiveLoginErrorReturned != null) {
      return passiveLoginErrorReturned;
    }

    return browserAuthentication(authSession, message);
  }

  /**
   * Checks if specified message matches one of the passive login error messages and if it does
   * builds a response that redirects the error back to the client.
   *
   * @param authSession the authentication session.
   * @param message the error message.
   * @return a {@code {@link Response}} that redirects the error message back to the client if the
   *         {@code message} is one of the passive login error messages, or {@code null} if it is
   *         not.
   */
  private Response checkPassiveLoginError(AuthenticationSessionModel authSession, String message) {
    LoginProtocol.Error error = OAuthErrorException.LOGIN_REQUIRED.equals(message)
        ? LoginProtocol.Error.PASSIVE_LOGIN_REQUIRED
        : (OAuthErrorException.INTERACTION_REQUIRED.equals(message)
            ? LoginProtocol.Error.PASSIVE_INTERACTION_REQUIRED
            : null);
    if (error != null) {
      LoginProtocol protocol = session.getProvider(LoginProtocol.class, authSession.getProtocol());
      protocol.setRealm(session.getContext().getRealm())
        .setHttpHeaders(headers)
        .setUriInfo(session.getContext().getUri())
        .setEventBuilder(event);
      return protocol.sendError(authSession, error);
    }
    return null;
  }

  private Response checkAccountManagementFailedLinking(AuthenticationSessionModel authSession,
      String error, Object... parameters) {
    UserSessionModel userSession =
        new AuthenticationSessionManager(session).getUserSession(authSession);
    if (userSession != null && authSession.getClient() != null
        && authSession.getClient().getClientId().equals(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID)) {

      this.event.event(EventType.FEDERATED_IDENTITY_LINK);
      UserModel user = userSession.getUser();
      this.event.user(user);
      this.event.detail(Details.USERNAME, user.getUsername());

      return redirectToAccountErrorPage(authSession, error, parameters);
    } else {
      return null;
    }
  }

  private Response redirectToAccountErrorPage(AuthenticationSessionModel authSession,
      String message, Object... parameters) {
    fireErrorEvent(message);

    FormMessage errorMessage = new FormMessage(message, parameters);
    try {
      String serializedError = JsonSerialization.writeValueAsString(errorMessage);
      authSession.setAuthNote(AccountFormService.ACCOUNT_MGMT_FORWARDED_ERROR_NOTE,
          serializedError);
    } catch (IOException ioe) {
      throw new RuntimeException(ioe);
    }

    URI accountServiceUri = UriBuilder.fromUri(authSession.getRedirectUri())
      .queryParam(Constants.TAB_ID, authSession.getTabId())
      .build();
    return Response.status(302).location(accountServiceUri).build();
  }

  private void fireErrorEvent(String message) {
    fireErrorEvent(message, null);
  }

  private void fireErrorEvent(String message, Throwable throwable) {
    if (!this.event.getEvent().getType().toString().endsWith("_ERROR")) {
      boolean newTransaction = !this.session.getTransactionManager().isActive();

      try {
        if (newTransaction) {
          this.session.getTransactionManager().begin();
        }

        this.event.error(message);

        if (newTransaction) {
          this.session.getTransactionManager().commit();
        }
      } catch (Exception e) {
        ServicesLogger.LOGGER.couldNotFireEvent(e);
        rollback();
      }
    }

    if (throwable != null) {
      LOG.error(message, throwable);
    } else {
      LOG.error(message);
    }
  }

  private void rollback() {
    if (this.session.getTransactionManager().isActive()) {
      this.session.getTransactionManager().rollback();
    }
  }

  protected Response browserAuthentication(AuthenticationSessionModel authSession,
      String errorMessage) {

    this.event.event(EventType.LOGIN);
    AuthenticationFlowModel flow = AuthenticationFlowResolver.resolveBrowserFlow(authSession);
    String flowId = flow.getId();
    AuthenticationProcessor processor = new AuthenticationProcessor();
    processor.setAuthenticationSession(authSession)
      .setFlowPath(LoginActionsService.AUTHENTICATE_PATH)
      .setFlowId(flowId)
      .setBrowserFlow(true)
      .setConnection(session.getContext().getConnection())
      .setEventBuilder(event)
      .setRealm(session.getContext().getRealm())
      .setSession(session)
      .setUriInfo(session.getContext().getUri())
      .setRequest(request);
    if (errorMessage != null)
      processor.setForwardedErrorMessage(new FormMessage(null, errorMessage));

    try {
      CacheControlUtil.noBackButtonCacheControlHeader();
      return processor.authenticate();
    } catch (Exception e) {
      return processor.handleBrowserException(e);
    }
  }
}
