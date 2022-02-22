package it.infn.cnaf.sd.kc.samlaggregate.resources;

import static it.infn.cnaf.sd.kc.samlaggregate.authenticator.SAMLAggregateAuthenticator.SAML_AGGREGATE_AUTH_PROVIDER;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import javax.ws.rs.GET;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriBuilder;

import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.OAuthErrorException;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.provider.IdentityProviderFactory;
import org.keycloak.broker.provider.util.IdentityBrokerState;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.constants.ServiceUrlConstants;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.AuthenticationFlowResolver;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.protocol.saml.JaxrsSAML2BindingBuilder;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.saml.SAML2AuthnRequestBuilder;
import org.keycloak.saml.SAML2NameIDPolicyBuilder;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resources.IdentityBrokerService;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.services.resources.SessionCodeChecks;
import org.keycloak.services.resources.account.AccountFormService;
import org.keycloak.services.util.BrowserHistoryHelper;
import org.keycloak.services.util.CacheControlUtil;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

import com.google.common.base.Strings;

import it.infn.cnaf.sd.kc.metadata.SAMLAggregateMetadataStoreProvider;
import it.infn.cnaf.sd.kc.metadata.SAMLIdpDescriptor;

public class SAMLAggregateBrokerResource
    implements RealmResourceProvider, IdentityProvider.AuthenticationCallback {

  protected static final Logger LOG = Logger.getLogger(SAMLAggregateBrokerResource.class);

  private final RealmModel realmModel;

  @Context
  private KeycloakSession session;

  @Context
  private ClientConnection clientConnection;

  @Context
  private HttpRequest request;

  @Context
  private HttpHeaders headers;

  private EventBuilder event;

  public SAMLAggregateBrokerResource(KeycloakSession session) {
    this.realmModel = session.getContext().getRealm();
  }

  public void init() {
    this.event = new EventBuilder(realmModel, session, clientConnection)
      .event(EventType.IDENTITY_PROVIDER_LOGIN);
  }

  @GET
  @Path("{provider}/login")
  @Produces(MediaType.APPLICATION_FORM_URLENCODED)
  public Response login(final @PathParam("provider") String provider,
      final @QueryParam("idp") String idp) throws URISyntaxException, SAMLAggregateBrokerException {

    RealmModel realm = session.getContext().getRealm();

    ClientModel client =
        session.clients().getClientByClientId(realm, Constants.ACCOUNT_CONSOLE_CLIENT_ID);

    AuthenticationSessionModel authSession = createAuthenticationSession(realm, client);
    authSession.setProtocol(SamlProtocol.LOGIN_PROTOCOL);
    authSession.setRedirectUri(RedirectUtils.getFirstValidRedirectUri(session, client.getRootUrl(), client.getRedirectUris()));

    ClientSessionCode<AuthenticationSessionModel> clientSessionCode =
        new ClientSessionCode<>(session, realm, authSession);
    clientSessionCode.setAction(AuthenticationSessionModel.Action.AUTHENTICATE.name());

    if (Strings.isNullOrEmpty(provider)) {
      return redirectToLoginPage(realm);
    }
    if (Strings.isNullOrEmpty(idp)) {
      return redirectToWAYF(realm, provider);
    }

    IdentityProviderModel identityProviderModel = realm.getIdentityProviderByAlias(provider);
    if (identityProviderModel == null) {
      return redirectToBadRequest("Identity Provider [" + provider + "] not found.");
    }
    if (identityProviderModel.isLinkOnly()) {
      return redirectToBadRequest(
          "Identity Provider [" + provider + "] is not allowed to perform a login.");
    }

    String issuerURL = getIssuer(provider);

    // SAMLAggregateIdentityProviderConfig config = null;
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

    AuthenticationRequest request = createAuthenticationRequest(session, realm, this.request,
        provider, clientSessionCode, assertionConsumerServiceUrl);

    try {

      SAML2AuthnRequestBuilder authnRequestBuilder =
          new SAML2AuthnRequestBuilder().assertionConsumerUrl(assertionConsumerServiceUrl)
            .destination(destinationUrl)
            .issuer(issuerURL)
            .forceAuthn(isForceAuthn)
            .protocolBinding(protocolBinding)
            .nameIdPolicy(SAML2NameIDPolicyBuilder.format(nameIDPolicyFormat));
      JaxrsSAML2BindingBuilder binding =
          new JaxrsSAML2BindingBuilder(session).relayState(request.getState().getEncoded());

      AuthnRequestType authnRequest = authnRequestBuilder.createAuthnRequest();

      if (authnRequest.getDestination() != null) {
        destinationUrl = authnRequest.getDestination().toString();
      }

      // Save the current RequestID in the Auth Session as we need to verify it against the ID
      // returned from the IdP
      authSession.setClientNote(SamlProtocol.SAML_REQUEST_ID, authnRequest.getID());

      if (postBinding) {
        return binding.postBinding(authnRequestBuilder.toDocument()).request(destinationUrl);
      } else {
        return binding.redirectBinding(authnRequestBuilder.toDocument()).request(destinationUrl);
      }
    } catch (Exception e) {
      throw new SAMLAggregateBrokerException("Could not create authentication request.", e);
    }
  }

  private AuthenticationRequest createAuthenticationRequest(KeycloakSession session,
      RealmModel realm, HttpRequest request, String providerId,
      ClientSessionCode<AuthenticationSessionModel> clientSessionCode, String redirectUri) {
    AuthenticationSessionModel authSession = null;
    IdentityBrokerState encodedState = null;

    if (clientSessionCode != null) {
      authSession = clientSessionCode.getClientSession();
      String relayState = clientSessionCode.getOrGenerateCode();
      encodedState = IdentityBrokerState.decoded(relayState, authSession.getClient().getClientId(),
          authSession.getTabId());
    }

    return new AuthenticationRequest(session, realm, authSession, request,
        session.getContext().getUri(), encodedState, redirectUri);
  }

  private AuthenticationSessionModel createAuthenticationSession(RealmModel realm,
      ClientModel client) {

    AuthenticationSessionManager manager = new AuthenticationSessionManager(session);
    RootAuthenticationSessionModel rootAuthSession =
        manager.getCurrentRootAuthenticationSession(realm);

    if (rootAuthSession != null) {
      return rootAuthSession.createAuthenticationSession(client);
    }
    return null;
  }

  private Response redirectToWAYF(RealmModel realm, String provider) {
    return Response
      .temporaryRedirect(UriBuilder.fromPath(ServiceUrlConstants.ACCOUNT_SERVICE_PATH)
        .queryParam(SAML_AGGREGATE_AUTH_PROVIDER, provider)
        .build(realm.getName()))
      .build();
  }

  private Response redirectToLoginPage(RealmModel realm) {
    return Response
      .temporaryRedirect(UriBuilder.fromPath(ServiceUrlConstants.AUTH_PATH).build(realm.getName()))
      .build();
  }

  private Response redirectToBadRequest(String message) {
    return Response.status(Status.BAD_REQUEST).entity(message).build();
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

  private String getIssuer(String providerAlias) {

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
  public Object authenticate(@PathParam("provider") String providerAlias,
      @QueryParam("idp") String idp) {

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
    IdentityProviderModel identityProviderModel =
        session.getContext().getRealm().getIdentityProviderByAlias(alias);

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

    IdentityBrokerState state = IdentityBrokerState.encoded(encodedCode);
    String code = state.getDecodedState();
    String clientId = state.getClientId();
    String tabId = state.getTabId();
    return parseSessionCode(code, clientId, tabId);
  }

  /**
   * This method will throw JAX-RS exception in case it is not able to retrieve
   * AuthenticationSessionModel. It never returns null
   */
  private AuthenticationSessionModel parseSessionCode(String code, String clientId, String tabId) {
    if (code == null || clientId == null || tabId == null) {
      LOG.debugf(
          "Invalid request. Authorization code, clientId or tabId was null. Code=%s, clientId=%s, tabID=%s",
          code, clientId, tabId);
      Response staleCodeError =
          redirectToErrorPage(Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
      throw new WebApplicationException(staleCodeError);
    }

    SessionCodeChecks checks = new SessionCodeChecks(session.getContext().getRealm(),
        session.getContext().getUri(), request, clientConnection, session, event, null, code, null,
        clientId, tabId, LoginActionsService.AUTHENTICATE_PATH);
    checks.initialVerify();
    if (!checks.verifyActiveAndValidAction(AuthenticationSessionModel.Action.AUTHENTICATE.name(),
        ClientSessionCode.ActionType.LOGIN)) {

      AuthenticationSessionModel authSession = checks.getAuthenticationSession();
      if (authSession != null) {
        // Check if error happened during login or during linking from account management
        Response accountManagementFailedLinking =
            checkAccountManagementFailedLinking(authSession, Messages.STALE_CODE_ACCOUNT);
        if (accountManagementFailedLinking != null) {
          throw new WebApplicationException(accountManagementFailedLinking);
        } else {
          Response errorResponse = checks.getResponse();

          // Remove "code" from browser history
          errorResponse = BrowserHistoryHelper.getInstance()
            .saveResponseAndRedirect(session, authSession, errorResponse, true, request);
          throw new WebApplicationException(errorResponse);
        }
      } else {
        throw new WebApplicationException(checks.getResponse());
      }
    } else {
      return checks.getClientCode().getClientSession();
    }
  }

  private Response redirectToErrorPage(Response.Status status, String message,
      Object... parameters) {
    return redirectToErrorPage(null, status, message, null, parameters);
  }

  private Response redirectToErrorPage(AuthenticationSessionModel authSession,
      Response.Status status, String message, Throwable throwable, Object... parameters) {
    if (message == null) {
      message = Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR;
    }

    fireErrorEvent(message, throwable);

    if (throwable != null && throwable instanceof WebApplicationException) {
      WebApplicationException webEx = (WebApplicationException) throwable;
      return webEx.getResponse();
    }

    return ErrorPage.error(this.session, authSession, status, message, parameters);
  }

  @Override
  public Response authenticated(BrokeredIdentityContext context) {

    LOG.info("authenticated(" + context.toString() + ")");

    IdentityBrokerService brokerService = new IdentityBrokerService(realmModel);
    ResteasyProviderFactory.getInstance().injectProperties(brokerService);
    brokerService.init();
    return brokerService.authenticated(context);
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
