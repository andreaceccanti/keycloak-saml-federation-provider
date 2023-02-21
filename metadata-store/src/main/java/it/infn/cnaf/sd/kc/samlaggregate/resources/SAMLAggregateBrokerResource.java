package it.infn.cnaf.sd.kc.samlaggregate.resources;

import static it.infn.cnaf.sd.kc.samlaggregate.authenticator.SAMLAggregateAuthenticator.SAML_AGGREGATE_AUTH_PROVIDER;
import static org.keycloak.events.Details.IDENTITY_PROVIDER;
import static org.keycloak.events.Details.IDENTITY_PROVIDER_USERNAME;
import static org.keycloak.events.Details.REDIRECT_URI;
import static org.keycloak.events.EventType.FEDERATED_IDENTITY_LINK;
import static org.keycloak.events.EventType.IDENTITY_PROVIDER_LOGIN;
import static org.keycloak.models.AccountRoles.MANAGE_ACCOUNT;
import static org.keycloak.models.Constants.ACCOUNT_CONSOLE_CLIENT_ID;
import static org.keycloak.models.Constants.ACCOUNT_MANAGEMENT_CLIENT_ID;
import static org.keycloak.services.messages.Messages.ACCOUNT_DISABLED;
import static org.keycloak.services.messages.Messages.IDENTITY_PROVIDER_NOT_FOUND;
import static org.keycloak.services.messages.Messages.INSUFFICIENT_PERMISSION;
import static org.keycloak.services.messages.Messages.INVALID_REDIRECT_URI;
import static org.keycloak.services.messages.Messages.MISSING_IDENTITY_PROVIDER;
import static org.keycloak.services.messages.Messages.SESSION_NOT_ACTIVE;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.POST;
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
import javax.ws.rs.core.UriInfo;

import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.OAuthErrorException;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.PostBrokerLoginConstants;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.provider.IdentityProviderFactory;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.broker.provider.IdentityProviderMapperSyncModeDelegate;
import org.keycloak.broker.provider.util.IdentityBrokerState;
import org.keycloak.broker.saml.SAMLEndpoint;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.ObjectUtil;
import org.keycloak.common.util.Time;
import org.keycloak.constants.ServiceUrlConstants;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.dom.saml.v2.protocol.StatusResponseType;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.locale.LocaleSelectorProvider;
import org.keycloak.locale.LocaleUpdaterProvider;
import org.keycloak.models.AccountRoles;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.Constants;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.AuthenticationFlowResolver;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.LoginProtocol.Error;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.protocol.saml.JaxrsSAML2BindingBuilder;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.protocol.saml.SamlSessionUtils;
import org.keycloak.protocol.saml.preprocessor.SamlAuthenticationPreprocessor;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.representations.account.AccountLinkUriRepresentation;
import org.keycloak.saml.SAML2AuthnRequestBuilder;
import org.keycloak.saml.SAML2NameIDPolicyBuilder;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.ErrorPageException;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.ForbiddenException;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.Auth;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resources.Cors;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.services.resources.SessionCodeChecks;
import org.keycloak.services.resources.account.AccountFormService;
import org.keycloak.services.util.AuthenticationFlowURLHelper;
import org.keycloak.services.util.BrowserHistoryHelper;
import org.keycloak.services.util.CacheControlUtil;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.keycloak.services.validation.Validation;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

import com.google.common.base.Strings;

import it.infn.cnaf.sd.kc.metadata.SAMLAggregateMetadataStoreProvider;
import it.infn.cnaf.sd.kc.metadata.SAMLIdpDescriptor;
import it.infn.cnaf.sd.kc.samlaggregate.authenticator.SAMLAggregateAuthenticator;
import it.infn.cnaf.sd.kc.samlaggregate.resources.model.SAMLAggregateLinkedAccountRepresentation;
import it.infn.cnaf.sd.kc.spi.SAMLAggregateFederatedIdentityServiceProvider;
import it.infn.cnaf.sd.kc.spi.SamlAggregateFederatedIdentityDTO;

public class SAMLAggregateBrokerResource
    implements RealmResourceProvider, IdentityProvider.AuthenticationCallback {

  // Authentication session note, which references identity provider that is currently linked
  private static final String LINKING_IDENTITY_PROVIDER = "LINKING_IDENTITY_PROVIDER";

  protected static final Logger LOG = Logger.getLogger(SAMLAggregateBrokerResource.class);
  public static final String SESSION_SAML_AGGREGATE_ENTITY_ID_ATTRIBUTE = "SAML_AGGREGATE_IDP";
  public static final String SESSION_SAML_AGGREGATE_ENTITY_ID_CLIENT_NOTE = "ENTITY_ID";
  public static final String SESSION_SAML_AGGREGATE_LINKING_ATTRIBUTE = "LINK";

  public static final String FIRST_BROKER_LOGIN_PATH = "saml-first-broker-login";
  public static final String AUTHENTICATE_PATH = "authenticate";

  public static final String SESSION_CODE = "session_code";
  public static final String AUTH_SESSION_ID = "auth_session_id";

  public static final String FORWARDED_ERROR_MESSAGE_NOTE = "forwardedErrorMessage";

  @Context
  private ClientConnection clientConnection;

  @Context
  private HttpRequest request;

  @Context
  private HttpHeaders headers;

  private final KeycloakSession session;
  private final RealmModel realm;
  private final AppAuthManager authManager;

  private SAMLAggregateFederatedIdentityServiceProvider federatedIdentitiesService;
  private EventBuilder event;

  public enum RequestType {
    LOGIN,
    LINKING,
    LOGOUT;
  }

  public SAMLAggregateBrokerResource(KeycloakSession session) {
    this.session = session;
    this.realm = session.getContext().getRealm();
    this.authManager = new AppAuthManager();
    this.federatedIdentitiesService =
        session.getProvider(SAMLAggregateFederatedIdentityServiceProvider.class);
  }

  public void init() {
    this.event =
        new EventBuilder(realm, session, clientConnection).event(EventType.IDENTITY_PROVIDER_LOGIN);
  }

  /**************************************
   * 
   * login requests
   * 
   ***************************************/

  @GET
  @Path("{provider}/login")
  @Produces(MediaType.APPLICATION_FORM_URLENCODED)
  public Response login(final @PathParam("provider") String provider,
      final @QueryParam("idp") String idp) throws URISyntaxException, SAMLAggregateBrokerException {

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
    Optional<SAMLIdpDescriptor> idpDescr = getIdentityProviderFromEntityId(realm, provider, idp);
    if (idpDescr.isEmpty()) {
      return redirectToBadRequest("Idp Descriptor for [" + idp + "] not found in metadata store.");
    }

    ClientModel client =
        session.clients().getClientByClientId(realm, Constants.ACCOUNT_CONSOLE_CLIENT_ID);

    AuthenticationSessionModel authSession = createAuthenticationSession(realm, client);
    authSession.setProtocol(SamlProtocol.LOGIN_PROTOCOL);
    authSession.setRedirectUri(RedirectUtils.getFirstValidRedirectUri(session, client.getRootUrl(),
        client.getRedirectUris()));

    ClientSessionCode<AuthenticationSessionModel> clientSessionCode =
        new ClientSessionCode<>(session, realm, authSession);
    clientSessionCode.setAction(AuthenticationSessionModel.Action.AUTHENTICATE.name());

    String issuerURL = getIssuer(provider);

    // SAMLAggregateIdentityProviderConfig config = null;
    // if (identityProviderModel.getConfig() instanceof SAMLAggregateIdentityProviderConfig) {
    // config = (SAMLAggregateIdentityProviderConfig) identityProviderModel.getConfig();
    // } else {
    // throw new SAMLAggregateBrokerException("Invalid Identity Provider Config");
    // }

    // to-do get it from config if defined
    String nameIDPolicyFormat = JBossSAMLURIConstants.NAMEID_FORMAT_PERSISTENT.get();
    if (!idpDescr.get().getDescriptor().getNameIDFormat().isEmpty()) {
      nameIDPolicyFormat = idpDescr.get().getDescriptor().getNameIDFormat().get(0);
    }

    String assertionConsumerServiceUrl = getRedirectUri(provider, idp);


    String protocolBinding = JBossSAMLURIConstants.SAML_HTTP_REDIRECT_BINDING.get();
    if (idpDescr.get().isPostBindingResponse()) {
      protocolBinding = JBossSAMLURIConstants.SAML_HTTP_POST_BINDING.get();
    }

    String destinationUrl = idpDescr.get().getSingleSignOnServiceUrl();

    Boolean isForceAuthn = false; // to-do use config.isForceAuthn();
    boolean postBinding = idpDescr.get().isPostBindingResponse();

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

      // Save the current RequestID in the Auth Session as we need to verify it
      // against the ID returned from the IdP
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

    UriBuilder builder = UriBuilder.fromUri(session.getContext().getAuthServerUrl())
        .path(RealmsResource.class)
        .path(RealmsResource.class, "getRealmResource")
        .path("saml-aggregate-broker")
        .path(SAMLAggregateBrokerResource.class, "authenticate")
        .queryParam("idp", idp);
    return builder.build(session.getContext().getRealm().getName(), providerAlias).toString();
  }

  private String getIssuer(String providerAlias) {

    return UriBuilder.fromUri(session.getContext().getAuthServerUrl())
      .path("realms")
      .path(session.getContext().getRealm().getName())
      .path(providerAlias)
      .build()
      .toString();
  }

  private Optional<SAMLIdpDescriptor> getIdentityProviderFromEntityId(RealmModel realm,
      String providerAlias, String entityId) throws SAMLAggregateBrokerException {

    SAMLAggregateMetadataStoreProvider md =
        session.getProvider(SAMLAggregateMetadataStoreProvider.class);

    return md.lookupIdpByEntityId(realm, providerAlias, entityId);
  }

  /**************************************
   * 
   * authenticate callback
   * 
   ***************************************/

  @Path("{provider}/authenticate")
  public Object authenticate(@PathParam("provider") String providerAlias,
      @QueryParam("idp") String idp) {

    IdentityProvider<?> identityProvider;
    try {
      identityProvider = getIdentityProvider(session, providerAlias);
      /* save current idp */
      session.setAttribute(SESSION_SAML_AGGREGATE_ENTITY_ID_ATTRIBUTE, idp);
    } catch (IdentityBrokerException e) {
      throw new NotFoundException(e.getMessage());
    }

    /* check if user is already authenticated = is a linking */
    AuthenticationManager.AuthResult cookieResult = AuthenticationManager.authenticateIdentityCookie(session, realm, true);

    if (cookieResult != null) {
      /* user is linking the identity */
      session.setAttribute(SESSION_SAML_AGGREGATE_LINKING_ATTRIBUTE, cookieResult.getUser().getId());
    }

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
        clientId, tabId, AUTHENTICATE_PATH);
    checks.initialVerify();
    if (!checks.verifyActiveAndValidAction(AuthenticationSessionModel.Action.AUTHENTICATE.name(),
        ClientSessionCode.ActionType.LOGIN)) {

      AuthenticationSessionModel authSession = checks.getAuthenticationSession();
      if (authSession != null) {
        // Check if error happened during login or during linking from account
        // management
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

    /*
     * IdentityBrokerService brokerService = new IdentityBrokerService(realm);
     * ResteasyProviderFactory.getInstance().injectProperties(brokerService); brokerService.init();
     * return brokerService.authenticated(context);
     */

    LOG.info("authenticated(" + context.toString() + ")");

    IdentityProviderModel identityProviderConfig = context.getIdpConfig();
    AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
    UserSessionModel userSession =
        new AuthenticationSessionManager(session).getUserSession(authenticationSession);
    String providerId = identityProviderConfig.getAlias();

    String entityId = (String) session.getAttribute(SESSION_SAML_AGGREGATE_ENTITY_ID_ATTRIBUTE);
    String linkingUser = null;
    if (session.getAttribute(SESSION_SAML_AGGREGATE_LINKING_ATTRIBUTE, String.class) != null) {
      linkingUser = session.getAttribute("link", String.class);
      context.getAuthenticationSession().setAuthNote(LINKING_IDENTITY_PROVIDER, userSession.getId() + authenticationSession.getClient().getClientId() + entityId);
    }

    if (!identityProviderConfig.isStoreToken()) {
      if (LOG.isDebugEnabled()) {
        LOG.debugf("Token will not be stored for identity provider [%s].", providerId);
      }
      context.setToken(null);
    }

    StatusResponseType loginResponse =
        (StatusResponseType) context.getContextData().get(SAMLEndpoint.SAML_LOGIN_RESPONSE);
    if (loginResponse != null) {
      for (Iterator<SamlAuthenticationPreprocessor> it =
          SamlSessionUtils.getSamlAuthenticationPreprocessorIterator(session); it.hasNext();) {
        loginResponse =
            it.next().beforeProcessingLoginResponse(loginResponse, authenticationSession);
      }
    }

    session.getContext().setClient(authenticationSession.getClient());

    context.getIdp().preprocessFederatedIdentity(session, realm, context);
    KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();
    realm.getIdentityProviderMappersByAliasStream(context.getIdpConfig().getAlias())
      .forEach(mapper -> {
        IdentityProviderMapper target = (IdentityProviderMapper) sessionFactory
          .getProviderFactory(IdentityProviderMapper.class, mapper.getIdentityProviderMapper());
        target.preprocessFederatedIdentity(session, realm, mapper, context);
      });

    this.event.event(IDENTITY_PROVIDER_LOGIN)
      .detail(REDIRECT_URI, authenticationSession.getRedirectUri())
      .detail(IDENTITY_PROVIDER, providerId)
      .detail(IDENTITY_PROVIDER_USERNAME, context.getUsername());

    Optional<SamlAggregateFederatedIdentityDTO> federatedIdentityDTO =
        federatedIdentitiesService.find(realm.getId(), context.getId()).findFirst();

    if (federatedIdentityDTO.isEmpty()) {

      if (shouldPerformAccountLinking(authenticationSession, userSession, entityId)) {
        return performAccountLinking(authenticationSession, userSession, context, linkingUser, entityId);
      }

      LOG.debugf("Federated user not found for provider '%s' and broker username '%s'", entityId,
          context.getUsername());

      String username = context.getModelUsername();
      if (username == null) {
        if (this.realm.isRegistrationEmailAsUsername() && !Validation.isBlank(context.getEmail())) {
          username = context.getEmail();
        } else if (context.getUsername() == null) {
          username = context.getIdpConfig().getAlias() + "." + context.getId();
        } else {
          username = context.getUsername();
        }
      }
      username = username.trim();
      context.setModelUsername(username);

      SerializedBrokeredIdentityContext ctx0 =
          SerializedBrokeredIdentityContext.readFromAuthenticationSession(authenticationSession,
              AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);
      if (ctx0 != null) {
        SerializedBrokeredIdentityContext ctx1 =
            SerializedBrokeredIdentityContext.serialize(context);
        ctx1.saveToAuthenticationSession(authenticationSession,
            AbstractIdpAuthenticator.NESTED_FIRST_BROKER_CONTEXT);
        LOG.warnv("Nested first broker flow detected: {0} -> {1}", ctx0.getIdentityProviderId(),
            ctx1.getIdentityProviderId());
        LOG.debug("Resuming last execution");
        URI redirect =
            new AuthenticationFlowURLHelper(session, realm, session.getContext().getUri())
              .getLastExecutionUrl(authenticationSession);
        return Response.status(Status.FOUND).location(redirect).build();
      }

      LOG.debug("Redirecting to flow for firstBrokerLogin");

      boolean forwardedPassiveLogin = "true"
        .equals(authenticationSession.getAuthNote(AuthenticationProcessor.FORWARDED_PASSIVE_LOGIN));
      // Redirect to firstBrokerLogin after successful login and ensure that previous authentication
      // state removed
      AuthenticationProcessor.resetFlow(authenticationSession,
          SAMLAggregateBrokerResource.FIRST_BROKER_LOGIN_PATH);

      // Set the FORWARDED_PASSIVE_LOGIN note (if needed) after resetting the session so it is not
      // lost.
      if (forwardedPassiveLogin) {
        authenticationSession.setAuthNote(AuthenticationProcessor.FORWARDED_PASSIVE_LOGIN, "true");
      }
      authenticationSession.setAuthNote("IS_SAML_AGGREGATE", "true");

      SerializedBrokeredIdentityContext ctx = SerializedBrokeredIdentityContext.serialize(context);
      ctx.saveToAuthenticationSession(authenticationSession,
          AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);

      URI redirect =
          SAMLAggregateBrokerResource.firstBrokerLoginProcessor(session.getContext().getUri())
            .queryParam(Constants.CLIENT_ID, authenticationSession.getClient().getClientId())
            .queryParam(Constants.TAB_ID, authenticationSession.getTabId())
            .build(realm.getName());
      return Response.status(302).location(redirect).build();

    } else {

      UserModel federatedUser =
          session.users().getUserById(realm, federatedIdentityDTO.get().getUserId());

      Response response = validateUser(authenticationSession, federatedUser, realm);
      if (response != null) {
        return response;
      }

      updateFederatedIdentity(context, federatedUser, federatedIdentityDTO.get());
      authenticationSession.setAuthenticatedUser(federatedUser);

      return finishOrRedirectToPostBrokerLogin(authenticationSession, context, false);
    }
  }

  private boolean shouldPerformAccountLinking(AuthenticationSessionModel authSession,
      UserSessionModel userSession, String identityProvider) {
    String noteFromSession = authSession.getAuthNote(LINKING_IDENTITY_PROVIDER);
    if (noteFromSession == null) {
      return false;
    }
    // is linking
    boolean linkingValid;
    if (userSession == null) {
      linkingValid = false;
    } else {
      String expectedNote =
          userSession.getId() + authSession.getClient().getClientId() + identityProvider;
      linkingValid = expectedNote.equals(noteFromSession);
    }

    if (linkingValid) {
      authSession.removeAuthNote(LINKING_IDENTITY_PROVIDER);
      return true;
    } else {
      throw new ErrorPageException(session, Response.Status.BAD_REQUEST,
          Messages.BROKER_LINKING_SESSION_EXPIRED);
    }
  }

  private Response performAccountLinking(AuthenticationSessionModel authSession,
      UserSessionModel userSession, BrokeredIdentityContext context, String linkingUser, String entityId) {

    this.event.event(FEDERATED_IDENTITY_LINK);

    UserModel authenticatedUser = userSession.getUser();
    authSession.setAuthenticatedUser(authenticatedUser);

    if (!authenticatedUser
      .hasRole(realm.getClientByClientId(ACCOUNT_MANAGEMENT_CLIENT_ID).getRole(MANAGE_ACCOUNT))) {
      return redirectToErrorPage(authSession, Response.Status.FORBIDDEN, INSUFFICIENT_PERMISSION);
    }

    if (!authenticatedUser.isEnabled()) {
      return redirectToErrorWhenLinkingFailed(authSession, ACCOUNT_DISABLED);
    }

    federatedIdentitiesService.add(realm.getId(), linkingUser, context.getIdpConfig().getInternalId(),
        context.getId(), entityId, context.getUsername());

    context.getIdp().authenticationFinished(authSession, context);

    AuthenticationManager.setClientScopesInSession(authSession);
    TokenManager.attachAuthenticationSession(session, userSession, authSession);

//    this.event.user(authenticatedUser)
//      .detail(Details.USERNAME, authenticatedUser.getUsername())
//      .detail(Details.IDENTITY_PROVIDER, dto.getIdentityProviderAlias())
//      .detail(Details.IDENTITY_PROVIDER_USERNAME, dto.getFederatedUsername())
//      .success();

    // we do this to make sure that the parent IDP is logged out when this user session is complete.
    // But for the case when userSession was previously authenticated with broker1 and now is linked
    // to another broker2, we shouldn't override broker1 notes with the broker2 for sure.
    // Maybe broker logout should be rather always skipped in case of broker-linking
    if (userSession.getNote(Details.IDENTITY_PROVIDER) == null) {
      userSession.setNote(Details.IDENTITY_PROVIDER, context.getIdpConfig().getAlias());
      userSession.setNote(Details.IDENTITY_PROVIDER_USERNAME, context.getUsername());
    }

    return Response.status(302)
      .location(UriBuilder.fromUri(authSession.getRedirectUri()).build())
      .build();
  }

  public static UriBuilder firstBrokerLoginProcessor(UriInfo uriInfo) {
    return samlAggregateBrokerBaseUrl(uriInfo).path(SAMLAggregateBrokerResource.class,
        "firstBrokerLoginGet");
  }

  public static UriBuilder postBrokerLoginProcessor(UriInfo uriInfo) {
    return samlAggregateBrokerBaseUrl(uriInfo).path(SAMLAggregateBrokerResource.class,
        "postBrokerLoginGet");
  }

  public static UriBuilder samlAggregateBrokerBaseUrl(UriInfo uriInfo) {
    UriBuilder baseUriBuilder = uriInfo.getBaseUriBuilder();
    return samlAggregateBrokerBaseUrl(baseUriBuilder);
  }

  public static UriBuilder samlAggregateBrokerBaseUrl(UriBuilder baseUriBuilder) {
    return baseUriBuilder.path(RealmsResource.class)
      .path(RealmsResource.class, "getRealmResource")
      .path("saml-aggregate-broker");
  }

  public static UriBuilder realmBase(URI baseUri) {
    return UriBuilder.fromUri(baseUri).path(RealmsResource.class);
  }

  private static URI identityProviderAfterFirstBrokerLogin(URI baseUri, String realmName,
      String accessCode, String clientId, String tabId) {

    return realmBase(baseUri).path(RealmsResource.class, "getRealmResource")
      .path("saml-aggregate-broker")
      .path(SAMLAggregateBrokerResource.class, "afterFirstBrokerLogin")
      .replaceQueryParam(SESSION_CODE, accessCode)
      .replaceQueryParam(Constants.CLIENT_ID, clientId)
      .replaceQueryParam(Constants.TAB_ID, tabId)
      .build(realmName);
  }

  private static URI identityProviderAfterPostBrokerLogin(URI baseUri, String realmName,
      String accessCode, String clientId, String tabId) {
    return realmBase(baseUri).path(RealmsResource.class, "getRealmResource")
      .path("saml-aggregate-broker")
      .path(SAMLAggregateBrokerResource.class, "afterPostBrokerLoginFlow")
      .replaceQueryParam(SESSION_CODE, accessCode)
      .replaceQueryParam(Constants.CLIENT_ID, clientId)
      .replaceQueryParam(Constants.TAB_ID, tabId)
      .build(realmName);
  }

  private Response redirectToErrorWhenLinkingFailed(AuthenticationSessionModel authSession,
      String message, Object... parameters) {
    if (authSession.getClient() != null
        && authSession.getClient().getClientId().equals(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID)) {
      return redirectToAccountErrorPage(authSession, message, parameters);
    } else {
      return redirectToErrorPage(authSession, Response.Status.BAD_REQUEST, message, parameters);
    }
  }

  private Response redirectToErrorPage(AuthenticationSessionModel authSession,
      Response.Status status, String message, Object... parameters) {
    return redirectToErrorPage(authSession, status, message, null, parameters);
  }

  public Response validateUser(AuthenticationSessionModel authSession, UserModel user,
      RealmModel realm) {

    if (!user.isEnabled()) {
      event.error(Errors.USER_DISABLED);
      return ErrorPage.error(session, authSession, Response.Status.BAD_REQUEST,
          Messages.ACCOUNT_DISABLED);
    }
    if (realm.isBruteForceProtected()) {
      if (session.getProvider(BruteForceProtector.class)
        .isTemporarilyDisabled(session, realm, user)) {
        event.error(Errors.USER_TEMPORARILY_DISABLED);
        return ErrorPage.error(session, authSession, Response.Status.BAD_REQUEST,
            Messages.ACCOUNT_DISABLED);
      }
    }
    return null;
  }

  private void updateFederatedIdentity(BrokeredIdentityContext context, UserModel federatedUser,
      SamlAggregateFederatedIdentityDTO dto) {

    if (context.getIdpConfig().getSyncMode() == IdentityProviderSyncMode.FORCE) {
      setBasicUserAttributes(context, federatedUser);
    }

    // Skip DB write if tokens are null or equal
    updateToken(context, federatedUser, dto);
    context.getIdp().updateBrokeredUser(session, realm, federatedUser, context);
    KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();
    realm.getIdentityProviderMappersByAliasStream(context.getIdpConfig().getAlias())
      .forEach(mapper -> {
        IdentityProviderMapper target = (IdentityProviderMapper) sessionFactory
          .getProviderFactory(IdentityProviderMapper.class, mapper.getIdentityProviderMapper());
        IdentityProviderMapperSyncModeDelegate.delegateUpdateBrokeredUser(session, realm,
            federatedUser, mapper, context, target);
      });
  }

  private void setBasicUserAttributes(BrokeredIdentityContext context, UserModel federatedUser) {
    setDiffAttrToConsumer(federatedUser.getEmail(), context.getEmail(), federatedUser::setEmail);
    setDiffAttrToConsumer(federatedUser.getFirstName(), context.getFirstName(),
        federatedUser::setFirstName);
    setDiffAttrToConsumer(federatedUser.getLastName(), context.getLastName(),
        federatedUser::setLastName);
  }

  private void setDiffAttrToConsumer(String actualValue, String newValue,
      Consumer<String> consumer) {
    String actualValueNotNull = Optional.ofNullable(actualValue).orElse("");
    if (newValue != null && !newValue.equals(actualValueNotNull)) {
      consumer.accept(newValue);
    }
  }

  private void updateToken(BrokeredIdentityContext context, UserModel federatedUser,
      SamlAggregateFederatedIdentityDTO dto) {

    if (context.getIdpConfig().isStoreToken()
        && !ObjectUtil.isEqualOrBothNull(context.getToken(), dto.getToken())) {

      federatedIdentitiesService.updateToken(dto, context.getToken());

      if (LOG.isDebugEnabled()) {
        LOG.debugf("Identity [%s] update with response from identity provider [%s].", federatedUser,
            context.getIdpConfig().getAlias());
      }
    }
  }

  private Response finishOrRedirectToPostBrokerLogin(AuthenticationSessionModel authSession,
      BrokeredIdentityContext context, boolean wasFirstBrokerLogin) {
    String postBrokerLoginFlowId = context.getIdpConfig().getPostBrokerLoginFlowId();
    if (postBrokerLoginFlowId == null) {

      LOG.debugf(
          "Skip redirect to postBrokerLogin flow. PostBrokerLogin flow not set for identityProvider '%s'.",
          context.getIdpConfig().getAlias());
      return afterPostBrokerLoginFlowSuccess(authSession, context, wasFirstBrokerLogin);
    } else {

      LOG.debugf(
          "Redirect to postBrokerLogin flow after authentication with identityProvider '%s'.",
          context.getIdpConfig().getAlias());

      authSession.getParentSession().setTimestamp(Time.currentTime());

      SerializedBrokeredIdentityContext ctx = SerializedBrokeredIdentityContext.serialize(context);
      ctx.saveToAuthenticationSession(authSession,
          PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT);

      authSession.setAuthNote(PostBrokerLoginConstants.PBL_AFTER_FIRST_BROKER_LOGIN,
          String.valueOf(wasFirstBrokerLogin));

      URI redirect =
          SAMLAggregateBrokerResource.postBrokerLoginProcessor(session.getContext().getUri())
            .queryParam(Constants.CLIENT_ID, authSession.getClient().getClientId())
            .queryParam(Constants.TAB_ID, authSession.getTabId())
            .build(realm.getName());
      return Response.status(302).location(redirect).build();
    }
  }

  private Response afterPostBrokerLoginFlowSuccess(AuthenticationSessionModel authSession,
      BrokeredIdentityContext context, boolean wasFirstBrokerLogin) {
    String providerId = context.getIdpConfig().getAlias();
    UserModel federatedUser = authSession.getAuthenticatedUser();

    if (wasFirstBrokerLogin) {
      return finishBrokerAuthentication(context, federatedUser, authSession, providerId);
    } else {

      boolean firstBrokerLoginInProgress =
          (authSession.getAuthNote(AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE) != null);
      if (firstBrokerLoginInProgress) {
        LOG.debugf("Reauthenticated with broker '%s' when linking user '%s' with other broker",
            context.getIdpConfig().getAlias(), federatedUser.getUsername());

        SerializedBrokeredIdentityContext serializedCtx =
            SerializedBrokeredIdentityContext.readFromAuthenticationSession(authSession,
                AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);
        authSession.setAuthNote(AbstractIdpAuthenticator.FIRST_BROKER_LOGIN_SUCCESS,
            serializedCtx.getIdentityProviderId());

        return afterFirstBrokerLogin(authSession);
      } else {
        return finishBrokerAuthentication(context, federatedUser, authSession, providerId);
      }
    }
  }

  private Response finishBrokerAuthentication(BrokeredIdentityContext context,
      UserModel federatedUser, AuthenticationSessionModel authSession, String providerId) {

    authSession.setAuthNote(AuthenticationProcessor.BROKER_SESSION_ID,
        context.getBrokerSessionId());
    authSession.setAuthNote(AuthenticationProcessor.BROKER_USER_ID, context.getBrokerUserId());

    this.event.user(federatedUser);

    context.getIdp().authenticationFinished(authSession, context);
    authSession.setUserSessionNote(IDENTITY_PROVIDER, providerId);
    authSession.setUserSessionNote(IDENTITY_PROVIDER_USERNAME, context.getUsername());

    event.detail(IDENTITY_PROVIDER, providerId)
      .detail(IDENTITY_PROVIDER_USERNAME, context.getUsername());

    if (LOG.isDebugEnabled()) {
      LOG.debugf("Performing local authentication for user [%s].", federatedUser);
    }

    AuthenticationManager.setClientScopesInSession(authSession);

    String nextRequiredAction =
        AuthenticationManager.nextRequiredAction(session, authSession, request, event);
    if (nextRequiredAction != null) {
      if ("true".equals(authSession.getAuthNote(AuthenticationProcessor.FORWARDED_PASSIVE_LOGIN))) {
        LOG.errorf(
            "Required action %s found. Auth requests using prompt=none are incompatible with required actions",
            nextRequiredAction);
        return checkPassiveLoginError(authSession, OAuthErrorException.INTERACTION_REQUIRED);
      }
      return AuthenticationManager.redirectToRequiredActions(session, realm, authSession,
          session.getContext().getUri(), nextRequiredAction);
    } else {
      event.detail(Details.CODE_ID, authSession.getParentSession().getId());
      return AuthenticationManager.finishedRequiredActions(session, authSession, null,
          clientConnection, request, session.getContext().getUri(), event);
    }
  }

  private Response afterFirstBrokerLogin(AuthenticationSessionModel authSession) {
    try {
      this.event.detail(Details.CODE_ID, authSession.getParentSession().getId())
        .removeDetail("auth_method");

      SerializedBrokeredIdentityContext serializedCtx = SerializedBrokeredIdentityContext
        .readFromAuthenticationSession(authSession, AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);
      if (serializedCtx == null) {
        throw new IdentityBrokerException("Not found serialized context in clientSession");
      }
      BrokeredIdentityContext context = serializedCtx.deserialize(session, authSession);
      String providerAlias = context.getIdpConfig().getAlias();

      event.detail(IDENTITY_PROVIDER, providerAlias);
      event.detail(IDENTITY_PROVIDER_USERNAME, context.getUsername());

      // Ensure the first-broker-login flow was successfully finished
      String authProvider =
          authSession.getAuthNote(AbstractIdpAuthenticator.FIRST_BROKER_LOGIN_SUCCESS);
      if (authProvider == null || !authProvider.equals(context.getIdpConfig().getAlias())) {
        throw new IdentityBrokerException(
            "Invalid request. Not found the flag that first-broker-login flow was finished");
      }

      // firstBrokerLogin workflow finished. Removing note now
      authSession.removeAuthNote(AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);

      UserModel federatedUser = authSession.getAuthenticatedUser();
      if (federatedUser == null) {
        throw new IdentityBrokerException(
            "Couldn't found authenticated federatedUser in authentication session");
      }

      event.user(federatedUser);
      event.detail(Details.USERNAME, federatedUser.getUsername());

      if (context.getIdpConfig().isAddReadTokenRoleOnCreate()) {
        ClientModel brokerClient = realm.getClientByClientId(Constants.BROKER_SERVICE_CLIENT_ID);
        if (brokerClient == null) {
          throw new IdentityBrokerException(
              "Client 'broker' not available. Maybe realm has not migrated to support the broker token exchange service");
        }
        RoleModel readTokenRole = brokerClient.getRole(Constants.READ_TOKEN_ROLE);
        federatedUser.grantRole(readTokenRole);
      }

      IdentityProviderModel idp = realm.getIdentityProviderByAlias(providerAlias);
      String entityId = authSession.getClientNote(SESSION_SAML_AGGREGATE_ENTITY_ID_CLIENT_NOTE);

      federatedIdentitiesService.add(realm.getId(), federatedUser.getId(), idp.getInternalId(),
          context.getId(), entityId, context.getUsername());

      String isRegisteredNewUser =
          authSession.getAuthNote(AbstractIdpAuthenticator.BROKER_REGISTERED_NEW_USER);
      if (Boolean.parseBoolean(isRegisteredNewUser)) {

        LOG.debugf(
            "Registered new user '%s' after first login with identity provider '%s'. Identity provider username is '%s' . ",
            federatedUser.getUsername(), providerAlias, context.getUsername());

        context.getIdp().importNewUser(session, realm, federatedUser, context);
        KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();
        realm.getIdentityProviderMappersByAliasStream(context.getIdpConfig().getAlias())
          .forEach(mapper -> {
            IdentityProviderMapper target = (IdentityProviderMapper) sessionFactory
              .getProviderFactory(IdentityProviderMapper.class, mapper.getIdentityProviderMapper());
            target.importNewUser(session, realm, federatedUser, mapper, context);
          });

        if (context.getIdpConfig().isTrustEmail() && !Validation.isBlank(federatedUser.getEmail())
            && !Boolean.parseBoolean(
                authSession.getAuthNote(AbstractIdpAuthenticator.UPDATE_PROFILE_EMAIL_CHANGED))) {
          LOG.debugf(
              "Email verified automatically after registration of user '%s' through Identity provider '%s' ",
              federatedUser.getUsername(), context.getIdpConfig().getAlias());
          federatedUser.setEmailVerified(true);
        }

        event.event(EventType.REGISTER)
          .detail(Details.REGISTER_METHOD, "broker")
          .detail(Details.EMAIL, federatedUser.getEmail())
          .success();

      } else {
        LOG.debugf(
            "Linked existing keycloak user '%s' with identity provider '%s' . Identity provider username is '%s' .",
            federatedUser.getUsername(), providerAlias, context.getUsername());

        event.event(EventType.FEDERATED_IDENTITY_LINK).success();

        federatedIdentitiesService.updateToken(realm.getId(), federatedUser.getId(),
            idp.getInternalId(), context.getId(), context.getToken());
      }

      return finishOrRedirectToPostBrokerLogin(authSession, context, true);

    } catch (Exception e) {
      return redirectToErrorPage(authSession, Response.Status.INTERNAL_SERVER_ERROR,
          Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR, e);
    }
  }

  @Path(FIRST_BROKER_LOGIN_PATH)
  @GET
  public Response firstBrokerLoginGet(@QueryParam(AUTH_SESSION_ID) String authSessionId,
      @QueryParam(SESSION_CODE) String code, @QueryParam(Constants.EXECUTION) String execution,
      @QueryParam(Constants.CLIENT_ID) String clientId, @QueryParam(Constants.TAB_ID) String tabId,
      @QueryParam("provider") String providerAlias, @QueryParam("entity") String entityId) {
    return brokerLoginFlow(authSessionId, code, execution, clientId, tabId, providerAlias, entityId,
        FIRST_BROKER_LOGIN_PATH);
  }

  @Path(FIRST_BROKER_LOGIN_PATH)
  @POST
  public Response firstBrokerLoginPost(@QueryParam(AUTH_SESSION_ID) String authSessionId,
      @QueryParam(SESSION_CODE) String code, @QueryParam(Constants.EXECUTION) String execution,
      @QueryParam(Constants.CLIENT_ID) String clientId, @QueryParam(Constants.TAB_ID) String tabId,
      @QueryParam("provider") String providerAlias, @QueryParam("entity") String entityId) {
    return brokerLoginFlow(authSessionId, code, execution, clientId, tabId, providerAlias, entityId,
        FIRST_BROKER_LOGIN_PATH);
  }

  protected Response brokerLoginFlow(String authSessionId, String code, String execution,
      String clientId, String tabId, String providerAlias, String entityId, String flowPath) {
    boolean firstBrokerLogin = flowPath.equals(FIRST_BROKER_LOGIN_PATH);

    EventType eventType = firstBrokerLogin ? EventType.IDENTITY_PROVIDER_FIRST_LOGIN
        : EventType.IDENTITY_PROVIDER_POST_LOGIN;
    event.event(eventType);

    SessionCodeChecks checks =
        checksForCode(authSessionId, code, execution, clientId, tabId, flowPath);
    if (!checks.verifyActiveAndValidAction(AuthenticationSessionModel.Action.AUTHENTICATE.name(),
        ClientSessionCode.ActionType.LOGIN)) {
      return checks.getResponse();
    }
    event.detail(Details.CODE_ID, code);
    final AuthenticationSessionModel authSession = checks.getAuthenticationSession();

    processLocaleParam(authSession);

    String noteKey = firstBrokerLogin ? AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE
        : PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT;
    SerializedBrokeredIdentityContext serializedCtx =
        SerializedBrokeredIdentityContext.readFromAuthenticationSession(authSession, noteKey);
    if (serializedCtx == null) {
      ServicesLogger.LOGGER.notFoundSerializedCtxInClientSession(noteKey);
      throw new WebApplicationException(ErrorPage.error(session, authSession,
          Response.Status.BAD_REQUEST, "Not found serialized context in authenticationSession."));
    }
    BrokeredIdentityContext brokerContext = serializedCtx.deserialize(session, authSession);
    final String identityProviderAlias = brokerContext.getIdpConfig().getAlias();

    String flowId = firstBrokerLogin ? brokerContext.getIdpConfig().getFirstBrokerLoginFlowId()
        : brokerContext.getIdpConfig().getPostBrokerLoginFlowId();
    if (flowId == null) {
      ServicesLogger.LOGGER.flowNotConfigForIDP(identityProviderAlias);
      throw new WebApplicationException(ErrorPage.error(session, authSession,
          Response.Status.BAD_REQUEST, "Flow not configured for identity provider"));
    }
    AuthenticationFlowModel brokerLoginFlow = realm.getAuthenticationFlowById(flowId);
    if (brokerLoginFlow == null) {
      ServicesLogger.LOGGER.flowNotFoundForIDP(flowId, identityProviderAlias);
      throw new WebApplicationException(ErrorPage.error(session, authSession,
          Response.Status.BAD_REQUEST, "Flow not found for identity provider"));
    }

    event.detail(Details.IDENTITY_PROVIDER, identityProviderAlias)
      .detail(Details.IDENTITY_PROVIDER_USERNAME, brokerContext.getUsername());

    AuthenticationProcessor processor = new AuthenticationProcessor() {

      @Override
      public Response authenticateOnly() throws AuthenticationFlowException {
        Response challenge = super.authenticateOnly();
        if (challenge != null) {
          if ("true".equals(authenticationSession.getAuthNote(FORWARDED_PASSIVE_LOGIN))) {
            // forwarded passive login is incompatible with challenges created by the broker flows.
            logger.errorf(
                "Challenge encountered when executing %s flow. Auth requests with prompt=none are incompatible with challenges",
                flowPath);
            LoginProtocol protocol =
                session.getProvider(LoginProtocol.class, authSession.getProtocol());
            protocol.setRealm(realm)
              .setHttpHeaders(headers)
              .setUriInfo(session.getContext().getUri())
              .setEventBuilder(event);
            return protocol.sendError(authSession, Error.PASSIVE_INTERACTION_REQUIRED);
          }
        }
        return challenge;
      }

      @Override
      protected Response authenticationComplete() {
        if (firstBrokerLogin) {
          authSession.setAuthNote(AbstractIdpAuthenticator.FIRST_BROKER_LOGIN_SUCCESS,
              identityProviderAlias);
        } else {
          String authStateNoteKey =
              PostBrokerLoginConstants.PBL_AUTH_STATE_PREFIX + identityProviderAlias;
          authSession.setAuthNote(authStateNoteKey, "true");
        }

        return redirectToAfterBrokerLoginEndpoint(authSession, firstBrokerLogin);
      }

    };

    return processFlow(checks.isActionRequest(), execution, authSession, flowPath, brokerLoginFlow,
        null, processor);
  }

  private Response redirectToAfterBrokerLoginEndpoint(AuthenticationSessionModel authSession,
      boolean firstBrokerLogin) {
    return redirectToAfterBrokerLoginEndpoint(session, realm, session.getContext().getUri(),
        authSession, firstBrokerLogin);
  }

  public static Response redirectToAfterBrokerLoginEndpoint(KeycloakSession session,
      RealmModel realm, UriInfo uriInfo, AuthenticationSessionModel authSession,
      boolean firstBrokerLogin) {
    ClientSessionCode<AuthenticationSessionModel> accessCode =
        new ClientSessionCode<>(session, realm, authSession);
    authSession.getParentSession().setTimestamp(Time.currentTime());

    String clientId = authSession.getClient().getClientId();
    String tabId = authSession.getTabId();
    URI redirect = firstBrokerLogin
        ? identityProviderAfterFirstBrokerLogin(uriInfo.getBaseUri(), realm.getName(),
            accessCode.getOrGenerateCode(), clientId, tabId)
        : identityProviderAfterPostBrokerLogin(uriInfo.getBaseUri(), realm.getName(),
            accessCode.getOrGenerateCode(), clientId, tabId);
    LOG.debugf("Redirecting to '%s' ", redirect);

    return Response.status(302).location(redirect).build();
  }

  @GET
  @NoCache
  @Path("/after-first-broker-login")
  public Response afterFirstBrokerLogin(@QueryParam(SESSION_CODE) String code,
      @QueryParam("client_id") String clientId, @QueryParam(Constants.TAB_ID) String tabId) {
    AuthenticationSessionModel authSession = parseSessionCode(code, clientId, tabId);
    return afterFirstBrokerLogin(authSession);
  }

  @GET
  @NoCache
  @Path("/after-post-broker-login")
  public Response afterPostBrokerLoginFlow(@QueryParam(SESSION_CODE) String code,
      @QueryParam("client_id") String clientId, @QueryParam(Constants.TAB_ID) String tabId) {
    AuthenticationSessionModel authenticationSession = parseSessionCode(code, clientId, tabId);

    try {
      SerializedBrokeredIdentityContext serializedCtx =
          SerializedBrokeredIdentityContext.readFromAuthenticationSession(authenticationSession,
              PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT);
      if (serializedCtx == null) {
        throw new IdentityBrokerException("Not found serialized context in clientSession. Note "
            + PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT + " was null");
      }
      BrokeredIdentityContext context = serializedCtx.deserialize(session, authenticationSession);

      String wasFirstBrokerLoginNote =
          authenticationSession.getAuthNote(PostBrokerLoginConstants.PBL_AFTER_FIRST_BROKER_LOGIN);
      boolean wasFirstBrokerLogin = Boolean.parseBoolean(wasFirstBrokerLoginNote);

      // Ensure the post-broker-login flow was successfully finished
      String authStateNoteKey =
          PostBrokerLoginConstants.PBL_AUTH_STATE_PREFIX + context.getIdpConfig().getAlias();
      String authState = authenticationSession.getAuthNote(authStateNoteKey);
      if (!Boolean.parseBoolean(authState)) {
        throw new IdentityBrokerException(
            "Invalid request. Not found the flag that post-broker-login flow was finished");
      }

      // remove notes
      authenticationSession.removeAuthNote(PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT);
      authenticationSession.removeAuthNote(PostBrokerLoginConstants.PBL_AFTER_FIRST_BROKER_LOGIN);

      return afterPostBrokerLoginFlowSuccess(authenticationSession, context, wasFirstBrokerLogin);
    } catch (IdentityBrokerException e) {
      return redirectToErrorPage(authenticationSession, Response.Status.INTERNAL_SERVER_ERROR,
          Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR, e);
    }
  }

  protected void processLocaleParam(AuthenticationSessionModel authSession) {
    if (authSession != null && realm.isInternationalizationEnabled()) {
      String locale = session.getContext()
        .getUri()
        .getQueryParameters()
        .getFirst(LocaleSelectorProvider.KC_LOCALE_PARAM);
      if (locale != null) {
        authSession.setAuthNote(LocaleSelectorProvider.USER_REQUEST_LOCALE, locale);

        LocaleUpdaterProvider localeUpdater = session.getProvider(LocaleUpdaterProvider.class);
        localeUpdater.updateLocaleCookie(locale);
      }
    }
  }

  private SessionCodeChecks checksForCode(String authSessionId, String code, String execution,
      String clientId, String tabId, String flowPath) {
    SessionCodeChecks res =
        new SessionCodeChecks(realm, session.getContext().getUri(), request, clientConnection,
            session, event, authSessionId, code, execution, clientId, tabId, flowPath);
    res.initialVerify();
    return res;
  }

  protected Response processFlow(boolean action, String execution,
      AuthenticationSessionModel authSession, String flowPath, AuthenticationFlowModel flow,
      String errorMessage, AuthenticationProcessor processor) {

    processor.setAuthenticationSession(authSession)
      .setFlowPath(flowPath)
      .setBrowserFlow(true)
      .setFlowId(flow.getId())
      .setConnection(clientConnection)
      .setEventBuilder(event)
      .setRealm(realm)
      .setSession(session)
      .setUriInfo(session.getContext().getUri())
      .setRequest(request);
    if (errorMessage != null) {
      processor.setForwardedErrorMessage(new FormMessage(null, errorMessage));
    }

    // Check the forwarded error message, which was set by previous HTTP request
    String forwardedErrorMessage = authSession.getAuthNote(FORWARDED_ERROR_MESSAGE_NOTE);
    if (forwardedErrorMessage != null) {
      authSession.removeAuthNote(FORWARDED_ERROR_MESSAGE_NOTE);
      processor.setForwardedErrorMessage(new FormMessage(null, forwardedErrorMessage));
    }


    Response response;
    try {
      if (action) {
        response = processor.authenticationAction(execution);
      } else {
        response = processor.authenticate();
      }
    } catch (WebApplicationException e) {
      response = e.getResponse();
      authSession = processor.getAuthenticationSession();
    } catch (Exception e) {
      response = processor.handleBrowserException(e);
      authSession = processor.getAuthenticationSession(); // Could be changed (eg. Forked flow)
    }

    return BrowserHistoryHelper.getInstance()
      .saveResponseAndRedirect(session, authSession, response, action, request);
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
      .setFlowPath(AUTHENTICATE_PATH)
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

  /**************************************
   * 
   * link account
   * 
   **************************************/

  @GET
  @NoCache
  @Path("/{provider_id}/link")
  public Response clientInitiatedAccountLinking(@PathParam("provider_id") String providerId,
                                                @QueryParam("redirect_uri") String redirectUri,
                                                @QueryParam("client_id") String clientId,
                                                @QueryParam("nonce") String nonce,
                                                @QueryParam("hash") String hash,
                                                @QueryParam("entity_id") String entityId
  ) {
      this.event.event(EventType.CLIENT_INITIATED_ACCOUNT_LINKING);
      checkRealm();
      ClientModel client = checkClient(clientId);
      redirectUri = RedirectUtils.verifyRedirectUri(session, redirectUri, client);
      if (redirectUri == null) {
          event.error(Errors.INVALID_REDIRECT_URI);
          throw new ErrorPageException(session, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
      }

      event.detail(Details.REDIRECT_URI, redirectUri);

      if (nonce == null || hash == null) {
          event.error(Errors.INVALID_REDIRECT_URI);
          throw new ErrorPageException(session, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);

      }

      AuthenticationManager.AuthResult cookieResult = AuthenticationManager.authenticateIdentityCookie(session, realm, true);
      String errorParam = "link_error";
      if (cookieResult == null) {
          event.error(Errors.NOT_LOGGED_IN);
          UriBuilder builder = UriBuilder.fromUri(redirectUri)
                  .queryParam(errorParam, Errors.NOT_LOGGED_IN)
                  .queryParam("nonce", nonce);

          return Response.status(302).location(builder.build()).build();
      }

      cookieResult.getSession();
      event.session(cookieResult.getSession());
      event.user(cookieResult.getUser());
      event.detail(Details.USERNAME, cookieResult.getUser().getUsername());

      AuthenticatedClientSessionModel clientSession = null;
      for (AuthenticatedClientSessionModel cs : cookieResult.getSession().getAuthenticatedClientSessions().values()) {
          if (cs.getClient().getClientId().equals(clientId)) {
              byte[] decoded = Base64Url.decode(hash);
              MessageDigest md = null;
              try {
                  md = MessageDigest.getInstance("SHA-256");
              } catch (NoSuchAlgorithmException e) {
                  throw new ErrorPageException(session, Response.Status.INTERNAL_SERVER_ERROR, Messages.UNEXPECTED_ERROR_HANDLING_REQUEST);
              }
              String input = nonce + cookieResult.getSession().getId() + clientId + providerId;
              byte[] check = md.digest(input.getBytes(StandardCharsets.UTF_8));
              if (MessageDigest.isEqual(decoded, check)) {
                  clientSession = cs;
                  break;
              }
          }
      }
      if (clientSession == null) {
          event.error(Errors.INVALID_TOKEN);
          throw new ErrorPageException(session, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
      }

      event.detail(Details.IDENTITY_PROVIDER, providerId);

      ClientModel accountService = realm.getClientByClientId(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID);
      if (!accountService.getId().equals(client.getId())) {
          RoleModel manageAccountRole = accountService.getRole(AccountRoles.MANAGE_ACCOUNT);

          // Ensure user has role and client has "role scope" for this role
          ClientSessionContext ctx = DefaultClientSessionContext.fromClientSessionScopeParameter(clientSession, session);
          Set<RoleModel> userAccountRoles = ctx.getRolesStream().collect(Collectors.toSet());

          if (!userAccountRoles.contains(manageAccountRole)) {
              RoleModel linkRole = accountService.getRole(AccountRoles.MANAGE_ACCOUNT_LINKS);
              if (!userAccountRoles.contains(linkRole)) {
                  event.error(Errors.NOT_ALLOWED);
                  UriBuilder builder = UriBuilder.fromUri(redirectUri)
                          .queryParam(errorParam, Errors.NOT_ALLOWED)
                          .queryParam("nonce", nonce);
                  return Response.status(302).location(builder.build()).build();
              }
          }
      }


      IdentityProviderModel identityProviderModel = realm.getIdentityProviderByAlias(providerId);
      if (identityProviderModel == null) {
          event.error(Errors.UNKNOWN_IDENTITY_PROVIDER);
          UriBuilder builder = UriBuilder.fromUri(redirectUri)
                  .queryParam(errorParam, Errors.UNKNOWN_IDENTITY_PROVIDER)
                  .queryParam("nonce", nonce);
          return Response.status(302).location(builder.build()).build();

      }


      // Create AuthenticationSessionModel with same ID like userSession and refresh cookie
      UserSessionModel userSession = cookieResult.getSession();

      // Auth session with ID corresponding to our userSession may already exists in some rare cases (EG. if some client tried to login in another browser tab with "prompt=login")
      RootAuthenticationSessionModel rootAuthSession = session.authenticationSessions().getRootAuthenticationSession(realm, userSession.getId());
      if (rootAuthSession == null) {
          rootAuthSession = session.authenticationSessions().createRootAuthenticationSession(realm, userSession.getId());
      }

      AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);

      // Refresh the cookie
      new AuthenticationSessionManager(session).setAuthSessionCookie(userSession.getId(), realm);

      ClientSessionCode<AuthenticationSessionModel> clientSessionCode = new ClientSessionCode<>(session, realm, authSession);
      clientSessionCode.setAction(AuthenticationSessionModel.Action.AUTHENTICATE.name());
      clientSessionCode.getOrGenerateCode();
      authSession.setProtocol(client.getProtocol());
      authSession.setRedirectUri(redirectUri);
      authSession.setClientNote(OIDCLoginProtocol.STATE_PARAM, UUID.randomUUID().toString());
      authSession.setAuthNote(LINKING_IDENTITY_PROVIDER, cookieResult.getSession().getId() + clientId + providerId);

      event.detail(Details.CODE_ID, userSession.getId());
      event.success();

      try {
          IdentityProvider<?> identityProvider = getIdentityProvider(session, realm, providerId);
          Response response = identityProvider.performLogin(createAuthenticationRequest(providerId, clientSessionCode));

          if (response != null) {
//              if (isDebugEnabled()) {
//                  logger.debugf("Identity provider [%s] is going to send a request [%s].", identityProvider, response);
//              }
              return response;
          }
      } catch (IdentityBrokerException e) {
          return redirectToErrorPage(authSession, Response.Status.INTERNAL_SERVER_ERROR, Messages.COULD_NOT_SEND_AUTHENTICATION_REQUEST, e, providerId);
      } catch (Exception e) {
          return redirectToErrorPage(authSession, Response.Status.INTERNAL_SERVER_ERROR, Messages.UNEXPECTED_ERROR_HANDLING_REQUEST, e, providerId);
      }

      return redirectToErrorPage(authSession, Response.Status.INTERNAL_SERVER_ERROR, Messages.COULD_NOT_PROCEED_WITH_AUTHENTICATION_REQUEST);

  }

  private void checkRealm() {
    if (!realm.isEnabled()) {
        event.error(Errors.REALM_DISABLED);
        throw new ErrorPageException(session, Response.Status.BAD_REQUEST, Messages.REALM_NOT_ENABLED);
    }
  }

  private ClientModel checkClient(String clientId) {
    if (clientId == null) {
        event.error(Errors.INVALID_REQUEST);
        throw new ErrorPageException(session, Response.Status.BAD_REQUEST, Messages.MISSING_PARAMETER, OIDCLoginProtocol.CLIENT_ID_PARAM);
    }

    event.client(clientId);

    ClientModel client = realm.getClientByClientId(clientId);
    if (client == null) {
        event.error(Errors.CLIENT_NOT_FOUND);
        throw new ErrorPageException(session, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
    }

    if (!client.isEnabled()) {
        event.error(Errors.CLIENT_DISABLED);
        throw new ErrorPageException(session, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
    }
    return client;

  }

  public static IdentityProvider<?> getIdentityProvider(KeycloakSession session, RealmModel realm, String alias) {
    IdentityProviderModel identityProviderModel = realm.getIdentityProviderByAlias(alias);

    if (identityProviderModel != null) {
        IdentityProviderFactory<?> providerFactory = getIdentityProviderFactory(session, identityProviderModel);

        if (providerFactory == null) {
            throw new IdentityBrokerException("Could not find factory for identity provider [" + alias + "].");
        }

        return providerFactory.create(session, identityProviderModel);
    }

    throw new IdentityBrokerException("Identity Provider [" + alias + "] not found.");
  }

  private AuthenticationRequest createAuthenticationRequest(String providerId, ClientSessionCode<AuthenticationSessionModel> clientSessionCode) {
    AuthenticationSessionModel authSession = null;
    IdentityBrokerState encodedState = null;

    if (clientSessionCode != null) {
        authSession = clientSessionCode.getClientSession();
        String relayState = clientSessionCode.getOrGenerateCode();
        encodedState = IdentityBrokerState.decoded(relayState, authSession.getClient().getClientId(), authSession.getTabId());
    }

    return new AuthenticationRequest(this.session, this.realm, authSession, this.request, this.session.getContext().getUri(), encodedState, getRedirectUri(providerId));
  }

  private String getRedirectUri(String providerId) {

    return realmBase(session.getContext().getUri().getBaseUri()).path(RealmsResource.class, "getRealmResource")
    .path("saml-aggregate-broker")
    .path(SAMLAggregateBrokerResource.class, "getEndpoint").build(realm.getName(), providerId).toString();
  }

  @Path("{provider_id}/endpoint")
  public Object getEndpoint(@PathParam("provider_id") String providerId) {

    session.setAttribute(SESSION_SAML_AGGREGATE_ENTITY_ID_ATTRIBUTE, providerId);
    session.setAttribute("is_linking", true);

    IdentityProvider<?> identityProvider;

    try {
        identityProvider = getIdentityProvider(session, realm, providerId);
    } catch (IdentityBrokerException e) {
        throw new NotFoundException(e.getMessage());
    }

    Object callback = identityProvider.callback(realm, this, event);
    ResteasyProviderFactory.getInstance().injectProperties(callback);
    return callback;
  }

  /**************************************
   * 
   * linked accounts
   * 
   ***************************************/

  @GET
  @Path("/linked-accounts")
  @Produces(MediaType.APPLICATION_JSON)
  public Response linkedAccounts() {

    final Auth auth = getAuthentication();
    auth.requireOneOf(AccountRoles.MANAGE_ACCOUNT, AccountRoles.VIEW_PROFILE);

    Set<String> socialIds = findSocialIds();

    SortedSet<SAMLAggregateLinkedAccountRepresentation> linkedAccounts =
        realm.getIdentityProvidersStream()
          .filter(IdentityProviderModel::isEnabled)
//          .filter(t -> !t.getProviderId().equals(SAMLAggregateIdentityProviderFactory.PROVIDER_ID))
          .map(provider -> toLinkedAccountRepresentation(provider, socialIds,
              session.users().getFederatedIdentitiesStream(realm, auth.getUser())))
          .collect(Collectors.toCollection(TreeSet::new));

    federatedIdentitiesService.list(realm.getId(), auth.getUser().getId())
      .forEach(a -> linkedAccounts.add(toLinkedAccountRepresentation(a)));

    return Cors.add(request, Response.ok(linkedAccounts))
      .auth()
      .allowedOrigins(auth.getToken())
      .build();
  }

  private Auth getAuthentication() throws NotAuthorizedException, ForbiddenException {

    ClientModel client = realm.getClientByClientId(ACCOUNT_MANAGEMENT_CLIENT_ID);
    AuthenticationManager.AuthResult authResult =
        authManager.authenticateIdentityCookie(session, realm);
    if (authResult == null) {
      throw new NotAuthorizedException("Bearer token required");
    }
    Auth auth = new Auth(realm, authResult.getToken(), authResult.getUser(), client,
        authResult.getSession(), true);
    return auth;
  }

  private Set<String> findSocialIds() {
    return session.getKeycloakSessionFactory()
      .getProviderFactoriesStream(SocialIdentityProvider.class)
      .map(ProviderFactory::getId)
      .collect(Collectors.toSet());
  }

  private SAMLAggregateLinkedAccountRepresentation toLinkedAccountRepresentation(
      SamlAggregateFederatedIdentityDTO fir) {

    SAMLAggregateLinkedAccountRepresentation rep = new SAMLAggregateLinkedAccountRepresentation();
    rep.setConnected(true);
    rep.setSocial(false);
    rep.setIdpId(fir.getIdentityProviderInternalId());
    rep.setProviderAlias(fir.getIdentityProviderAlias());
    rep.setDisplayName(fir.getEntityId());
    rep.setGuiOrder(null);
    rep.setProviderName(fir.getIdentityProviderAlias());
    rep.setLinkedUsername(fir.getFederatedUsername());
    rep.setFederatedUserId(fir.getFederatedUserId());
    rep.setSAMLAggregate(true);
    rep.setEntityId(fir.getEntityId());
    rep.setRealmId(fir.getRealmId());
    rep.setUserId(fir.getUserId());
    return rep;
  }

  private SAMLAggregateLinkedAccountRepresentation toLinkedAccountRepresentation(
      IdentityProviderModel provider, Set<String> socialIds,
      Stream<FederatedIdentityModel> identities) {

    String providerId = provider.getAlias();
    FederatedIdentityModel identity = getIdentity(identities, providerId);

    String displayName = KeycloakModelUtils.getIdentityProviderDisplayName(session, provider);
    String guiOrder = provider.getConfig() != null ? provider.getConfig().get("guiOrder") : null;

    SAMLAggregateLinkedAccountRepresentation rep = new SAMLAggregateLinkedAccountRepresentation();
    rep.setConnected(identity != null);
    rep.setSocial(socialIds.contains(provider.getProviderId()));
    rep.setIdpId(provider.getInternalId());
    rep.setProviderAlias(providerId);
    rep.setDisplayName(displayName);
    rep.setGuiOrder(guiOrder);
    rep.setProviderName(provider.getAlias());
    if (identity != null) {
      rep.setLinkedUsername(identity.getUserName());
      rep.setFederatedUserId(identity.getUserName());
      rep.setUserId(identity.getUserId());
    }
    rep.setSAMLAggregate(false);
    rep.setEntityId(null);
    rep.setRealmId(realm.getId());
    return rep;
  }

  private FederatedIdentityModel getIdentity(Stream<FederatedIdentityModel> identities,
      String providerId) {
    return identities.filter(model -> Objects.equals(model.getIdentityProvider(), providerId))
      .findFirst()
      .orElse(null);
  }

  @DELETE
  @Path("/linked-accounts")
  @Consumes(MediaType.APPLICATION_JSON)
  public Response unlinkAccount(SAMLAggregateLinkedAccountRepresentation linkedAccount) {

    final Auth auth = getAuthentication();
    auth.require(AccountRoles.MANAGE_ACCOUNT);

    if (linkedAccount.isSAMLAggregate()) {
      federatedIdentitiesService.remove(linkedAccount.getRealmId(), linkedAccount.getUserId(),
          linkedAccount.getIdpId(), linkedAccount.getFederatedUserId());
    } else {
      this.session.users()
        .removeFederatedIdentity(realm, auth.getUser(), linkedAccount.getProviderName());
    }

    event.event(EventType.REMOVE_FEDERATED_IDENTITY)
      .client(auth.getClient())
      .user(auth.getUser())
      .detail(Details.USERNAME, auth.getUser().getUsername())
      .detail(Details.IDENTITY_PROVIDER, linkedAccount.getProviderAlias())
      .detail(Details.IDENTITY_PROVIDER_USERNAME, linkedAccount.getLinkedUsername())
      .success();

    return Cors.add(request, Response.noContent()).auth().allowedOrigins(auth.getToken()).build();
  }


  @GET
  @Path("/linked-accounts/{providerId}")
  @Produces(MediaType.APPLICATION_JSON)
  public Response linkedAccounts(final @PathParam("providerId") String providerId,
      @QueryParam("redirectUri") String redirectUri) {

    final Auth auth = getAuthentication();
    auth.require(AccountRoles.MANAGE_ACCOUNT);

    if (redirectUri == null) {
      return ErrorResponse.error(INVALID_REDIRECT_URI, Response.Status.BAD_REQUEST);
    }

    if (Validation.isEmpty(providerId)) {
      return ErrorResponse.error(MISSING_IDENTITY_PROVIDER, Response.Status.BAD_REQUEST);
    }

    if (!isValidProvider(providerId)) {
      return ErrorResponse.error(IDENTITY_PROVIDER_NOT_FOUND, Response.Status.BAD_REQUEST);
    }

    if (!auth.getUser().isEnabled()) {
      return ErrorResponse.error(ACCOUNT_DISABLED, Response.Status.BAD_REQUEST);
    }

    if (auth.getSession() == null) {
      return ErrorResponse.error(SESSION_NOT_ACTIVE, Response.Status.BAD_REQUEST);
    }

    try {
      String nonce = UUID.randomUUID().toString();
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      String input = nonce + auth.getSession().getId() + ACCOUNT_CONSOLE_CLIENT_ID + providerId;
      byte[] check = md.digest(input.getBytes(StandardCharsets.UTF_8));
      String hash = Base64Url.encode(check);
      URI linkUri = identityProviderLinkRequest(
          this.session.getContext().getUri().getBaseUri(), providerId, realm.getName());
      linkUri = UriBuilder.fromUri(linkUri)
        .queryParam("nonce", nonce)
        .queryParam("hash", hash)
        // need to use "account-console" client because IdentityBrokerService authenticates user
        // using cookies
        // the regular "account" client is used only for REST calls therefore cookies authentication
        // cannot be used
        .queryParam("client_id", ACCOUNT_CONSOLE_CLIENT_ID)
        .queryParam("redirect_uri", redirectUri)
        .queryParam(SAMLAggregateAuthenticator.SAML_AGGREGATE_AUTH_PROVIDER, providerId)
        .build();

      AccountLinkUriRepresentation rep = new AccountLinkUriRepresentation();
      rep.setAccountLinkUri(linkUri);
      rep.setHash(hash);
      rep.setNonce(nonce);

      return Cors.add(request, Response.ok(rep)).auth().allowedOrigins(auth.getToken()).build();
    } catch (Exception spe) {
      spe.printStackTrace();
      return ErrorResponse.error(Messages.FAILED_TO_PROCESS_RESPONSE,
          Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  private URI identityProviderLinkRequest(URI baseUri, String providerId, String realmName) {
    
    return realmBase(session.getContext().getUri().getBaseUri()).path(RealmsResource.class, "getRealmResource")
        .path("saml-aggregate-broker")
        .path(SAMLAggregateBrokerResource.class, "clientInitiatedAccountLinking").build(realmName, providerId);
  }

  private boolean isValidProvider(String providerId) {
    return realm.getIdentityProvidersStream()
      .anyMatch(model -> Objects.equals(model.getAlias(), providerId));
  }

  @Override
  public void close() {}

  @Override
  public Object getResource() {
    return this;
  }

}
