package it.infn.cnaf.sd.kc.idp;

import java.net.URI;
import java.util.Iterator;
import java.util.Optional;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.IdentityProviderDataMarshaller;
import org.keycloak.broker.saml.SAMLDataMarshaller;
import org.keycloak.broker.saml.SAMLEndpoint;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.dom.saml.v2.protocol.LogoutRequestType;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.saml.JaxrsSAML2BindingBuilder;
import org.keycloak.protocol.saml.SamlSessionUtils;
import org.keycloak.protocol.saml.preprocessor.SamlAuthenticationPreprocessor;
import org.keycloak.saml.SAML2AuthnRequestBuilder;
import org.keycloak.saml.SAML2LogoutRequestBuilder;
import org.keycloak.saml.SAML2NameIDPolicyBuilder;
import org.keycloak.saml.SamlProtocolExtensionsAwareBuilder.NodeGenerator;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.processing.api.saml.v2.request.SAML2Request;
import org.keycloak.saml.validators.DestinationValidator;
import org.keycloak.utils.MediaType;

import com.google.common.base.Strings;

import it.infn.cnaf.sd.kc.metadata.SAMLAggregateMetadataStoreProvider;
import it.infn.cnaf.sd.kc.metadata.SAMLIdpDescriptor;


public class SAMLAggregateIdentityProvider
    extends AbstractIdentityProvider<SAMLAggregateIdentityProviderConfig> {

  private static final String SAML_AGGREGATE_CURRENT_IDP = "saml-aggregate-current-idp";

  private static final String IDP_ENTITY_ID_KEY = "saml-aggregate.idp_entity_id";
  private static final String WAYF_REQUESTED= "saml-aggregate.wayf_requested";

  protected static final Logger logger =
      Logger.getLogger(SAMLAggregateIdentityProviderConfig.class);

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


  protected Response redirectToWayf(AuthenticationRequest request) {

    final String providerAlias = getConfig().getAlias();

    request.getAuthenticationSession().setAuthNote(WAYF_REQUESTED, providerAlias);
    
    KeycloakUriInfo uriInfo = session.getContext().getUri();

    String wayfPagePath = String.format("realms/%s/saml-wayf/page", request.getRealm().getName());

//    String sessionCode = uriInfo.getQueryParameters().get(LoginActionsService.SESSION_CODE).get(0);
//    String tabId = uriInfo.getQueryParameters().get(Constants.TAB_ID).get(0);
//    String clientId = uriInfo.getQueryParameters().get("client_id").get(0);
    URI wayfURI = uriInfo.getBaseUriBuilder()
      .path(wayfPagePath)
      .queryParam("provider", providerAlias)
      // .queryParam("tabId", tabId)
      // .queryParam("clientId", clientId)
      // .queryParam("sessionCode", sessionCode)
      .build();

    return Response.temporaryRedirect(wayfURI).type(MediaType.TEXT_HTML_UTF_8_TYPE).build();
  }


  @Override
  public Response performLogin(AuthenticationRequest request) {

    try {

      UriInfo uriInfo = request.getUriInfo();
      RealmModel realm = request.getRealm();

      String providerAlias = getConfig().getAlias();
      String idpEntityId = uriInfo.getQueryParameters().getFirst("entity_id");

      if (Strings.isNullOrEmpty(idpEntityId)) {
        return redirectToWayf(request);
      }

      SAMLIdpDescriptor idp = getIdentityProviderFromEntityId(realm, providerAlias, idpEntityId);

      String issuerURL = getEntityId(uriInfo, realm);

      String protocolBinding = JBossSAMLURIConstants.SAML_HTTP_REDIRECT_BINDING.get();

      if (idp.isPostBindingResponse()) {
        protocolBinding = JBossSAMLURIConstants.SAML_HTTP_POST_BINDING.get();
      }

      String nameIDPolicyFormat = JBossSAMLURIConstants.NAMEID_FORMAT_PERSISTENT.get();
      Boolean isForceAuthn = false;

      String assertionConsumerServiceUrl = request.getRedirectUri();

      String destinationUrl = idp.getSingleSignOnServiceUrl();

      SAML2AuthnRequestBuilder authnRequestBuilder =
          new SAML2AuthnRequestBuilder().assertionConsumerUrl(assertionConsumerServiceUrl)
            .destination(destinationUrl)
            .issuer(issuerURL)
            .forceAuthn(isForceAuthn)
            .protocolBinding(protocolBinding)
            .nameIdPolicy(SAML2NameIDPolicyBuilder.format(nameIDPolicyFormat));
      JaxrsSAML2BindingBuilder binding =
          new JaxrsSAML2BindingBuilder(session).relayState(request.getState().getEncoded());

      boolean postBinding = idp.isPostBindingResponse();

      AuthnRequestType authnRequest = authnRequestBuilder.createAuthnRequest();
      for (Iterator<SamlAuthenticationPreprocessor> it =
          SamlSessionUtils.getSamlAuthenticationPreprocessorIterator(session); it.hasNext();) {
        authnRequest =
            it.next().beforeSendingLoginRequest(authnRequest, request.getAuthenticationSession());
      }

      if (postBinding) {
        return binding.postBinding(authnRequestBuilder.toDocument()).request(destinationUrl);
      } else {
        return binding.redirectBinding(authnRequestBuilder.toDocument()).request(destinationUrl);
      }
    } catch (Exception e) {
      throw new IdentityBrokerException("Could not create authentication request.", e);
    }
  }

  private SAMLIdpDescriptor getIdentityProviderFromEntityId(RealmModel realm, String providerAlias,
      String entityId) {

    SAMLAggregateMetadataStoreProvider md =
        session.getProvider(SAMLAggregateMetadataStoreProvider.class);

    Optional<SAMLIdpDescriptor> result = md.lookupIdpByEntityId(realm, providerAlias, entityId);

    if (!result.isPresent()) {
      throw new IdentityBrokerException(
          "Could not create authentication request. entity_id " + entityId + " not found.");
    }


    return result.get();
  }

  @Override
  public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {

    SAMLIdpDescriptor descriptor = null;
    return new SAMLAggregateEndpoint(realm, this, getConfig(), callback, descriptor,
        destinationValidator);
  }

  @Override
  public IdentityProviderDataMarshaller getMarshaller() {
    return new SAMLDataMarshaller();
  }

  private String getEntityId(UriInfo uriInfo, RealmModel realm) {
    return UriBuilder.fromUri(uriInfo.getBaseUri())
      .path("realms")
      .path(realm.getName())
      .build()
      .toString();
  }

  @Override
  public Response keycloakInitiatedBrowserLogout(KeycloakSession session,
      UserSessionModel userSession, UriInfo uriInfo, RealmModel realm) {

    SAMLIdpDescriptor idp = (SAMLIdpDescriptor) session.getAttribute(SAML_AGGREGATE_CURRENT_IDP);
    String singleLogoutServiceUrl = idp.getSingleLogoutServiceUrl();
    if (singleLogoutServiceUrl == null || singleLogoutServiceUrl.trim().equals(""))
      return null;

    try {
      LogoutRequestType logoutRequest =
          buildLogoutRequest(userSession, uriInfo, realm, singleLogoutServiceUrl);
      JaxrsSAML2BindingBuilder binding = buildLogoutBinding(session, userSession, realm);
      if (idp.isPostBindingLogout()) {
        return binding.postBinding(SAML2Request.convert(logoutRequest))
          .request(singleLogoutServiceUrl);
      } else {
        return binding.redirectBinding(SAML2Request.convert(logoutRequest))
          .request(singleLogoutServiceUrl);
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  protected LogoutRequestType buildLogoutRequest(UserSessionModel userSession, UriInfo uriInfo,
      RealmModel realm, String singleLogoutServiceUrl, NodeGenerator... extensions)
      throws ConfigurationException {
    SAML2LogoutRequestBuilder logoutBuilder =
        new SAML2LogoutRequestBuilder().assertionExpiration(realm.getAccessCodeLifespan())
          .issuer(getEntityId(uriInfo, realm))
          .sessionIndex(userSession.getNote(SAMLEndpoint.SAML_FEDERATED_SESSION_INDEX))
          .nameId(NameIDType
            .deserializeFromString(userSession.getNote(SAMLEndpoint.SAML_FEDERATED_SUBJECT_NAMEID)))
          .destination(singleLogoutServiceUrl);
    LogoutRequestType logoutRequest = logoutBuilder.createLogoutRequest();
    for (NodeGenerator extension : extensions) {
      logoutBuilder.addExtension(extension);
    }
    for (Iterator<SamlAuthenticationPreprocessor> it =
        SamlSessionUtils.getSamlAuthenticationPreprocessorIterator(session); it.hasNext();) {
      logoutRequest = it.next().beforeSendingLogoutRequest(logoutRequest, userSession, null);
    }
    return logoutRequest;
  }

  private JaxrsSAML2BindingBuilder buildLogoutBinding(KeycloakSession session,
      UserSessionModel userSession, RealmModel realm) {
    JaxrsSAML2BindingBuilder binding =
        new JaxrsSAML2BindingBuilder(session).relayState(userSession.getId());
    return binding;
  }

}
