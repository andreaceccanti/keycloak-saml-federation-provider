package it.infn.cnaf.sd.kc.idp;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.saml.common.constants.GeneralConstants;
import org.keycloak.saml.validators.DestinationValidator;

import it.infn.cnaf.sd.kc.idp.binding.SAMLPostBinding;
import it.infn.cnaf.sd.kc.idp.binding.SAMLRedirectBinding;
import it.infn.cnaf.sd.kc.metadata.SAMLIdpDescriptor;

public class SAMLAggregateEndpoint {

  public static final Logger LOG = Logger.getLogger(SAMLAggregateEndpoint.class);

  protected EventBuilder event;

  protected final RealmModel realm;
  protected final SAMLAggregateIdentityProvider provider;
  protected final SAMLAggregateIdentityProviderConfig config;
  protected final IdentityProvider.AuthenticationCallback callback;
  protected final SAMLIdpDescriptor idpDescriptor;

  protected final DestinationValidator destinationValidator;

  @Context
  private KeycloakSession session;

  @Context
  private ClientConnection clientConnection;

  @Context
  private HttpHeaders headers;


  public SAMLAggregateEndpoint(RealmModel realm, SAMLAggregateIdentityProvider provider,
      SAMLAggregateIdentityProviderConfig config, IdentityProvider.AuthenticationCallback callback,
      SAMLIdpDescriptor idpDescriptor, DestinationValidator validator) {
    this.realm = realm;
    this.config = config;
    this.callback = callback;
    this.provider = provider;
    this.idpDescriptor = idpDescriptor;
    this.destinationValidator = validator;
  }

  @GET
  @NoCache
  @Path("descriptor")
  public Response getSPDescriptor() {
    return provider.export(session.getContext().getUri(), realm, null);
  }

  @GET
  public Response redirectBinding(@QueryParam(GeneralConstants.SAML_REQUEST_KEY) String samlRequest,
      @QueryParam(GeneralConstants.SAML_RESPONSE_KEY) String samlResponse,
      @QueryParam(GeneralConstants.RELAY_STATE) String relayState) {
    return new SAMLRedirectBinding(this).execute(samlRequest, samlResponse, relayState, null);
  }

  @POST
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  public Response postBinding(@FormParam(GeneralConstants.SAML_REQUEST_KEY) String samlRequest,
      @FormParam(GeneralConstants.SAML_RESPONSE_KEY) String samlResponse,
      @FormParam(GeneralConstants.RELAY_STATE) String relayState) {
    return new SAMLPostBinding(this).execute(samlRequest, samlResponse, relayState, null);
  }


  @Path("clients/{client_id}")
  @GET
  public Response redirectBinding(@QueryParam(GeneralConstants.SAML_REQUEST_KEY) String samlRequest,
      @QueryParam(GeneralConstants.SAML_RESPONSE_KEY) String samlResponse,
      @QueryParam(GeneralConstants.RELAY_STATE) String relayState,
      @PathParam("client_id") String clientId) {
    return new SAMLRedirectBinding(this).execute(samlRequest, samlResponse, relayState, clientId);
  }


  /**
   */
  @Path("clients/{client_id}")
  @POST
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  public Response postBinding(@FormParam(GeneralConstants.SAML_REQUEST_KEY) String samlRequest,
      @FormParam(GeneralConstants.SAML_RESPONSE_KEY) String samlResponse,
      @FormParam(GeneralConstants.RELAY_STATE) String relayState,
      @PathParam("client_id") String clientId) {
    return new SAMLPostBinding(this).execute(samlRequest, samlResponse, relayState, clientId);
  }

  public EventBuilder getEvent() {
    return event;
  }

  public void buildEventBuilder() {
    event = new EventBuilder(realm, session, clientConnection);
  }

  public KeycloakSession getSession() {
    return session;
  }

  public void setSession(KeycloakSession session) {
    this.session = session;
  }

  public ClientConnection getClientConnection() {
    return clientConnection;
  }

  public void setClientConnection(ClientConnection clientConnection) {
    this.clientConnection = clientConnection;
  }

  public HttpHeaders getHeaders() {
    return headers;
  }

  public void setHeaders(HttpHeaders headers) {
    this.headers = headers;
  }

  public RealmModel getRealm() {
    return realm;
  }

  public SAMLAggregateIdentityProvider getProvider() {
    return provider;
  }

  public SAMLAggregateIdentityProviderConfig getConfig() {
    return config;
  }

  public IdentityProvider.AuthenticationCallback getCallback() {
    return callback;
  }

  public SAMLIdpDescriptor getIdpDescriptor() {
    return idpDescriptor;
  }

  public DestinationValidator getDestinationValidator() {
    return destinationValidator;
  }
}
