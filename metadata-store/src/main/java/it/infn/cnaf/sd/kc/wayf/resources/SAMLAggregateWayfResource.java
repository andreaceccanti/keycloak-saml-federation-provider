package it.infn.cnaf.sd.kc.wayf.resources;

import java.net.URI;
import java.util.List;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.jboss.logging.Logger;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

import it.infn.cnaf.sd.kc.metadata.SAMLAggregateMetadataStoreProvider;
import it.infn.cnaf.sd.kc.metadata.SAMLIdpDescriptor;

public class SAMLAggregateWayfResource implements RealmResourceProvider {

  public static final String ENTITY_ID_PARAM = "entityID";
  public static final String RETURN_PARAM = "return";
  public static final String RETURN_ID_PARAM = "returnIDParam";

  protected static final Logger LOG = Logger.getLogger(SAMLAggregateWayfResource.class);

  protected KeycloakSession session;

  public SAMLAggregateWayfResource(KeycloakSession session) {
    this.session = session;
  }

  @GET
  @Path("{provider}")
  @Produces(MediaType.TEXT_HTML)
  public Response discover(final @PathParam("provider") String providerAlias,
      final @QueryParam(ENTITY_ID_PARAM) String entityIdParam,
      final @QueryParam(RETURN_PARAM) String returnParam,
      final @QueryParam(RETURN_ID_PARAM) String returnIdParam) {

    LoginFormsProvider loginFormsProvider = session.getProvider(LoginFormsProvider.class);

    SAMLAggregateMetadataStoreProvider md = session.getProvider(SAMLAggregateMetadataStoreProvider.class);
    List<SAMLIdpDescriptor> descriptors = null;
    try {
     descriptors = md.getEntities(session.getContext().getRealm(), providerAlias);
    } catch (RuntimeException e) {
      return loginFormsProvider.setError(e.getMessage()).createErrorPage(Status.BAD_REQUEST);
    }

    return loginFormsProvider
         .setAttribute("provider", providerAlias)
         .setAttribute("actionUrl", returnParam)
         .setAttribute(ENTITY_ID_PARAM, entityIdParam)
         .setAttribute(RETURN_PARAM, returnParam)
         .setAttribute(RETURN_ID_PARAM, returnIdParam)
         .setAttribute("descriptors", descriptors)
         .createForm("saml-wayf.ftl");
  }


  @GET
  @Path("/{provider}/ex")
  @Produces("text/plain; charset=utf-8")
  public String getWayfPage(final @PathParam("provider") String provider,
      final @QueryParam(Constants.CLIENT_ID) String clientId) {

    String name = session.getContext().getRealm().getDisplayName();
    if (name == null) {
      name = session.getContext().getRealm().getName();
    }
    return "Hello from " + name + " realm " + provider + "'s wayf. Got clientId = " + clientId;

    // RealmModel realmModel = init(name);
    // IdentityProviderModel idpConfig = realmModel.getIdentityProviderByAlias(providerAlias);
    //
    // if (Objects.isNull(idpConfig)
    // || !SAMLAggregateIdentityProviderFactory.PROVIDER_ID.equals(idpConfig.getProviderId())) {
    // throw new ErrorResponseException("Invalid WAYF provider",
    // "Provider " + providerAlias + " does not exist or is not a SAMLAggregateProvider",
    // Response.Status.BAD_REQUEST);
    // }
    //
    // String BASE_URL = request.getUri().getBaseUri().toString();
    // String actionUrl;
    //
    // LoginFormsProvider loginFormsProvider = session.getProvider(LoginFormsProvider.class);
    // SAMLAggregateMetadataStoreProvider md =
    // session.getProvider(SAMLAggregateMetadataStoreProvider.class);
    // List<SAMLIdpDescriptor> descriptors = md.getEntities(realmModel, providerAlias);
    //
    // actionUrl = BASE_URL + "saml-aggregate-broker/login";
    //
    // return loginFormsProvider
    // .setAttribute("provider", providerAlias)
    // .setAttribute("actionUrl", actionUrl)
    // .setAttribute("descriptors", descriptors)
    // .createForm("saml-wayf.ftl");

  }


  @Override
  public void close() {

  }


  @Override
  public Object getResource() {
    return this;
  }

  // @GET
  // @Path("page")
  // @Produces(MediaType.TEXT_HTML)
  // public Response getWayfPage(final @PathParam("realm") String name,
  // @QueryParam("provider") String providerAlias, @Context HttpServletRequest httpRequest)
  // throws IOException, FreeMarkerException {
  //
  // if (Strings.isNullOrEmpty(providerAlias)) {
  // throw new ErrorResponseException("Bad request", "Please specify a provider",
  // Response.Status.BAD_REQUEST);
  // }
  //
  // HttpSession httpSession = httpRequest.getSession(false);
  //
  // RealmModel realm = init(name);
  //
  // IdentityProviderModel idpConfig = realm.getIdentityProviderByAlias(providerAlias);
  //
  // if (Objects.isNull(idpConfig)
  // || !SAMLAggregateIdentityProviderFactory.PROVIDER_ID.equals(idpConfig.getProviderId())) {
  // throw new ErrorResponseException("Invalid WAYF provider",
  // "Provider " + providerAlias + " does not exist or is not a SAMLAggregateProvider",
  // Response.Status.BAD_REQUEST);
  // }
  //
  // Map<String, String> attributes = new HashMap<>();
  // attributes.put("realm", name);
  // attributes.put("provider", providerAlias);
  //
  // Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
  //
  // FreeMarkerUtil freemarker = new FreeMarkerUtil();
  // String wayfHtml = freemarker.processTemplate(attributes, "saml-wayf.ftl", theme);
  //
  // Response.ResponseBuilder rb = Response.status(Response.Status.OK)
  // .entity(wayfHtml)
  // .cacheControl(CacheControlUtil.noCache());
  //
  // return rb.build();
  // }

  // @GET
  // @Path("{realm}/saml-wayf")
  // @Produces(MediaType.APPLICATION_JSON)
  // public Response lookupIdps(final @PathParam("realm") String name,
  // @QueryParam("provider") String providerAlias, @QueryParam("q") String matchString) {
  //
  // if (Strings.isNullOrEmpty(providerAlias)) {
  // throw new ErrorResponseException("Bad request", "Please specify a provider",
  // Response.Status.BAD_REQUEST);
  // }
  //
  // if (Strings.isNullOrEmpty(matchString)) {
  // throw new ErrorResponseException("Bad request", "Please specify a query string",
  // Response.Status.BAD_REQUEST);
  // }
  //
  // RealmModel realm = init(name);
  //
  // IdentityProviderModel idpConfig = realm.getIdentityProviderByAlias(providerAlias);
  //
  // if (!SAMLAggregateIdentityProviderFactory.PROVIDER_ID.equals(idpConfig.getProviderId())) {
  // throw new ErrorResponseException("Invalid WAYF provider",
  // "Provider " + providerAlias + " does not exist or is not a SAMLAggregateProvider",
  // Response.Status.BAD_REQUEST);
  // }
  //
  // SAMLAggregateMetadataStoreProvider md =
  // session.getProvider(SAMLAggregateMetadataStoreProvider.class);
  //
  // List<SAMLAggregateIdpRepresentation> results =
  // md.lookupEntities(realm, providerAlias, matchString)
  // .stream()
  // .map(this::toRepresentation)
  // .collect(Collectors.toList());
  //
  // SAMLAggreateWayfResponseRepresentation envelope = new SAMLAggreateWayfResponseRepresentation();
  //
  // envelope.setProvider(providerAlias);
  // envelope.setQuery(matchString);
  // envelope.setRealm(realm.getName());
  // envelope.setResults(results);
  //
  // return Response.ok(envelope).build();
  // }
  //
  //
  //
  // SAMLAggregateIdpRepresentation toRepresentation(SAMLIdpDescriptor descriptor) {
  // SAMLAggregateIdpRepresentation repr = new SAMLAggregateIdpRepresentation();
  // repr.setDiplayName(descriptor.getDisplayName());
  // repr.setEntityId(descriptor.getEntityId());
  // return repr;
  // }

}
