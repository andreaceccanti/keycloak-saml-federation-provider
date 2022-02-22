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

  @Override
  public void close() {

  }

  @Override
  public Object getResource() {
    return this;
  }

}
