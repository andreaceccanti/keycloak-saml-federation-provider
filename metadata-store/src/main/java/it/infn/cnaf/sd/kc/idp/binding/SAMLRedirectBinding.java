package it.infn.cnaf.sd.kc.idp.binding;

import javax.ws.rs.core.MultivaluedMap;

import org.keycloak.common.VerificationException;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.protocol.saml.SamlProtocolUtils;
import org.keycloak.rotation.KeyLocator;
import org.keycloak.saml.SAMLRequestParser;
import org.keycloak.saml.common.constants.GeneralConstants;
import org.keycloak.saml.processing.core.saml.v2.common.SAMLDocumentHolder;

import it.infn.cnaf.sd.kc.idp.SAMLAggregateEndpoint;

public class SAMLRedirectBinding extends AbstractSAMLBinding {

  public SAMLRedirectBinding(SAMLAggregateEndpoint endpoint) {
    super(endpoint);
  }

  @Override
  public boolean containsUnencryptedSignature(SAMLDocumentHolder documentHolder) {

    MultivaluedMap<String, String> encodedParams =
        endpoint.getSession().getContext().getUri().getQueryParameters(false);

    String algorithm = encodedParams.getFirst(GeneralConstants.SAML_SIG_ALG_REQUEST_KEY);
    String signature = encodedParams.getFirst(GeneralConstants.SAML_SIGNATURE_REQUEST_KEY);
    return algorithm != null && signature != null;
  }

  @Override
  public void verifySignature(String key, SAMLDocumentHolder documentHolder)
      throws VerificationException {

    KeyLocator locator = getIDPKeyLocator();
    SamlProtocolUtils.verifyRedirectSignature(documentHolder, locator,
        endpoint.getSession().getContext().getUri(), key);
  }

  @Override
  public SAMLDocumentHolder extractRequestDocument(String samlRequest) {
    return SAMLRequestParser.parseRequestRedirectBinding(samlRequest);
  }

  @Override
  public SAMLDocumentHolder extractResponseDocument(String response) {
    return SAMLRequestParser.parseResponseRedirectBinding(response);
  }

  @Override
  public String getBindingType() {
    return SamlProtocol.SAML_REDIRECT_BINDING;
  }
}
