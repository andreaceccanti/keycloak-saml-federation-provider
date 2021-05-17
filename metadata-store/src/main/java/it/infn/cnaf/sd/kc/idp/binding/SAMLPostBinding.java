package it.infn.cnaf.sd.kc.idp.binding;

import java.util.List;

import javax.xml.crypto.dsig.XMLSignature;

import org.keycloak.common.VerificationException;
import org.keycloak.dom.saml.v2.protocol.ResponseType;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.protocol.saml.SamlProtocolUtils;
import org.keycloak.saml.SAMLRequestParser;
import org.keycloak.saml.processing.core.saml.v2.common.SAMLDocumentHolder;
import org.keycloak.saml.processing.web.util.PostBindingUtil;
import org.w3c.dom.NodeList;

import it.infn.cnaf.sd.kc.idp.SAMLAggregateEndpoint;

public class SAMLPostBinding extends AbstractSAMLBinding {

  public SAMLPostBinding(SAMLAggregateEndpoint endpoint) {
    super(endpoint);
  }

  @Override
  public String getBindingType() {
    return SamlProtocol.SAML_POST_BINDING;
  }

  @Override
  public boolean containsUnencryptedSignature(SAMLDocumentHolder documentHolder) {
    NodeList nl =
        documentHolder.getSamlDocument().getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    return (nl != null && nl.getLength() > 0);
  }

  @Override
  public void verifySignature(String key, SAMLDocumentHolder documentHolder)
      throws VerificationException {

    if ((!containsUnencryptedSignature(documentHolder))
        && (documentHolder.getSamlObject() instanceof ResponseType)) {
      ResponseType responseType = (ResponseType) documentHolder.getSamlObject();
      List<ResponseType.RTChoiceType> assertions = responseType.getAssertions();
      if (!assertions.isEmpty()) {
        // Only relax verification if the response is an authnresponse and contains
        // (encrypted/plaintext) assertion.
        // In that case, signature is validated on assertion element
        return;
      }
    }
    SamlProtocolUtils.verifyDocumentSignature(documentHolder.getSamlDocument(), getIDPKeyLocator());

  }

  @Override
  public SAMLDocumentHolder extractRequestDocument(String samlRequest) {
    return SAMLRequestParser.parseRequestPostBinding(samlRequest);
  }

  @Override
  public SAMLDocumentHolder extractResponseDocument(String response) {
    byte[] samlBytes = PostBindingUtil.base64Decode(response);
    return SAMLRequestParser.parseResponseDocument(samlBytes);
  }

}
