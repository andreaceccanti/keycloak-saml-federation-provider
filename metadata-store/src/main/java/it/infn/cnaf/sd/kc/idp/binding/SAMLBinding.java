package it.infn.cnaf.sd.kc.idp.binding;

import java.util.Optional;

import javax.ws.rs.core.Response;

import org.keycloak.common.VerificationException;
import org.keycloak.dom.saml.v2.protocol.LogoutRequestType;
import org.keycloak.dom.saml.v2.protocol.ResponseType;
import org.keycloak.dom.saml.v2.protocol.StatusResponseType;
import org.keycloak.rotation.KeyLocator;
import org.keycloak.saml.processing.core.saml.v2.common.SAMLDocumentHolder;

public interface SAMLBinding {

  String getBindingType();
  boolean checkSsl();

  Optional<Response> basicSanityChecks(String samlRequest, String samlResponse);

  boolean containsUnencryptedSignature(SAMLDocumentHolder documentHolder);

  void verifySignature(String key, SAMLDocumentHolder documentHolder) throws VerificationException;

  SAMLDocumentHolder extractRequestDocument(String samlRequest);

  SAMLDocumentHolder extractResponseDocument(String response);

  KeyLocator getIDPKeyLocator();


  Response execute(String samlRequest, String samlResponse, String relayState, String clientId);

  Response handleSamlRequest(String samlRequest, String relayState);

  Response handleSamlResponse(String samlResponse, String relayState, String clientId);

  Response handleLoginResponse(String samlResponse, SAMLDocumentHolder documentHolder,
      ResponseType responseType, String relayState, String clientId);

  Response handleLogoutResponse(SAMLDocumentHolder holder, StatusResponseType responseType,
      String relayState);

  Response logoutRequest(LogoutRequestType request, String relayState);


}
