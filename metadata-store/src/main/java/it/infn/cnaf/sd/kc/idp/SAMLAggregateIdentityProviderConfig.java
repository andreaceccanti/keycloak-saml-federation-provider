package it.infn.cnaf.sd.kc.idp;

import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.saml.SamlPrincipalType;
import org.keycloak.saml.common.util.XmlKeyInfoKeyNameTransformer;

import it.infn.cnaf.sd.kc.metadata.SAMLAggregateMetadataStoreProvider;

public class SAMLAggregateIdentityProviderConfig extends IdentityProviderModel {

  public static final XmlKeyInfoKeyNameTransformer DEFAULT_XML_KEY_INFO_KEY_NAME_TRANSFORMER = XmlKeyInfoKeyNameTransformer.NONE;

  public static final String ADD_EXTENSIONS_ELEMENT_WITH_KEY_INFO = "addExtensionsElementWithKeyInfo";
  public static final String SP_ENTITY_ID = "spEntityId";
  public static final String METADATA_URL = "metadataUrl";
  public static final String POST_BINDING_LOGOUT = "postBindingLogout";
  public static final String POST_BINDING_RESPONSE = "postBindingResponse";
  public static final String SIGNATURE_ALGORITHM = "signatureAlgorithm";
  public static final String SIGNING_CERTIFICATE_KEY = "signingCertificate";
  public static final String SINGLE_LOGOUT_SERVICE_URL = "singleLogoutServiceUrl";
  public static final String WANT_ASSERTIONS_ENCRYPTED = "wantAssertionsEncrypted";
  public static final String WANT_ASSERTIONS_SIGNED = "wantAssertionsSigned";
  public static final String WANT_AUTHN_REQUESTS_SIGNED = "wantAuthnRequestsSigned";
  public static final String VALIDATE_SIGNATURE = "validateSignature";
  public static final String PRINCIPAL_TYPE = "principalType";
  public static final String PRINCIPAL_ATTRIBUTE = "principalAttribute";
  public static final String XML_SIG_KEY_INFO_KEY_NAME_TRANSFORMER = "xmlSigKeyInfoKeyNameTransformer";

  private static final long serialVersionUID = 1L;

  private KeycloakSessionFactory sessionFactory;

  public SAMLAggregateIdentityProviderConfig() {
    super();
  }

  public SAMLAggregateIdentityProviderConfig(IdentityProviderModel model) {
    super(model);
  }

  public String getMetadataUrl() {
    return getConfig().get(METADATA_URL);
  }

  public void setMetadataUrl(String metadataUrl) {
    getConfig().put(METADATA_URL, metadataUrl);
  }

  public String getSpEntityId() {
    return getConfig().get(SP_ENTITY_ID);
  }

  public void setSpEntityId(String entityId) {
    getConfig().put(SP_ENTITY_ID, entityId);
  }

  public boolean isWantAssertionsEncrypted() {
    return Boolean.valueOf(getConfig().get(WANT_ASSERTIONS_ENCRYPTED));
  }

  public void setWantAssertionsEncrypted(boolean wantAssertionsEncrypted) {
    getConfig().put(WANT_ASSERTIONS_ENCRYPTED, String.valueOf(wantAssertionsEncrypted));
  }

  public boolean isWantAssertionsSigned() {
    return Boolean.valueOf(getConfig().get(WANT_ASSERTIONS_SIGNED));
  }

  public void setWantAssertionsSigned(boolean wantAssertionsSigned) {
    getConfig().put(WANT_ASSERTIONS_SIGNED, String.valueOf(wantAssertionsSigned));
  }

  public boolean isValidateSignature() {
    return Boolean.valueOf(getConfig().get(VALIDATE_SIGNATURE));
  }

  public void setValidateSignature(boolean validateSignature) {
    getConfig().put(VALIDATE_SIGNATURE, String.valueOf(validateSignature));
  }

  public SamlPrincipalType getPrincipalType() {
    return SamlPrincipalType.from(getConfig().get(PRINCIPAL_TYPE), SamlPrincipalType.SUBJECT);
  }

  public void setPrincipalType(SamlPrincipalType principalType) {
    getConfig().put(PRINCIPAL_TYPE, principalType == null ? null : principalType.name());
  }

  public String getPrincipalAttribute() {
    return getConfig().get(PRINCIPAL_ATTRIBUTE);
  }

  public void setPrincipalAttribute(String principalAttribute) {
    getConfig().put(PRINCIPAL_ATTRIBUTE, principalAttribute);
  }

  public int getAllowedClockSkew() {
    int result = 0;
    String allowedClockSkew = getConfig().get(ALLOWED_CLOCK_SKEW);
    if (allowedClockSkew != null && !allowedClockSkew.isEmpty()) {
      try {
        result = Integer.parseInt(allowedClockSkew);
        if (result < 0) {
          result = 0;
        }
      } catch (NumberFormatException e) {
        // ignore it and use 0
      }
    }
    return result;
  }

  public void setAllowedClockSkew(int allowedClockSkew) {
    if (allowedClockSkew < 0) {
      getConfig().remove(ALLOWED_CLOCK_SKEW);
    } else {
      getConfig().put(ALLOWED_CLOCK_SKEW, String.valueOf(allowedClockSkew));
    }
  }

  public void addSigningCertificate(String signingCertificate) {
    String crt = getConfig().get(SIGNING_CERTIFICATE_KEY);
    if (crt == null || crt.isEmpty()) {
      getConfig().put(SIGNING_CERTIFICATE_KEY, signingCertificate);
    } else {
      // Note that "," is not coding character per PEM format specification:
      // see https://tools.ietf.org/html/rfc1421, section 4.3.2.4 Step 4: Printable Encoding
      getConfig().put(SIGNING_CERTIFICATE_KEY, crt + "," + signingCertificate);
    }
  }

  public String[] getSigningCertificates() {
    String crt = getConfig().get(SIGNING_CERTIFICATE_KEY);
    if (crt == null || crt.isEmpty()) {
      return new String[] { };
    }
    // Note that "," is not coding character per PEM format specification:
    // see https://tools.ietf.org/html/rfc1421, section 4.3.2.4 Step 4: Printable Encoding
    return crt.split(",");
  }

  public String getSingleLogoutServiceUrl() {
    return getConfig().get(SINGLE_LOGOUT_SERVICE_URL);
  }

  public void setSingleLogoutServiceUrl(String singleLogoutServiceUrl) {
    getConfig().put(SINGLE_LOGOUT_SERVICE_URL, singleLogoutServiceUrl);
  }

  public boolean isPostBindingLogout() {
    String postBindingLogout = getConfig().get(POST_BINDING_LOGOUT);
    if (postBindingLogout == null) {
      // To maintain unchanged behavior when adding this field, we set the inital value to equal that
      // of the binding for the response:
      return isPostBindingResponse();
    }
    return Boolean.valueOf(postBindingLogout);
  }

  public void setPostBindingLogout(boolean postBindingLogout) {
    getConfig().put(POST_BINDING_LOGOUT, String.valueOf(postBindingLogout));
  }

  public boolean isPostBindingResponse() {
    return Boolean.valueOf(getConfig().get(POST_BINDING_RESPONSE));
  }

  public void setPostBindingResponse(boolean postBindingResponse) {
    getConfig().put(POST_BINDING_RESPONSE, String.valueOf(postBindingResponse));
  }

  public boolean isWantAuthnRequestsSigned() {
    return Boolean.valueOf(getConfig().get(WANT_AUTHN_REQUESTS_SIGNED));
  }

  public void setWantAuthnRequestsSigned(boolean wantAuthnRequestsSigned) {
    getConfig().put(WANT_AUTHN_REQUESTS_SIGNED, String.valueOf(wantAuthnRequestsSigned));
  }

  @Override
  public void validate(RealmModel realm) {
    SAMLAggregateMetadataStoreProvider provider = getMetadataProvider();
    provider.parseMetadata(realm, getAlias(), getMetadataUrl());
  }

  private SAMLAggregateMetadataStoreProvider getMetadataProvider() {

    return sessionFactory.create().getProvider(SAMLAggregateMetadataStoreProvider.class);
  }

  public void setSessionFactory(KeycloakSessionFactory sessionFactory) {
    this.sessionFactory = sessionFactory;
  }

  public String getSignatureAlgorithm() {
    return getConfig().get(SIGNATURE_ALGORITHM);
  }

  public void setSignatureAlgorithm(String signatureAlgorithm) {
    getConfig().put(SIGNATURE_ALGORITHM, signatureAlgorithm);
  }

  public boolean isAddExtensionsElementWithKeyInfo() {
    return Boolean.valueOf(getConfig().get(ADD_EXTENSIONS_ELEMENT_WITH_KEY_INFO));
  }

  public void setAddExtensionsElementWithKeyInfo(boolean addExtensionsElementWithKeyInfo) {
    getConfig().put(ADD_EXTENSIONS_ELEMENT_WITH_KEY_INFO, String.valueOf(addExtensionsElementWithKeyInfo));
  }

  public XmlKeyInfoKeyNameTransformer getXmlSigKeyInfoKeyNameTransformer() {
    return XmlKeyInfoKeyNameTransformer.from(getConfig().get(XML_SIG_KEY_INFO_KEY_NAME_TRANSFORMER), DEFAULT_XML_KEY_INFO_KEY_NAME_TRANSFORMER);
  }


}
