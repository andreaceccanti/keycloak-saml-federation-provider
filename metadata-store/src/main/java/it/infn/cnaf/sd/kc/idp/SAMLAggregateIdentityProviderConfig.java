package it.infn.cnaf.sd.kc.idp;

import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.saml.SamlPrincipalType;

import it.infn.cnaf.sd.kc.metadata.SAMLAggregateMetadataStoreProvider;

public class SAMLAggregateIdentityProviderConfig extends IdentityProviderModel {


  public static final String SP_ENTITY_ID = "spEntityId";
  public static final String METADATA_URL = "metadataUrl";
  public static final String WANT_ASSERTIONS_ENCRYPTED = "wantAssertionsEncrypted";
  public static final String WANT_ASSERTIONS_SIGNED = "wantAssertionsSigned";
  public static final String VALIDATE_SIGNATURE = "validateSignature";
  public static final String PRINCIPAL_TYPE = "principalType";
  public static final String PRINCIPAL_ATTRIBUTE = "principalAttribute";

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
}
