package it.infn.cnaf.sd.kc.spi;

import it.infn.cnaf.sd.kc.jpa.SAMLAggregateFederatedIdentity;

public class FederatedIdentityRepresentation {

  private String userId;
  private String federatedEntityId;
  private String identityProvider;
  private String realmId;
  private String federatedUserId;
  private String federatedUsername;

  public FederatedIdentityRepresentation() {}

  public FederatedIdentityRepresentation(SAMLAggregateFederatedIdentity fi) {

    userId = fi.getUserId();
    federatedEntityId = fi.getFederatedEntityId();
    identityProvider = fi.getIdentityProvider();
    realmId = fi.getRealmId();
    federatedUserId = fi.getFederatedUserId();
    federatedUsername = fi.getFederatedUsername();
  }

  public String getUserId() {
    return userId;
  }

  public void setUserId(String userId) {
    this.userId = userId;
  }

  public String getFederatedEntityId() {
    return federatedEntityId;
  }

  public void setFederatedEntityId(String federatedEntityId) {
    this.federatedEntityId = federatedEntityId;
  }

  public String getIdentityProvider() {
    return identityProvider;
  }

  public void setIdentityProvider(String identityProvider) {
    this.identityProvider = identityProvider;
  }

  public String getRealmId() {
    return realmId;
  }

  public void setRealmId(String realmId) {
    this.realmId = realmId;
  }

  public String getFederatedUserId() {
    return federatedUserId;
  }

  public void setFederatedUserId(String federatedUserId) {
    this.federatedUserId = federatedUserId;
  }

  public String getFederatedUsername() {
    return federatedUsername;
  }

  public void setFederatedUsername(String federatedUsername) {
    this.federatedUsername = federatedUsername;
  }

}
