package it.infn.cnaf.sd.kc.samlaggregate.resources.model;

import org.keycloak.representations.account.LinkedAccountRepresentation;

public class SAMLAggregateLinkedAccountRepresentation extends LinkedAccountRepresentation {

  private String realmId;
  private String userId;
  private String entityId;
  private boolean isSAMLAggregate;
  private String federatedUserId;
  private String idpId;

  public String getRealmId() {
    return realmId;
  }

  public void setRealmId(String realmId) {
    this.realmId = realmId;
  }

  public String getUserId() {
    return userId;
  }

  public void setUserId(String userId) {
    this.userId = userId;
  }

  public String getEntityId() {
    return entityId;
  }

  public void setEntityId(String entityId) {
    this.entityId = entityId;
  }

  public boolean isSAMLAggregate() {
    return isSAMLAggregate;
  }

  public void setSAMLAggregate(boolean isSAMLAggregate) {
    this.isSAMLAggregate = isSAMLAggregate;
  }

  public String getFederatedUserId() {
    return federatedUserId;
  }

  public void setFederatedUserId(String federatedUserId) {
    this.federatedUserId = federatedUserId;
  }

  public String getIdpId() {
    return idpId;
  }

  public void setIdpId(String idpId) {
    this.idpId = idpId;
  }

}
