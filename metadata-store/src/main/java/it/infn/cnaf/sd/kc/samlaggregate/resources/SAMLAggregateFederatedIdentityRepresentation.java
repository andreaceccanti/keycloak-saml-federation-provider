package it.infn.cnaf.sd.kc.samlaggregate.resources;

public class SAMLAggregateFederatedIdentityRepresentation {

  protected String identityProvider;
  protected String entityId;
  protected String userId;
  protected String userName;

  public String getIdentityProvider() {
      return identityProvider;
  }

  public void setIdentityProvider(String identityProvider) {
      this.identityProvider = identityProvider;
  }

  public String getUserId() {
      return userId;
  }

  public void setUserId(String userId) {
      this.userId = userId;
  }

  public String getUserName() {
      return userName;
  }

  public void setUserName(String userName) {
      this.userName = userName;
  }

  public String getEntityId() {
    return entityId;
  }

  public void setEntityId(String entityId) {
    this.entityId = entityId;
  }
}
