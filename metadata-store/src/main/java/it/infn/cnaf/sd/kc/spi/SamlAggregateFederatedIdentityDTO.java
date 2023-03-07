package it.infn.cnaf.sd.kc.spi;

import java.util.Objects;

import it.infn.cnaf.sd.kc.samlaggregate.entities.SAMLAggregateFederatedIdentityEntity;
import it.infn.cnaf.sd.kc.samlaggregate.resources.SAMLAggregateFederatedIdentityRepresentation;

public class SamlAggregateFederatedIdentityDTO {

  private String realmId;
  private String userId;
  private String username;
  private String federatedUserId;
  private String federatedUsername;
  private String identityProviderInternalId;
  private String identityProviderAlias;
  private String entityId;
  private String token;

  public SamlAggregateFederatedIdentityDTO() {}

  public static SamlAggregateFederatedIdentityDTO toDTO (SAMLAggregateFederatedIdentityEntity entity) {

    SamlAggregateFederatedIdentityDTO dto = new SamlAggregateFederatedIdentityDTO();
    dto.setRealmId(entity.getRealm().getId());
    dto.setUserId(entity.getUser().getId());
    dto.setUsername(entity.getUser().getUsername());
    dto.setIdentityProviderInternalId(entity.getIdentityProvider().getInternalId());
    dto.setIdentityProviderAlias(entity.getIdentityProvider().getAlias());
    dto.setFederatedUserId(entity.getFederatedUserId());
    dto.setEntityId(entity.getEntityId());
    dto.setFederatedUsername(entity.getFederatedUsername());
    dto.setToken(entity.getToken());
    return dto;
  }

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

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getFederatedUserId() {
    return federatedUserId;
  }

  public void setFederatedUserId(String federatedUserId) {
    this.federatedUserId = federatedUserId;
  }

  public String getIdentityProviderInternalId() {
    return identityProviderInternalId;
  }

  public void setIdentityProviderInternalId(String identityProviderInternalId) {
    this.identityProviderInternalId = identityProviderInternalId;
  }

  public String getIdentityProviderAlias() {
    return identityProviderAlias;
  }

  public void setIdentityProviderAlias(String identityProviderAlias) {
    this.identityProviderAlias = identityProviderAlias;
  }

  public String getEntityId() {
    return entityId;
  }

  public void setEntityId(String entityId) {
    this.entityId = entityId;
  }

  public String getFederatedUsername() {
    return federatedUsername;
  }

  public void setFederatedUsername(String federatedUsername) {
    this.federatedUsername = federatedUsername;
  }

  public String getToken() {
    return token;
  }

  public void setToken(String token) {
    this.token = token;
  }

  @Override
  public int hashCode() {
    return Objects.hash(federatedUserId, identityProviderInternalId, realmId, userId);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    SamlAggregateFederatedIdentityDTO other = (SamlAggregateFederatedIdentityDTO) obj;
    return Objects.equals(federatedUserId, other.federatedUserId)
        && Objects.equals(identityProviderInternalId, other.identityProviderInternalId)
        && Objects.equals(realmId, other.realmId) && Objects.equals(userId, other.userId);
  }

  public SAMLAggregateFederatedIdentityRepresentation toRepresentation() {
    
    SAMLAggregateFederatedIdentityRepresentation o = new SAMLAggregateFederatedIdentityRepresentation();
    o.setEntityId(entityId);
    o.setIdentityProvider(identityProviderAlias);
    o.setUserId(federatedUserId);
    o.setUserName(federatedUsername);
    return o;
  }
}
