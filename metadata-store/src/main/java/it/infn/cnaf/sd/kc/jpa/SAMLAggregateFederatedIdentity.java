package it.infn.cnaf.sd.kc.jpa;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;

@Entity
@Table(name = "SAML_AGGREGATE_FEDERATED_IDENTITY")
@NamedQueries({@NamedQuery(name = "findByRealmAndUser",
    query = "from SAMLAggregateFederatedIdentity where realmId = :realmId and userId = :userId"),
    @NamedQuery(name = "findByRealmUserIdpAndEntity",
        query = "from SAMLAggregateFederatedIdentity where realmId = :realmId and userId = :userId and federatedEntityId = :entityId and identityProvider = :idpId")})
public class SAMLAggregateFederatedIdentity implements Serializable {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  @Id
  @Column(name = "USER_ID", nullable = false)
  private String userId;

  @Id
  @Column(name = "FEDERATED_ENTITY_ID", nullable = false)
  private String federatedEntityId;

  @Id
  @Column(name = "IDENTITY_PROVIDER", nullable = false)
  private String identityProvider;

  @Column(name = "REALM_ID", nullable = false)
  private String realmId;

  @Column(name = "FEDERATED_USER_ID")
  private String federatedUserId;

  @Column(name = "FEDERATED_USERNAME")
  private String federatedUsername;

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

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((federatedEntityId == null) ? 0 : federatedEntityId.hashCode());
    result = prime * result + ((federatedUserId == null) ? 0 : federatedUserId.hashCode());
    result = prime * result + ((identityProvider == null) ? 0 : identityProvider.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    SAMLAggregateFederatedIdentity other = (SAMLAggregateFederatedIdentity) obj;
    if (federatedEntityId == null) {
      if (other.federatedEntityId != null)
        return false;
    } else if (!federatedEntityId.equals(other.federatedEntityId))
      return false;
    if (federatedUserId == null) {
      if (other.federatedUserId != null)
        return false;
    } else if (!federatedUserId.equals(other.federatedUserId))
      return false;
    if (identityProvider == null) {
      if (other.identityProvider != null)
        return false;
    } else if (!identityProvider.equals(other.identityProvider))
      return false;
    return true;
  }

}
