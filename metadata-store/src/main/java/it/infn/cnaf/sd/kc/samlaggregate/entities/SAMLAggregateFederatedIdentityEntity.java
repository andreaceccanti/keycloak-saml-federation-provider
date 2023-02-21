package it.infn.cnaf.sd.kc.samlaggregate.entities;

import java.io.Serializable;
import java.util.Objects;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.IdClass;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;

import org.keycloak.models.jpa.entities.IdentityProviderEntity;
import org.keycloak.models.jpa.entities.RealmEntity;
import org.keycloak.models.jpa.entities.UserEntity;

@Entity
@Table(name = "SAML_AGGREGATE_FEDERATED_IDENTITY")
@NamedQueries({@NamedQuery(name = "findByRealmUserIdentityProviderAndFederatedUserId",
    query = "from SAMLAggregateFederatedIdentityEntity where realm.id = :realmId"
        + " and federatedUserId = :federatedUserId and identityProvider.internalId = :providerId and user.id = :userId"),
    @NamedQuery(name = "findByRealmAndUser",
        query = "from SAMLAggregateFederatedIdentityEntity where realm.id = :realmId and user.id = :userId"),
    @NamedQuery(name = "findByRealmAndFederatedUser",
        query = "from SAMLAggregateFederatedIdentityEntity where realm.id = :realmId and federatedUserId = :federatedUserId"),})
@IdClass(SAMLAggregateFederatedIdentityEntity.Key.class)
public class SAMLAggregateFederatedIdentityEntity implements Serializable {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  @Id
  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "REALM_ID")
  private RealmEntity realm;

  @Id
  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "USER_ID")
  private UserEntity user;

  @Id
  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "IDENTITY_PROVIDER_INTERNAL_ID")
  private IdentityProviderEntity identityProvider;

  @Id
  @Column(name = "FEDERATED_USER_ID", nullable = false)
  private String federatedUserId;

  @Column(name = "ENTITY_ID")
  private String entityId;

  @Column(name = "FEDERATED_USERNAME")
  private String federatedUsername;

  @Column(name = "TOKEN")
  private String token;

  public SAMLAggregateFederatedIdentityEntity() {}

  public RealmEntity getRealm() {
    return realm;
  }

  public void setRealm(RealmEntity realmId) {
    this.realm = realmId;
  }

  public UserEntity getUser() {
    return user;
  }

  public void setUser(UserEntity user) {
    this.user = user;
  }

  public IdentityProviderEntity getIdentityProvider() {
    return identityProvider;
  }

  public void setIdentityProvider(IdentityProviderEntity identityProvider) {
    this.identityProvider = identityProvider;
  }

  public String getFederatedUserId() {
    return federatedUserId;
  }

  public void setFederatedUserId(String federatedUserId) {
    this.federatedUserId = federatedUserId;
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
    return Objects.hash(federatedUserId, identityProvider.getInternalId(), realm.getId(),
        user.getId());
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    SAMLAggregateFederatedIdentityEntity other = (SAMLAggregateFederatedIdentityEntity) obj;
    return Objects.equals(federatedUserId, other.federatedUserId)
        && Objects.equals(identityProvider.getInternalId(), other.identityProvider.getInternalId())
        && Objects.equals(realm.getId(), other.realm.getId())
        && Objects.equals(user.getId(), other.getUser().getId());
  }

  @Override
  public String toString() {
    return "SAMLAggregateFederatedIdentityEntity [realmId=" + realm.getId() + ", userId="
        + user.getId() + ", identityProviderInternalId=" + identityProvider.getInternalId()
        + ", federatedUserId=" + federatedUserId + ", entityId=" + entityId + ", federatedUsername="
        + federatedUsername + ", token=" + token + "]";
  }

  public static class Key implements Serializable {

    private static final long serialVersionUID = 1L;

    protected RealmEntity realm;
    protected UserEntity user;
    protected IdentityProviderEntity identityProvider;
    protected String federatedUserId;

    public Key() {}

    public Key(RealmEntity realm, UserEntity user, IdentityProviderEntity identityProvider,
        String federatedUserId) {
      this.realm = realm;
      this.user = user;
      this.identityProvider = identityProvider;
      this.federatedUserId = federatedUserId;
    }

    public RealmEntity getRealm() {
      return realm;
    }

    public void setRealmId(RealmEntity realm) {
      this.realm = realm;
    }

    public UserEntity getUser() {
      return user;
    }

    public void setUser(UserEntity user) {
      this.user = user;
    }

    public IdentityProviderEntity getIdentityProvider() {
      return identityProvider;
    }

    public void setIdentityProviderInternalId(IdentityProviderEntity identityProvider) {
      this.identityProvider = identityProvider;
    }

    public String getFederatedUserId() {
      return federatedUserId;
    }

    public void setFederatedUserId(String federatedUserId) {
      this.federatedUserId = federatedUserId;
    }

    @Override
    public int hashCode() {
      return Objects.hash(federatedUserId, identityProvider.getInternalId(), realm.getId(),
          user.getId());
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj)
        return true;
      if (obj == null)
        return false;
      if (getClass() != obj.getClass())
        return false;
      Key other = (Key) obj;
      return Objects.equals(federatedUserId, other.federatedUserId)
          && Objects.equals(identityProvider.getInternalId(),
              other.identityProvider.getInternalId())
          && Objects.equals(realm.getId(), other.realm.getId())
          && Objects.equals(user.getId(), other.user.getId());
    }

    @Override
    public String toString() {
      return "Key [realmId=" + realm.getId() + ", userId=" + user.getId()
          + ", identityProviderInternalId=" + identityProvider.getInternalId()
          + ", federatedUserId=" + federatedUserId + "]";
    }

  }
}
