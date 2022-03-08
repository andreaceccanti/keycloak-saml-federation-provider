package it.infn.cnaf.sd.kc.spi.impl;

import java.util.List;

import javax.persistence.EntityManager;

import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import com.google.common.collect.Lists;

import it.infn.cnaf.sd.kc.jpa.SAMLAggregateFederatedIdentity;
import it.infn.cnaf.sd.kc.spi.FederatedIdentityRepresentation;
import it.infn.cnaf.sd.kc.spi.SAMLAggregateFederatedIdentityServiceProvider;

public class SAMLAggregateFederatedIdentityServiceProviderImpl
    implements SAMLAggregateFederatedIdentityServiceProvider {

  private final KeycloakSession session;

  public SAMLAggregateFederatedIdentityServiceProviderImpl(KeycloakSession session) {
    this.session = session;
    if (getRealm() == null) {
      throw new IllegalStateException(
          "The service cannot accept a session without a realm in its context.");
    }
  }

  private EntityManager getEntityManager() {
    return session.getProvider(JpaConnectionProvider.class).getEntityManager();
  }

  protected RealmModel getRealm() {
    return session.getContext().getRealm();
  }

  @Override
  public void close() {
    // nothing to do
  }

  @Override
  public List<FederatedIdentityRepresentation> listsUserFederatedIdentities(String userId) {
    List<FederatedIdentityRepresentation> results = Lists.newArrayList();

    List<SAMLAggregateFederatedIdentity> entities = getEntityManager()
      .createNamedQuery("findByRealmAndUser", SAMLAggregateFederatedIdentity.class)
      .setParameter("realmId", getRealm().getId())
      .setParameter("userId", userId)
      .getResultList();

    for (SAMLAggregateFederatedIdentity entity : entities) {
      results.add(new FederatedIdentityRepresentation(entity));
    }
    return results;
  }

  @Override
  public FederatedIdentityRepresentation findFederatedIdentity(String userId, String idpId,
      String entityId) {

    FederatedIdentityRepresentation result = null;

    List<SAMLAggregateFederatedIdentity> entities = getEntityManager()
      .createNamedQuery("findByRealmUserIdpAndEntity", SAMLAggregateFederatedIdentity.class)
      .setParameter("realmId", getRealm().getId())
      .setParameter("userId", userId)
      .setParameter("idpId", idpId)
      .setParameter("entityId", entityId)
      .getResultList();

    if (entities.size() > 0) {
      result = new FederatedIdentityRepresentation(entities.get(0));
    }

    return result;
  }

  @Override
  public FederatedIdentityRepresentation addFederatedIdentity(
      FederatedIdentityRepresentation federatedIdentity) {

    SAMLAggregateFederatedIdentity entity = new SAMLAggregateFederatedIdentity();
    entity.setRealmId(federatedIdentity.getRealmId());
    entity.setUserId(federatedIdentity.getUserId());
    entity.setIdentityProvider(federatedIdentity.getIdentityProvider());
    entity.setFederatedEntityId(federatedIdentity.getFederatedEntityId());
    entity.setFederatedUsername(federatedIdentity.getFederatedUsername());
    entity.setFederatedUserId(federatedIdentity.getFederatedUserId());
    entity.setToken(federatedIdentity.getToken());

    getEntityManager().persist(entity);

    return federatedIdentity;
  }

}
