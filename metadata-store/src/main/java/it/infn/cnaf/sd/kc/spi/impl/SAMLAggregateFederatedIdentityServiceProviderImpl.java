package it.infn.cnaf.sd.kc.spi.impl;

import static it.infn.cnaf.sd.kc.spi.SamlAggregateFederatedIdentityDTO.toDTO;
import static org.keycloak.utils.StreamsUtil.closing;

import java.util.List;
import java.util.stream.Stream;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;

import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.jpa.entities.IdentityProviderEntity;
import org.keycloak.models.jpa.entities.RealmEntity;
import org.keycloak.models.jpa.entities.UserEntity;

import com.google.common.collect.Lists;

import it.infn.cnaf.sd.kc.samlaggregate.entities.SAMLAggregateFederatedIdentityEntity;
import it.infn.cnaf.sd.kc.spi.SAMLAggregateFederatedIdentityServiceProvider;
import it.infn.cnaf.sd.kc.spi.SamlAggregateFederatedIdentityDTO;

public class SAMLAggregateFederatedIdentityServiceProviderImpl
    implements SAMLAggregateFederatedIdentityServiceProvider {

  protected static final Logger LOG =
      Logger.getLogger(SAMLAggregateFederatedIdentityServiceProviderImpl.class);

  private final KeycloakSession session;

  public SAMLAggregateFederatedIdentityServiceProviderImpl(KeycloakSession session) {
    this.session = session;
  }

  private EntityManager getEntityManager() {
    return session.getProvider(JpaConnectionProvider.class).getEntityManager();
  }

  @Override
  public void close() {
    // nothing to do
  }

  private Stream<SamlAggregateFederatedIdentityDTO> collect(
      Stream<SAMLAggregateFederatedIdentityEntity> entities) {
    List<SamlAggregateFederatedIdentityDTO> results = Lists.newArrayList();
    entities.forEach(fi -> results.add(toDTO(fi)));
    return closing(results.stream().distinct());
  }

  @Override
  public Stream<SamlAggregateFederatedIdentityDTO> list(String realmId, String userId) {

    return collect(getEntityManager()
      .createNamedQuery("findByRealmAndUser", SAMLAggregateFederatedIdentityEntity.class)
      .setParameter("realmId", realmId)
      .setParameter("userId", userId)
      .getResultStream());
  }

  @Override
  public Stream<SamlAggregateFederatedIdentityDTO> find(String realmId, String federatedUserId) {

    return collect(getEntityManager()
      .createNamedQuery("findByRealmAndFederatedUser", SAMLAggregateFederatedIdentityEntity.class)
      .setParameter("realmId", realmId)
      .setParameter("federatedUserId", federatedUserId)
      .getResultStream());
  }

  @Override
  public Stream<SamlAggregateFederatedIdentityDTO> find(String realmId, String userId, String idpId,
      String federatedUserId) {

    return collect(getEntityManager()
      .createNamedQuery("findByRealmUserIdentityProviderAndFederatedUserId",
          SAMLAggregateFederatedIdentityEntity.class)
      .setParameter("realmId", realmId)
      .setParameter("userId", userId)
      .setParameter("providerId", idpId)
      .setParameter("federatedUserId", federatedUserId)
      .getResultStream());
  }

  @Override
  public void add(SamlAggregateFederatedIdentityDTO dto) {

    add(dto.getRealmId(), dto.getUserId(), dto.getIdentityProviderInternalId(),
        dto.getFederatedUserId(), dto.getEntityId(), dto.getFederatedUsername());
  }

  @Override
  public void updateToken(String realmId, String userId, String idpId, String federatedUserId,
      String token) {

    EntityManager em = getEntityManager();

    LOG.info("Looking for realm by id: " + realmId);
    RealmEntity realm = em.find(RealmEntity.class, realmId);
    LOG.info("Found: " + realm.getName());
    LOG.info("Looking for user by id: " + userId);
    UserEntity user = em.find(UserEntity.class, userId);
    LOG.info("Found: " + user.getUsername());
    LOG.info("Looking for identity provider by id: " + idpId);
    IdentityProviderEntity identityProvider = em.find(IdentityProviderEntity.class, idpId);
    LOG.info("Found: " + identityProvider.getAlias());

    updateToken(new SAMLAggregateFederatedIdentityEntity.Key(realm, user, identityProvider,
        federatedUserId), token);
  }

  @Override
  public void updateToken(SamlAggregateFederatedIdentityDTO updateMe, String token) {

    updateToken(updateMe.getRealmId(), updateMe.getUserId(),
        updateMe.getIdentityProviderInternalId(), updateMe.getFederatedUserId(), token);
  }

  private void updateToken(SAMLAggregateFederatedIdentityEntity.Key pk, String token) {

    EntityManager em = getEntityManager();

    LOG.info("Looking for SAML Aggregate Federated Identity by: " + pk);

    SAMLAggregateFederatedIdentityEntity toUpdate = getEntityManager()
      .createNamedQuery("findByRealmUserIdentityProviderAndFederatedUserId",
          SAMLAggregateFederatedIdentityEntity.class)
      .setParameter("realmId", pk.getRealm().getId())
      .setParameter("userId", pk.getUser().getId())
      .setParameter("providerId", pk.getIdentityProvider().getInternalId())
      .setParameter("federatedUserId", pk.getFederatedUserId())
      .getSingleResult();

    if (toUpdate == null) {
      throw new NoResultException();
    }

    LOG.info("Found: " + toUpdate);
    toUpdate.setToken(token);

    em.persist(toUpdate);
    em.flush();
  }

  private int remove(SAMLAggregateFederatedIdentityEntity.Key k) {

    EntityManager em = getEntityManager();

    SAMLAggregateFederatedIdentityEntity rmEntity =
        em.find(SAMLAggregateFederatedIdentityEntity.class, k);

    try {
      em.remove(rmEntity);
      em.flush();
      return 1;
    } catch (NoResultException e) {
      return 0;
    }
  }

  @Override
  public int remove(SamlAggregateFederatedIdentityDTO removeMe) {

    return remove(removeMe.getRealmId(), removeMe.getUserId(),
        removeMe.getIdentityProviderInternalId(), removeMe.getFederatedUserId());
  }

  @Override
  public int remove(String realmId, String userId, String idpId, String federatedUserId) {

    EntityManager em = getEntityManager();

    LOG.info("Looking for realm by id: " + realmId);
    RealmEntity realm = em.find(RealmEntity.class, realmId);
    LOG.info("Found: " + realm.getName());
    LOG.info("Looking for user by id: " + userId);
    UserEntity user = em.find(UserEntity.class, userId);
    LOG.info("Found: " + user.getUsername());
    LOG.info("Looking for identity provider by id: " + idpId);
    IdentityProviderEntity identityProvider = em.find(IdentityProviderEntity.class, idpId);
    LOG.info("Found: " + identityProvider.getAlias());

    return remove(new SAMLAggregateFederatedIdentityEntity.Key(realm, user, identityProvider,
        federatedUserId));
  }

  @Override
  public void add(String realmId, String userId, String idpId, String federatedUserId,
      String entityId, String federatedUsername) {

    EntityManager em = getEntityManager();
    LOG.info("Looking for realm by id: " + realmId);
    RealmEntity realm = em.find(RealmEntity.class, realmId);
    LOG.info("Found: " + realm.getName());
    LOG.info("Looking for user by id: " + userId);
    UserEntity user = em.find(UserEntity.class, userId);
    LOG.info("Found: " + user.getUsername());
    LOG.info("Looking for identity provider by id: " + idpId);
    IdentityProviderEntity identityProvider = em.find(IdentityProviderEntity.class, idpId);
    LOG.info("Found: " + identityProvider.getAlias());

    SAMLAggregateFederatedIdentityEntity entity = new SAMLAggregateFederatedIdentityEntity();
    entity.setRealm(realm);
    entity.setUser(user);
    entity.setIdentityProvider(identityProvider);
    entity.setFederatedUserId(federatedUserId);
    entity.setEntityId(entityId);
    entity.setFederatedUsername(federatedUsername);
    LOG.info("Saving SAML Aggregate Federated Identity: " + entity);
    em.persist(entity);
    em.flush();
  }

}
