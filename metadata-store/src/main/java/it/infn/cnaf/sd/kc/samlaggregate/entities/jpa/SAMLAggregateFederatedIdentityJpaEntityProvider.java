package it.infn.cnaf.sd.kc.samlaggregate.entities.jpa;

import java.util.Collections;
import java.util.List;

import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;

import it.infn.cnaf.sd.kc.samlaggregate.entities.SAMLAggregateFederatedIdentityEntity;

public class SAMLAggregateFederatedIdentityJpaEntityProvider implements JpaEntityProvider {

  @Override
  public void close() {
  }

  @Override
  public List<Class<?>> getEntities() {
    return Collections.<Class<?>>singletonList(SAMLAggregateFederatedIdentityEntity.class);
  }

  @Override
  public String getChangelogLocation() {
    return "META-INF/federated-identity-changelog.xml";
  }

  @Override
  public String getFactoryId() {
    return SAMLAggregateFederatedIdentityJpaEntityProviderFactory.ID;
  }

}
