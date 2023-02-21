package it.infn.cnaf.sd.kc.jpa;

import java.util.Collections;
import java.util.List;

import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;

public class SAMLAggregateFederatedIdentityJpaEntityProvider implements JpaEntityProvider {

  @Override
  public void close() {
  }

  @Override
  public List<Class<?>> getEntities() {
    return Collections.<Class<?>>singletonList(SAMLAggregateFederatedIdentity.class);
  }

  @Override
  public String getChangelogLocation() {
    return "META-INF/linked-providers-changelog.xml";
  }

  @Override
  public String getFactoryId() {
    return SAMLAggregateFederatedIdentityJpaEntityProviderFactory.ID;
  }

}
