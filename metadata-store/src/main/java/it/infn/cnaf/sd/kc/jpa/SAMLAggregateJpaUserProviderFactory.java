package it.infn.cnaf.sd.kc.jpa;

import javax.persistence.EntityManager;

import org.keycloak.Config;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserProvider;
import org.keycloak.models.UserProviderFactory;

public class SAMLAggregateJpaUserProviderFactory implements UserProviderFactory {

	@Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return "eosc-kc-jpa";
    }

    @Override
    public UserProvider create(KeycloakSession session) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new SAMLAggregateJpaUserProvider(session, em);
    }

    @Override
    public void close() {
    }

    @Override
    public int order() {
        return 1;
    }

}
