package it.infn.cnaf.sd.kc.jpa;

import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.persistence.EntityManager;

import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.jpa.JpaUserProvider;

import it.infn.cnaf.sd.kc.idp.SAMLAggregateIdentityProvider;

/* class not used */
public class SAMLAggregateJpaUserProvider extends JpaUserProvider {

  private final KeycloakSession session;

  public SAMLAggregateJpaUserProvider(KeycloakSession session, EntityManager em) {
    super(session, em);
    this.session = session;
  }

  private boolean isSAMLAggregateProvider(String identityProvider) {
    return session.getAllProviders(SAMLAggregateIdentityProvider.class)
      .stream()
      .filter(p -> p.getConfig().getAlias().equals(identityProvider))
      .collect(Collectors.toList())
      .size() > 0;
  }

  @Override
  public void addFederatedIdentity(RealmModel realm, UserModel user,
      FederatedIdentityModel identity) {

    /* check if you're managing a SAML Aggregate Identity Provider */
    if (isSAMLAggregateProvider(identity.getIdentityProvider())) {
      return;
    }
    super.addFederatedIdentity(realm, user, identity);
  }

  @Override
  public boolean removeFederatedIdentity(RealmModel realm, UserModel user, String identityProvider) {

    /* check if you're managing a SAML Aggregate Identity Provider */
    if (isSAMLAggregateProvider(identityProvider)) {
      return false;
    }
    return super.removeFederatedIdentity(realm, user, identityProvider);
  }

  @Override
  public void updateFederatedIdentity(RealmModel realm, UserModel federatedUser,
      FederatedIdentityModel identity) {

    /* check if you're managing a SAML Aggregate Identity Provider */
    if (isSAMLAggregateProvider(identity.getIdentityProvider())) {
      return;
    }
    super.updateFederatedIdentity(realm, federatedUser, identity);
  }

//  @Override
//  public Set<FederatedIdentityModel> getFederatedIdentities(UserModel user, RealmModel realm) {
//    return getFederatedIdentitiesStream(realm, user).collect(Collectors.toSet());
//  }

  @Override
  public Stream<FederatedIdentityModel> getFederatedIdentitiesStream(RealmModel realm,
      UserModel user) {

    return super.getFederatedIdentitiesStream(realm, user)
      .filter(f -> !isSAMLAggregateProvider(f.getIdentityProvider()));
  }

  @Override
  public FederatedIdentityModel getFederatedIdentity(RealmModel realm, UserModel user,
      String identityProvider) {

    /* check if you're managing a SAML Aggregate Identity Provider */
    if (isSAMLAggregateProvider(identityProvider)) {
      return null;
    }
    return super.getFederatedIdentity(realm, user, identityProvider);
  }

//  @Override
//  public UserModel getUserByFederatedIdentity(FederatedIdentityModel socialLink, RealmModel realm) {
//
//    return this.getUserByFederatedIdentity(realm, socialLink);
//  }

  @Override
  public UserModel getUserByFederatedIdentity(RealmModel realm, FederatedIdentityModel identity) {

    if (isSAMLAggregateProvider(identity.getIdentityProvider())) {
      return null;
    }
    return super.getUserByFederatedIdentity(realm, identity);
  }

}
