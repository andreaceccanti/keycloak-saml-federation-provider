package it.infn.cnaf.sd.kc.spi;

import java.util.List;

import org.keycloak.provider.Provider;

public interface SAMLAggregateFederatedIdentityServiceProvider extends Provider {

  List<FederatedIdentityRepresentation> listsUserFederatedIdentities(String userId);

  FederatedIdentityRepresentation findFederatedIdentity(String userId, String idpId, String entityId);

  FederatedIdentityRepresentation addFederatedIdentity(FederatedIdentityRepresentation federatedIdentity);
}
