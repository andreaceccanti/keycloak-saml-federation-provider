package it.infn.cnaf.sd.kc.spi;

import java.util.stream.Stream;

import org.keycloak.provider.Provider;

public interface SAMLAggregateFederatedIdentityServiceProvider extends Provider {

  Stream<SamlAggregateFederatedIdentityDTO> list(String realmId, String userId);

  Stream<SamlAggregateFederatedIdentityDTO> find(String realmId, String userId,
      String idpId, String federatedUserId);

  Stream<SamlAggregateFederatedIdentityDTO> find(String realmId, String federatedUserId);

  void add(SamlAggregateFederatedIdentityDTO dto);

  void add(String realmId, String userId, String idpId, String federatedUserId,
      String entityId, String federatedUsername);

  void updateToken(String realmId, String userId, String idpId,
      String federatedUserId, String token);

  void updateToken(SamlAggregateFederatedIdentityDTO updateMe, String token);

  int remove(SamlAggregateFederatedIdentityDTO removeMe);

  int remove(String realmId, String userId, String idpId, String federatedUserId);

}
