package it.infn.cnaf.sd.kc.metadata;

import java.util.List;
import java.util.Optional;

import org.keycloak.models.RealmModel;
import org.keycloak.provider.Provider;

public interface SAMLAggregateMetadataStoreProvider extends Provider {

  void parseMetadata(RealmModel realm, String providerAlias, String metadataUrl);

  boolean cleanupMetadata(RealmModel realm, String providerAlias);

  Optional<SAMLIdpDescriptor> lookupIdpByEntityId(RealmModel realm, String providerAlias,
      String entityId);

  List<SAMLIdpDescriptor> lookupEntities(RealmModel realm, String providerAlias, String query);
}
