package it.infn.cnaf.sd.kc.metadata;

import static com.google.common.base.Strings.isNullOrEmpty;
import static java.util.Collections.emptyList;
import static java.util.Objects.isNull;
import static java.util.stream.Collectors.toList;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.apache.commons.compress.utils.Lists;
import org.infinispan.Cache;
import org.infinispan.configuration.cache.ConfigurationBuilder;
import org.infinispan.configuration.global.GlobalConfigurationBuilder;
import org.infinispan.manager.DefaultCacheManager;
import org.infinispan.manager.EmbeddedCacheManager;
import org.jboss.logging.Logger;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.saml.common.exceptions.ParsingException;

import com.google.common.collect.Sets;

public class InMemorySAMLAggregateMetadataStoreProvider
    implements SAMLAggregateMetadataStoreProvider {

  public static final long MAX_IDP_RESULTS = 20;

  private static final Logger LOG =
      Logger.getLogger(InMemorySAMLAggregateMetadataStoreProvider.class);

  private final KeycloakSession session;

  private static final String CACHE_NAME = "metadataStore";
  private final EmbeddedCacheManager cacheManager;
  private final Cache<String, Map<String, SAMLIdpDescriptor>> metadataStore;

  private final Set<RegisteredProvider> registeredProviders = Sets.newHashSet();

  private final SAMLAggregateParser parser = new SAMLAggregateParser();

  public InMemorySAMLAggregateMetadataStoreProvider(KeycloakSession session) {
    this.session = session;

    GlobalConfigurationBuilder global = GlobalConfigurationBuilder.defaultClusteredBuilder();
    cacheManager = new DefaultCacheManager(global.build());
    ConfigurationBuilder builder = new ConfigurationBuilder().simpleCache(true);
    cacheManager.defineConfiguration(CACHE_NAME, builder.build());
    metadataStore = cacheManager.getCache(CACHE_NAME);
  }

  @Override
  public void close() {

  }

  private String providerKey(RealmModel realm, String providerAlias) {
    return String.format("%s/%s", realm.getName(), providerAlias);
  }

  protected InputStream fetchMetadata(String metadataUrl) {

    LOG.infov("Parsing metadata from URL: {0}", metadataUrl);

    try {
      return session.getProvider(HttpClientProvider.class).get(metadataUrl);
    } catch (IOException e) {
      final String errorMsg =
          String.format("Error parsing metadata from %s: %s", metadataUrl, e.getMessage());
      throw new SAMLMetadataParsingError(errorMsg, e);
    }
  }

  @Override
  public void parseMetadata(RealmModel realm, String providerAlias, String metadataUrl) {

    InputStream mdStream = fetchMetadata(metadataUrl);

    final String providerKey = providerKey(realm, providerAlias);

    try {
      Map<String, SAMLIdpDescriptor> mdMap = parser.parseMetadata(mdStream);

      LOG.infov("Parsed {0} entities from {1} for provider {2}", mdMap.keySet().size(), metadataUrl,
          providerKey);

      registeredProviders
        .add(RegisteredProvider.builder().providerKey(providerKey).metadataUrl(metadataUrl).build());

      metadataStore.put(metadataUrl, mdMap);

    } catch (ParsingException e) {

      final String errorMsg =
          String.format("Error parsing metadata from %s: %s", metadataUrl, e.getMessage());
      LOG.error(errorMsg, e);
      throw new SAMLMetadataParsingError(errorMsg, e);

    }
  }

  @Override
  public Optional<SAMLIdpDescriptor> lookupIdpByEntityId(RealmModel realm, String providerAlias,
      String entityId) {

    final String providerKey = providerKey(realm, providerAlias);

    RegisteredProvider provider = registeredProviders.stream()
      .filter(p -> p.getProviderKey().equals(providerKey(realm, providerAlias)))
      .findAny()
      .orElseThrow(() -> new RuntimeException("Unknown provider: " + providerKey));

    if (Objects.isNull(provider)) {
      return Optional.empty();
    }

    if (isNull(metadataStore.get(provider.getMetadataUrl()))) {
      throw new RuntimeException("No metadata found for provider: " + providerKey);
    }

    return Optional.ofNullable(metadataStore.get(provider.getMetadataUrl()).get(entityId));
  }

  @Override
  public List<SAMLIdpDescriptor> lookupEntities(RealmModel realm, String providerAlias,
      String matchString) {

    if (matchString.length() < 3) {
      return emptyList();
    }

    final String providerKey = providerKey(realm, providerAlias);

    RegisteredProvider provider = registeredProviders.stream()
      .filter(p -> p.getProviderKey().equals(providerKey(realm, providerAlias)))
      .findAny()
      .orElseThrow(() -> new RuntimeException("Unknown provider: " + providerKey));

    if (isNull(metadataStore.get(provider.getMetadataUrl()))) {
      throw new RuntimeException("No metadata found for provider: " + providerKey);
    }

    final String lowercaseMatchString = matchString.toLowerCase();

    List<SAMLIdpDescriptor> idpList = Lists.newArrayList();

    lookupIdpByEntityId(realm, providerAlias, matchString).ifPresent(idpList::add);

    if (!idpList.isEmpty()) {
      return idpList;
    }

    return metadataStore.get(provider.getMetadataUrl())
      .values()
      .stream()
      .filter(idp -> !isNullOrEmpty(idp.getDisplayName())
          && idp.getDisplayName().toLowerCase().contains(lowercaseMatchString))
      .limit(MAX_IDP_RESULTS)
      .collect(toList());
  }

  @Override
  public boolean cleanupMetadata(RealmModel realm, String providerAlias) {
    final String providerKey = providerKey(realm, providerAlias);

    RegisteredProvider provider = registeredProviders.stream()
      .filter(p -> p.getProviderKey().equals(providerKey))
      .findAny()
      .orElse(null);

    if (!isNull(provider)) {
      registeredProviders.remove(provider);
      if (!registeredProviders.stream()
        .anyMatch(p -> p.getMetadataUrl().equals(provider.getMetadataUrl()))) {
        metadataStore.remove(provider.getMetadataUrl());
      }
      return true;
    }

    return false;
  }

}
