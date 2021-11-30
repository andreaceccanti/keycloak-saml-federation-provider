package it.infn.cnaf.sd.kc.samlaggregate.authenticator;

import java.util.HashMap;
import java.util.Map;

import org.jboss.logging.Logger;
import org.junit.Assert;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.keycloak.TokenVerifier;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.common.VerificationException;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;

import dasniko.testcontainers.keycloak.KeycloakContainer;

import static org.assertj.core.api.Assertions.assertThat;


public class BasicTest {

  protected Logger log = Logger.getLogger(this.getClass());

  public static final String KEYCLOAK_IMAGE = "cnafsd/eosc-kc:latest";
  
  public static final String MASTER_REALM = "master";

  public static final String ADMIN_CLI = "admin-cli";

  @Test
  public void example() throws Exception {

    try (KeycloakContainer keycloak = new KeycloakContainer(KEYCLOAK_IMAGE)
      .withRealmImportFile("sp-realm-export.json")
      .withExtensionClassesFrom("target/classes")) {
      keycloak.start();

      Keycloak keycloakClient = Keycloak.getInstance(keycloak.getAuthServerUrl(), MASTER_REALM,
          keycloak.getAdminUsername(), keycloak.getAdminPassword(), ADMIN_CLI);

      RealmResource realm = keycloakClient.realm(MASTER_REALM);
      ClientRepresentation client = realm.clients().findByClientId(ADMIN_CLI).get(0);

      configureCustomOidcProtocolMapper(realm, client);

      keycloakClient.tokenManager().refreshToken();
      AccessTokenResponse tokenResponse = keycloakClient.tokenManager().getAccessToken();

      // parse the received access-token
      TokenVerifier<AccessToken> verifier =
          TokenVerifier.create(tokenResponse.getToken(), AccessToken.class);
      verifier.parse();

      // check for the custom claim
      AccessToken accessToken = verifier.getToken();
      String customClaimValue = "TEST";
      assertThat(customClaimValue).isNotNull();
      assertThat(customClaimValue).startsWith("testdata:");
    }
  }

  /**
   * Configures the {@link SimpleOidcMapper} to the given client in the given realm.
   */
  private static void configureCustomOidcProtocolMapper(RealmResource realm,
      ClientRepresentation client) {

    ProtocolMapperRepresentation mapper = new ProtocolMapperRepresentation();
    mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
    mapper.setProtocolMapper("PROVIDER_ID");
    mapper.setName("test-simple-oidc-mapper");

    Map<String, String> config = new HashMap<>();
    config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true");
    mapper.setConfig(config);

    realm.clients().get(client.getId()).getProtocolMappers().createMapper(mapper).close();
  }

}
