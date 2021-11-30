package it.infn.cnaf.sd.kc.samlaggregate.authenticator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.ws.rs.core.UriBuilder;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.platform.engine.support.descriptor.AbstractTestDescriptor;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.AuthenticationManagementResource;
import org.keycloak.constants.ServiceUrlConstants;
import org.keycloak.protocol.oidc.utils.PkceUtils;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static io.restassured.RestAssured.given;

import dasniko.testcontainers.keycloak.KeycloakContainer;

@Testcontainers
public class SAMLAggregateAuthenticatorTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(SAMLAggregateAuthenticatorTest.class);

    private static final int KEYCLOAK_HTTP_PORT = 8080;

    private static final String KEYCLOAK_ADMIN_PASS = "admin";
    private static final String KEYCLOAK_ADMIN_USER = "admin";

    private static final String REALM_TEST = "sp";
    private static final String CLIENT_TEST_RESTRICTED = "test-client-restricted";
    private static final String CLIENT_TEST_RESTRICTED_BY_POLICY = "test-client-restricted-by-policy";
    private static final String CLIENT_SECRET_TEST_RESTRICTED_BY_POLICY = "42437f49-2b56-498e-a67c-13d4ee2d8cad";
    private static final String CLIENT_TEST_UNRESTRICTED = "test-client-unrestricted";
    private static final String USER_TEST_RESTRICTED = "test-restricted";
    private static final String PASS_TEST_RESTRICTED = "test";
    private static final String USER_TEST_UNRESTRICTED = "test-unrestricted";
    private static final String PASS_TEST_UNRESTRICTED = "test";

    private static String KEYCLOAK_AUTH_URL;

    @Container
    private static final KeycloakContainer KEYCLOAK_CONTAINER = new CustomKeycloakContainer("cnafsd/eosc-kc:latest")
            .withProviderClassesFrom("target/classes")
            .withAdminUsername(KEYCLOAK_ADMIN_USER)
            .withAdminPassword(KEYCLOAK_ADMIN_PASS)
            .withRealmImportFile("sp-realm-export.json")
            .withRealmImportFile("idp-realm.json")
            .withExposedPorts(KEYCLOAK_HTTP_PORT)
            .withLogConsumer(new Slf4jLogConsumer(LOGGER).withSeparateOutputStreams())
            .waitingFor(Wait.forHttp("/auth/")
                    .forStatusCode(200)
                    .withStartupTimeout(Duration.ofMinutes(1)));


    @BeforeAll
    static void setUp() {
        KEYCLOAK_AUTH_URL = KEYCLOAK_CONTAINER.getAuthServerUrl();
    }

    private UserRepresentation getUser(String username, String firstName, String lastName, String email, boolean emailVerified) {
      UserRepresentation u = new UserRepresentation();
      u.setId(UUID.randomUUID().toString());
      u.setUsername(username);
      u.setFirstName(firstName);
      u.setLastName(lastName);
      u.setEmail(email);
      u.setEmailVerified(emailVerified);
      return u;
    }

    private UserRepresentation createUser(Keycloak kc, String realmName, String username, String givenName, String familyName, String email, Boolean emailVerified) {
      UserRepresentation u = getUser(username, givenName, familyName, email, emailVerified);
      kc.realm(realmName).users().create(u);
      return u;
    }

    @Test
    void createUser() {

      Keycloak admin = Keycloak.getInstance(KEYCLOAK_AUTH_URL, "master", "admin", "admin", "admin-cli");
      createUser(admin, "sp", "vianello", "Enrico", "Vianello", "enrico.vianello@mail.example", true);
      LOGGER.info("users count = " + admin.realm("sp").users().count());
      assertEquals(1, admin.realm("sp").users().count());
    }

    @Test
    void testSamlAggregateAuthenticatorRedirection() {

      final String PKCE_METHOD = "S256";
      final String RESPONSE_TYPE = "code";
      final String SCOPE = "openid";

      Keycloak admin = Keycloak.getInstance(KEYCLOAK_AUTH_URL, "master", "admin", "admin", "admin-cli");
      AuthenticationManagementResource flows = admin.realm(REALM_TEST).flows();
      assertTrue(flows
          .getExecutions("b2").stream()
          .filter(it -> it.getProviderId().equalsIgnoreCase("saml-aggregate-authenticator"))
          .findFirst()
          .isPresent());
      createUser(admin, REALM_TEST, "vianello", "Enrico", "Vianello", "enrico.vianello@mail.example", true);

      String authServerUrl = KEYCLOAK_CONTAINER.getAuthServerUrl();

      String state = UUID.randomUUID().toString();
      String codeVerifier = PkceUtils.generateCodeVerifier();
      String codeChallenge = PkceUtils.encodeCodeChallenge(codeVerifier, PKCE_METHOD);
      String clientId = "account-console";
      String redirectUri = UriBuilder.fromUri(authServerUrl)
        .path(ServiceUrlConstants.ACCOUNT_SERVICE_PATH)
        .build(REALM_TEST)
        .toString();

      String loginUrl = String.format("%s/realms/%s/protocol/openid-connect/auth?%s=%s&%s=%s&%s=%s&%s=%s&%s=%s&%s=%s&%s=%s&%s=%s", authServerUrl, REALM_TEST, "samlaggregate", "edugain", OAuth2Constants.CLIENT_ID, clientId, OAuth2Constants.CODE_CHALLENGE, codeChallenge, OAuth2Constants.CODE_CHALLENGE_METHOD, PKCE_METHOD, OAuth2Constants.STATE, state, OAuth2Constants.SCOPE, SCOPE, OAuth2Constants.RESPONSE_TYPE, RESPONSE_TYPE, OAuth2Constants.REDIRECT_URI, redirectUri);

//      given().get(authServerUrl + "/realms/sp/protocol/openid-connect/auth").then().assertThat().statusCode(200);
      given().get(loginUrl).then().assertThat().statusCode(303);

    }

    /**
     * If no access provider is configured for the authenticator, and no server-wide default access provider is configured via
     * SPI configuration, then we fallback to 'client-role'.
     */
    @Nested
    class RestrictedClient {

        @ParameterizedTest
        @CsvSource(value = {"client-role", "null"}, nullValues = "null")
        void accessForUserWithoutRoleIsDenied(String accessProviderId) {
            SAMLAggregateAuthenticatorTest.this.switchAccessProvider(accessProviderId);
            Keycloak keycloak = keycloakTest(USER_TEST_RESTRICTED, PASS_TEST_RESTRICTED, CLIENT_TEST_RESTRICTED);
//            assertThatThrownBy(() -> keycloak.tokenManager().getAccessToken())
//                    .isInstanceOf(NotAuthorizedException.class);
        }

        @ParameterizedTest
        @CsvSource(value = {"client-role", "null"}, nullValues = "null")
        void accessForUserWithRoleIsAllowed(String accessProviderId) {
            SAMLAggregateAuthenticatorTest.this.switchAccessProvider(accessProviderId);
            Keycloak keycloak = keycloakTest(USER_TEST_UNRESTRICTED, PASS_TEST_UNRESTRICTED, CLIENT_TEST_RESTRICTED);
//            assertThat(keycloak.tokenManager().getAccessToken()).isNotNull();
        }
    }

    @Nested
    class RestrictedClientByPolicy {

        @BeforeEach
        void switchAccessProvider() {
            SAMLAggregateAuthenticatorTest.this.switchAccessProvider("policy");
        }

        @Test
        void accessForUserWithoutRoleIsDenied() {
            Keycloak keycloak = keycloakTest(USER_TEST_RESTRICTED, PASS_TEST_RESTRICTED, CLIENT_TEST_RESTRICTED_BY_POLICY, CLIENT_SECRET_TEST_RESTRICTED_BY_POLICY);
//            assertThatThrownBy(() -> keycloak.tokenManager().getAccessToken())
//                .isInstanceOf(NotAuthorizedException.class);
        }

        @Test
        void accessForUserWithRoleIsAllowed() {
            Keycloak keycloak = keycloakTest(USER_TEST_UNRESTRICTED, PASS_TEST_UNRESTRICTED, CLIENT_TEST_RESTRICTED_BY_POLICY, CLIENT_SECRET_TEST_RESTRICTED_BY_POLICY);
//            assertThat(keycloak.tokenManager().getAccessToken()).isNotNull();
        }
    }

    @Nested
    class UnrestrictedClient {

        @BeforeEach
        void switchAccessProvider() {
            SAMLAggregateAuthenticatorTest.this.switchAccessProvider(null);
        }

        @Test
        void accessForRestrictedUserIsAllowed() {
            Keycloak keycloak = keycloakTest(USER_TEST_RESTRICTED, PASS_TEST_RESTRICTED, CLIENT_TEST_UNRESTRICTED);
//            assertThat(keycloak.tokenManager().getAccessToken()).isNotNull();
        }

        @Test
        void accessForUnrestrictedUserIsAllowed() {
            Keycloak keycloak = keycloakTest(USER_TEST_UNRESTRICTED, PASS_TEST_UNRESTRICTED, CLIENT_TEST_UNRESTRICTED);
//            assertThat(keycloak.tokenManager().getAccessToken()).isNotNull();
        }
    }


    private void switchAccessProvider(String accessProviderId) {
        Keycloak admin = keycloakAdmin();
        AuthenticationManagementResource flows = admin.realm(REALM_TEST).flows();
        String authenticationConfigId = flows
            .getExecutions("direct-grant-restricted-client-auth").stream()
            .filter(it -> it.getProviderId().equalsIgnoreCase("restrict-client-auth-authenticator"))
            .findFirst()
            .get()
            .getAuthenticationConfig();
        AuthenticatorConfigRepresentation authenticatorConfig = flows.getAuthenticatorConfig(authenticationConfigId);
        Map<String, String> config = authenticatorConfig.getConfig();
        if (accessProviderId == null) {
            config.remove("accessProviderId");
        } else {
            config.put("accessProviderId", accessProviderId);
        }
        authenticatorConfig.setConfig(config);
        flows.updateAuthenticatorConfig(authenticationConfigId, authenticatorConfig);
    }

    private Keycloak keycloakAdmin() {
        return keycloak("master", "admin", "admin", "admin-cli", null);
    }

    private static Keycloak keycloakTest(String username, String password, String client) {
        return keycloakTest(username, password, client, null);
    }

    private static Keycloak keycloakTest(String username, String password, String client, String clientSecret) {
        return keycloak(REALM_TEST, username, password, client, clientSecret);
    }

    private static Keycloak keycloak(String realm, String username, String password, String client, String clientSecret) {
        return Keycloak.getInstance(KEYCLOAK_AUTH_URL, realm, username, password, client, clientSecret);
    }


}