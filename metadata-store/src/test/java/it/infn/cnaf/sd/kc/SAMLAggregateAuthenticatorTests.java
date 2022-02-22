package it.infn.cnaf.sd.kc;

import static io.restassured.RestAssured.given;
import static it.infn.cnaf.sd.kc.samlaggregate.authenticator.SAMLAggregateAuthenticator.SAML_AGGREGATE_AUTH_IDP;
import static it.infn.cnaf.sd.kc.samlaggregate.authenticator.SAMLAggregateAuthenticator.SAML_AGGREGATE_AUTH_PROVIDER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.keycloak.OAuth2Constants.CLIENT_ID;
import static org.keycloak.OAuth2Constants.CODE_CHALLENGE;
import static org.keycloak.OAuth2Constants.CODE_CHALLENGE_METHOD;
import static org.keycloak.OAuth2Constants.REDIRECT_URI;
import static org.keycloak.OAuth2Constants.RESPONSE_TYPE;
import static org.keycloak.OAuth2Constants.SCOPE;
import static org.keycloak.OAuth2Constants.STATE;

import java.util.Map;
import java.util.UUID;

import javax.ws.rs.core.UriBuilder;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.AuthenticationManagementResource;
import org.keycloak.constants.ServiceUrlConstants;
import org.keycloak.protocol.oidc.utils.PkceUtils;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableMap;

import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

public class SAMLAggregateAuthenticatorTests {

  private static final Logger LOGGER = LoggerFactory.getLogger(SAMLAggregateAuthenticatorTests.class);
      
  private static final String KC_IMAGE = "cnafsd/eosc-kc:latest";

  private static final String KEYCLOAK_ADMIN_PASS = "admin";
  private static final String KEYCLOAK_ADMIN_USER = "admin";

  private static final String REALM_TEST = "sp";
  private static final String SAML_AGGREGATE_IDP_ALIAS = "edugain";
  private static final String OAUTH_REQUEST_CLIENT_ID = "account-console";
  private static final String OAUTH_REQUEST_RESPONSE_TYPE = "code";
  private static final String OAUTH_REQUEST_SCOPE = "openid";
  private static final String OAUTH_REQUEST_PKCE_METHOD = "S256";

  private KeycloakDevContainer kc;

  @BeforeEach
  public void startKeycloakContainer() {
    kc = new KeycloakDevContainer(KC_IMAGE);

    kc.withFixedExposedPort(8081, 8080);
    kc.withFixedExposedPort(1044, 1044);
    kc.withClassFolderChangeTrackingEnabled(true);

    kc.withRealmImportFile("sp-realm-export.json");
    kc.withRealmImportFile("idp-realm.json");

    kc.start();
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

  private Response login(Map<String, String> queryParams) {

    String authServerUrl = kc.getAuthServerUrl();
    String state = UUID.randomUUID().toString();
    String codeVerifier = PkceUtils.generateCodeVerifier();
    String codeChallenge = PkceUtils.encodeCodeChallenge(codeVerifier, OAUTH_REQUEST_PKCE_METHOD);
    String loginUrl =
        String.format("%s/realms/%s/protocol/openid-connect/auth", authServerUrl, REALM_TEST);

    RequestSpecification rs = given().queryParam(STATE, state)
      .queryParam(SCOPE, OAUTH_REQUEST_SCOPE)
      .queryParam(RESPONSE_TYPE, OAUTH_REQUEST_RESPONSE_TYPE)
      .queryParam(CLIENT_ID, OAUTH_REQUEST_CLIENT_ID)
      .queryParam(CODE_CHALLENGE, codeChallenge)
      .queryParam(CODE_CHALLENGE_METHOD, OAUTH_REQUEST_PKCE_METHOD);
    queryParams.forEach((k, v) -> rs.queryParam(k, v));

    return rs.get(loginUrl).then().contentType(ContentType.HTML).extract().response();
  }

  @Test
  public void addUserTest() {

    Keycloak admin = Keycloak.getInstance(kc.getAuthServerUrl(), "master", KEYCLOAK_ADMIN_USER, KEYCLOAK_ADMIN_PASS, "admin-cli");
    createUser(admin, REALM_TEST, "vianello", "Enrico", "Vianello", "enrico.vianello@mail.example", true);
    LOGGER.info("users count = " + admin.realm("sp").users().count());
    assertEquals(1, admin.realm(REALM_TEST).users().count());
  }

  @Test
  public void redirectToWayfTest() {

    Keycloak admin = Keycloak.getInstance(kc.getAuthServerUrl(), "master", KEYCLOAK_ADMIN_USER, KEYCLOAK_ADMIN_PASS, "admin-cli");
    AuthenticationManagementResource flows = admin.realm(REALM_TEST).flows();
    assertTrue(flows
        .getExecutions("b2").stream()
        .filter(it -> it.getProviderId().equalsIgnoreCase("saml-aggregate-authenticator"))
        .findFirst()
        .isPresent());
    createUser(admin, REALM_TEST, "vianello", "Enrico", "Vianello", "enrico.vianello@mail.example", true);

    String redirectUri = UriBuilder.fromUri(kc.getAuthServerUrl())
        .path(ServiceUrlConstants.ACCOUNT_SERVICE_PATH)
        .build(REALM_TEST)
        .toString();

    Response response = login(new ImmutableMap.Builder<String, String>()
        .put(SAML_AGGREGATE_AUTH_PROVIDER, SAML_AGGREGATE_IDP_ALIAS)
        .put(REDIRECT_URI, redirectUri)
        .build());

    assertEquals(200, response.getStatusCode());
    assertTrue(response.asString().contains("edugain - Sign in with your IdP"));
  }

  @Test
  public void redirectToIdpLoginTest() {

    Keycloak admin = Keycloak.getInstance(kc.getAuthServerUrl(), "master", KEYCLOAK_ADMIN_USER, KEYCLOAK_ADMIN_PASS, "admin-cli");
    AuthenticationManagementResource flows = admin.realm(REALM_TEST).flows();
    assertTrue(flows
        .getExecutions("b2").stream()
        .filter(it -> it.getProviderId().equalsIgnoreCase("saml-aggregate-authenticator"))
        .findFirst()
        .isPresent());
    createUser(admin, REALM_TEST, "vianello", "Enrico", "Vianello", "enrico.vianello@mail.example", true);

    String redirectUri = UriBuilder.fromUri(kc.getAuthServerUrl())
        .path(ServiceUrlConstants.ACCOUNT_SERVICE_PATH)
        .build(REALM_TEST)
        .toString();

    Response response = login(new ImmutableMap.Builder<String, String>()
        .put(SAML_AGGREGATE_AUTH_PROVIDER, SAML_AGGREGATE_IDP_ALIAS)
        .put(SAML_AGGREGATE_AUTH_IDP, "http://dev.local.io:8081/auth/realms/idp")
        .put(REDIRECT_URI, redirectUri)
        .build());

    assertEquals(200, response.getStatusCode());
    assertTrue(response.asString().contains("Redirecting, please wait"));
    assertTrue(response.asString().contains("action=\"http://dev.local.io:8081/auth/realms/idp/protocol/saml\""));
  }

  @AfterEach
  public void stopKeycloakContainer() {
    kc.stop();
  }
}
