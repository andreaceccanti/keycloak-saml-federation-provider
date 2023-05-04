package it.infn.cnaf.sd.kc.idp.binding;

import static java.util.Objects.isNull;

import java.net.URI;
import java.security.Key;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import javax.xml.namespace.QName;

import org.apache.commons.lang.NotImplementedException;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.common.VerificationException;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.assertion.AuthnStatementType;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.assertion.SubjectType;
import org.keycloak.dom.saml.v2.protocol.LogoutRequestType;
import org.keycloak.dom.saml.v2.protocol.RequestAbstractType;
import org.keycloak.dom.saml.v2.protocol.ResponseType;
import org.keycloak.dom.saml.v2.protocol.StatusResponseType;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.saml.SamlPrincipalType;
import org.keycloak.rotation.HardcodedKeyLocator;
import org.keycloak.rotation.KeyLocator;
import org.keycloak.saml.common.constants.GeneralConstants;
import org.keycloak.saml.common.constants.JBossSAMLConstants;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.processing.core.saml.v2.common.SAMLDocumentHolder;
import org.keycloak.saml.processing.core.saml.v2.constants.X500SAMLProfileConstants;
import org.keycloak.saml.processing.core.saml.v2.util.AssertionUtil;
import org.keycloak.saml.processing.core.util.XMLSignatureUtil;
import org.keycloak.saml.validators.ConditionsValidator;
import org.keycloak.saml.validators.DestinationValidator;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;
import org.w3c.dom.Element;

import it.infn.cnaf.sd.kc.idp.SAMLAggregateEndpoint;
import it.infn.cnaf.sd.kc.idp.SAMLAggregateIdentityProviderConfig;
import it.infn.cnaf.sd.kc.metadata.SAMLIdpDescriptor;

public abstract class AbstractSAMLBinding implements SAMLBinding {

  public static final String SAML_LOGIN_RESPONSE = "SAML_LOGIN_RESPONSE";
  public static final String SAML_ASSERTION = "SAML_ASSERTION";
  public static final String SAML_IDP_INITIATED_CLIENT_ID = "SAML_IDP_INITIATED_CLIENT_ID";
  public static final String SAML_AUTHN_STATEMENT = "SAML_AUTHN_STATEMENT";
  public static final String SAML_FEDERATED_SESSION_INDEX = "SAML_FEDERATED_SESSION_INDEX";

  static final Logger LOG = Logger.getLogger(AbstractSAMLBinding.class);

  final SAMLAggregateEndpoint endpoint;

  public AbstractSAMLBinding(SAMLAggregateEndpoint endpoint) {
    this.endpoint = endpoint;
  }

  protected boolean isSuccessfulSamlResponse(ResponseType responseType) {
    return responseType != null && responseType.getStatus() != null
        && responseType.getStatus().getStatusCode() != null
        && responseType.getStatus().getStatusCode().getValue() != null
        && Objects.equals(responseType.getStatus().getStatusCode().getValue().toString(),
            JBossSAMLURIConstants.STATUS_SUCCESS.get());
  }


  protected String getEntityId(UriInfo uriInfo, RealmModel realm) {
    String configEntityId = endpoint.getConfig().getSpEntityId();

    if (configEntityId == null || configEntityId.isEmpty())
      return UriBuilder.fromUri(uriInfo.getBaseUri())
        .path("realms")
        .path(realm.getName())
        .build()
        .toString();
    else
      return configEntityId;
  }

  protected NameIDType getSubjectNameID(final AssertionType assertion) {
    SubjectType subject = assertion.getSubject();
    SubjectType.STSubType subType = subject.getSubType();
    return subType != null ? (NameIDType) subType.getBaseID() : null;
  }

  protected String getX500Attribute(AssertionType assertion, X500SAMLProfileConstants attribute) {
    return getFirstMatchingAttribute(assertion, attribute::correspondsTo);
  }

  protected String getAttributeByName(AssertionType assertion, String name) {
    return getFirstMatchingAttribute(assertion,
        attribute -> Objects.equals(attribute.getName(), name));
  }

  protected String getAttributeByFriendlyName(AssertionType assertion, String friendlyName) {
    return getFirstMatchingAttribute(assertion,
        attribute -> Objects.equals(attribute.getFriendlyName(), friendlyName));
  }

  protected String getFirstMatchingAttribute(AssertionType assertion,
      Predicate<AttributeType> predicate) {
    return assertion.getAttributeStatements()
      .stream()
      .map(AttributeStatementType::getAttributes)
      .flatMap(Collection::stream)
      .map(AttributeStatementType.ASTChoiceType::getAttribute)
      .filter(predicate)
      .map(AttributeType::getAttributeValue)
      .flatMap(Collection::stream)
      .findFirst()
      .map(Object::toString)
      .orElse(null);
  }

  protected String expectedPrincipalType() {
    SamlPrincipalType principalType = endpoint.getConfig().getPrincipalType();
    switch (principalType) {
      case SUBJECT:
        return principalType.name();
      case ATTRIBUTE:
      case FRIENDLY_ATTRIBUTE:
        return String.format("%s(%s)", principalType.name(),
            endpoint.getConfig().getPrincipalAttribute());
      default:
        return null;
    }
  }

  private String getPrincipal(AssertionType assertion) {

    SamlPrincipalType principalType = endpoint.getConfig().getPrincipalType();

    if (principalType == null || principalType.equals(SamlPrincipalType.SUBJECT)) {
      NameIDType subjectNameID = getSubjectNameID(assertion);
      return subjectNameID != null ? subjectNameID.getValue() : null;
    } else if (principalType.equals(SamlPrincipalType.ATTRIBUTE)) {
      return getAttributeByName(assertion, endpoint.getConfig().getPrincipalAttribute());
    } else {
      return getAttributeByFriendlyName(assertion, endpoint.getConfig().getPrincipalAttribute());
    }

  }

  @Override
  public boolean checkSsl() {
    if (endpoint.getSession().getContext().getUri().getBaseUri().getScheme().equals("https")) {
      return true;
    } else {
      return !endpoint.getRealm().getSslRequired().isRequired(endpoint.getClientConnection());
    }
  }

  @Override
  public Optional<Response> basicSanityChecks(String samlRequest, String samlResponse) {

    EventBuilder event = endpoint.getEvent();
    KeycloakSession session = endpoint.getSession();

    if (!checkSsl()) {
      event.event(EventType.LOGIN);
      event.error(Errors.SSL_REQUIRED);
      return Optional.of(ErrorPage.error(endpoint.getSession(), null, Response.Status.BAD_REQUEST,
          Messages.HTTPS_REQUIRED));
    }

    if (!endpoint.getRealm().isEnabled()) {
      event.event(EventType.LOGIN_ERROR);
      event.error(Errors.REALM_DISABLED);
      return Optional.of(
          ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.REALM_NOT_ENABLED));
    }

    if (samlRequest == null && samlResponse == null) {
      event.event(EventType.LOGIN);
      event.error(Errors.INVALID_REQUEST);
      return Optional
        .of(ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST));

    }

    return Optional.empty();
  }

  @Override
  public KeyLocator getIDPKeyLocator() {
    List<Key> keys = new LinkedList<>();

    X509Certificate cert = null;

    // FIXME: handle multiple signing certificates for IdPs
    try {
      cert = XMLSignatureUtil.getX509CertificateFromKeyInfoString(
          endpoint.getIdpDescriptor().getSigningCertificate().replaceAll("\\s", ""));
      cert.checkValidity();
      keys.add(cert.getPublicKey());
    } catch (CertificateException e) {
      LOG.warnf("Ignoring invalid certificate: %s", cert);
    } catch (ProcessingException e) {
      throw new RuntimeException(e);
    }

    return new HardcodedKeyLocator(keys);
  }

  @Override
  public Response execute(String samlRequest, String samlResponse, String relayState,
      String clientId) {
    endpoint.buildEventBuilder();
    Optional<Response> r = basicSanityChecks(samlRequest, samlResponse);
    if (r.isPresent()) {
      return r.get();
    }
    if (!isNull(samlRequest)) {
      return handleSamlRequest(samlRequest, relayState);
    } else {
      return handleSamlResponse(samlResponse, relayState, clientId);
    }
  }

  @Override
  public Response handleSamlRequest(String samlRequest, String relayState) {
    SAMLDocumentHolder holder = extractRequestDocument(samlRequest);
    RequestAbstractType requestAbstractType = (RequestAbstractType) holder.getSamlObject();
    EventBuilder event = endpoint.getEvent();
    KeycloakSession session = endpoint.getSession();
    DestinationValidator destinationValidator = endpoint.getDestinationValidator();

    // validate destination
    if (requestAbstractType.getDestination() == null && containsUnencryptedSignature(holder)) {
      event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
      event.detail(Details.REASON, "missing_required_destination");
      event.error(Errors.INVALID_REQUEST);
      return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
    }

    if (!destinationValidator.validate(session.getContext().getUri().getAbsolutePath(),
        requestAbstractType.getDestination())) {
      event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
      event.detail(Details.REASON, "invalid_destination");
      event.error(Errors.INVALID_SAML_RESPONSE);
      return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
    }

    // Make signature verification conditional depending on configuration
    try {
      verifySignature(GeneralConstants.SAML_REQUEST_KEY, holder);
    } catch (VerificationException e) {
      LOG.error("SAML signature verification failed", e);
      event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
      event.error(Errors.INVALID_SIGNATURE);
      return ErrorPage.error(session, null, Response.Status.BAD_REQUEST,
          Messages.INVALID_REQUESTER);
    }

    if (requestAbstractType instanceof LogoutRequestType) {
      event.event(EventType.LOGOUT);
      LogoutRequestType logout = (LogoutRequestType) requestAbstractType;
      return logoutRequest(logout, relayState);

    } else {
      event.event(EventType.LOGIN);
      event.error(Errors.INVALID_TOKEN);
      return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
    }
  }

  @Override
  public Response logoutRequest(LogoutRequestType request, String relayState) {
    throw new NotImplementedException();
  }

  @Override
  public Response handleSamlResponse(String samlResponse, String relayState, String clientId) {

    EventBuilder event = endpoint.getEvent();
    KeycloakSession session = endpoint.getSession();
    SAMLAggregateIdentityProviderConfig config = endpoint.getConfig();

    SAMLDocumentHolder holder = extractResponseDocument(samlResponse);
    if (holder == null) {
      event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
      event.detail(Details.REASON, "invalid_saml_document");
      event.error(Errors.INVALID_SAML_RESPONSE);
      return ErrorPage.error(session, null, Response.Status.BAD_REQUEST,
          Messages.INVALID_FEDERATED_IDENTITY_ACTION);
    }

    StatusResponseType statusResponse = (StatusResponseType) holder.getSamlObject();
    if (statusResponse.getDestination() == null && containsUnencryptedSignature(holder)) {
      event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
      event.detail(Details.REASON, "missing_required_destination");
      event.error(Errors.INVALID_SAML_LOGOUT_RESPONSE);
      return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
    }

    if (!endpoint.getDestinationValidator()
      .validate(session.getContext().getUri().getAbsolutePath(), statusResponse.getDestination())) {
      event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
      event.detail(Details.REASON, "invalid_destination");
      event.error(Errors.INVALID_SAML_RESPONSE);
      return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
    }

    if (config.isValidateSignature()) {
      try {
        verifySignature(GeneralConstants.SAML_RESPONSE_KEY, holder);
      } catch (VerificationException e) {
        LOG.error("Signature validation failed", e);
        event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
        event.error(Errors.INVALID_SIGNATURE);
        return ErrorPage.error(session, null, Response.Status.BAD_REQUEST,
            Messages.INVALID_FEDERATED_IDENTITY_ACTION);
      }
    }

    if (statusResponse instanceof ResponseType) {
      return handleLoginResponse(samlResponse, holder, (ResponseType) statusResponse, relayState,
          clientId);
    } else {
      // todo need to check that it is actually a LogoutResponse
      return handleLogoutResponse(holder, statusResponse, relayState);
    }
  }

  @Override
  public Response handleLoginResponse(String samlResponse, SAMLDocumentHolder holder,
      ResponseType responseType, String relayState, String clientId) {

    EventBuilder event = endpoint.getEvent();
    KeycloakSession session = endpoint.getSession();
    RealmModel realm = endpoint.getRealm();

    SAMLAggregateIdentityProviderConfig config = endpoint.getConfig();

    KeyManager.ActiveRsaKey keys =
        endpoint.getSession().keys().getActiveRsaKey(endpoint.getRealm());

    SAMLIdpDescriptor descriptor = endpoint.getIdpDescriptor();

    if (!isSuccessfulSamlResponse(responseType)) {
      String statusMessage =
          responseType.getStatus() == null ? Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR
              : responseType.getStatus().getStatusMessage();
      return endpoint.getCallback().error(statusMessage);
    }

    if (responseType.getAssertions() == null || responseType.getAssertions().isEmpty()) {
      return endpoint.getCallback().error(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
    }

    try {
      boolean assertionIsEncrypted = AssertionUtil.isAssertionEncrypted(responseType);
      if (config.isWantAssertionsEncrypted() && !assertionIsEncrypted) {
        LOG.error(
            "Received assertion is not encrypted, which is required for this SAML aggregate IdP");
        event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
        event.error(Errors.INVALID_SAML_RESPONSE);
        return ErrorPage.error(session, null, Response.Status.BAD_REQUEST,
            Messages.INVALID_REQUESTER);
      }

      Element assertionElement;

      if (assertionIsEncrypted) {
        // This methods writes the parsed and decrypted assertion back on the responseType
        // parameter:
        assertionElement =
            AssertionUtil.decryptAssertion(responseType, keys.getPrivateKey());
      } else {
        /*
         * We verify the assertion using original document to handle cases where the IdP includes
         * whitespace and/or newlines inside tags.
         */
        assertionElement = DocumentUtil.getElement(holder.getSamlDocument(),
            new QName(JBossSAMLConstants.ASSERTION.get()));
      }

      boolean signed = AssertionUtil.isSignedElement(assertionElement);
      final boolean assertionSignatureNotExistsWhenRequired =
          config.isWantAssertionsSigned() && !signed;
      final boolean signatureNotValid = signed && config.isValidateSignature()
          && !AssertionUtil.isSignatureValid(assertionElement, getIDPKeyLocator());
      final boolean hasNoSignatureWhenRequired =
          !signed && config.isValidateSignature() && !containsUnencryptedSignature(holder);

      if (assertionSignatureNotExistsWhenRequired || signatureNotValid
          || hasNoSignatureWhenRequired) {
        LOG.error("Assertion signature validation failed");
        event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
        event.error(Errors.INVALID_SIGNATURE);
        return ErrorPage.error(session, null, Response.Status.BAD_REQUEST,
            Messages.INVALID_REQUESTER);
      }
      AssertionType assertion = responseType.getAssertions().get(0).getAssertion();
      NameIDType subjectNameID = getSubjectNameID(assertion);
      String principal = getPrincipal(assertion);

      if (principal == null) {
        LOG.errorf("no principal in assertion; expected: %s", expectedPrincipalType());
        event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
        event.error(Errors.INVALID_SAML_RESPONSE);
        return ErrorPage.error(session, null, Response.Status.BAD_REQUEST,
            Messages.INVALID_REQUESTER);
      }

      BrokeredIdentityContext identity = new BrokeredIdentityContext(principal);
      identity.getContextData().put(SAML_LOGIN_RESPONSE, responseType);
      identity.getContextData().put(SAML_ASSERTION, assertion);

      if (clientId != null && !clientId.trim().isEmpty()) {
        identity.getContextData().put(SAML_IDP_INITIATED_CLIENT_ID, clientId);
      }

      identity.setUsername(principal);


      // SAML Spec 2.2.2 Format is optional
      if (subjectNameID != null && subjectNameID.getFormat() != null
          && subjectNameID.getFormat()
            .toString()
            .equals(JBossSAMLURIConstants.NAMEID_FORMAT_EMAIL.get())) {
        identity.setEmail(subjectNameID.getValue());
      }

      if (config.isStoreToken()) {
        identity.setToken(samlResponse);
      }

      ConditionsValidator.Builder cvb = new ConditionsValidator.Builder(assertion.getID(),
          assertion.getConditions(), endpoint.getDestinationValidator())
            .clockSkewInMillis(1000 * config.getAllowedClockSkew());


      try {
        String issuerURL = getEntityId(session.getContext().getUri(), realm);
        cvb.addAllowedAudience(URI.create(issuerURL));
        // getDestination has been validated to match request URL already so it matches SAML
        // endpoint
        if (responseType.getDestination() != null) {
          cvb.addAllowedAudience(URI.create(responseType.getDestination()));
        }
      } catch (IllegalArgumentException ex) {
        // warning has been already emitted in DeploymentBuilder
      }

      if (!cvb.build().isValid()) {
        LOG.error("Assertion expired.");
        event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
        event.error(Errors.INVALID_SAML_RESPONSE);
        return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.EXPIRED_CODE);
      }

      AuthnStatementType authn = null;
      for (Object statement : assertion.getStatements()) {
        if (statement instanceof AuthnStatementType) {
          authn = (AuthnStatementType) statement;
          identity.getContextData().put(SAML_AUTHN_STATEMENT, authn);
          break;
        }
      }

      if (assertion.getAttributeStatements() != null) {
        String email = getX500Attribute(assertion, X500SAMLProfileConstants.EMAIL);
        if (email != null)
          identity.setEmail(email);
      }

      String brokerUserId = config.getAlias() + "." + principal;

      identity.setBrokerUserId(brokerUserId);
      identity.setIdpConfig(config);
      identity.setIdp(endpoint.getProvider());

      if (authn != null && authn.getSessionIndex() != null) {
        identity.setBrokerSessionId(identity.getBrokerUserId() + "." + authn.getSessionIndex());
      }

      //identity.setCode(relayState);

      return endpoint.getCallback().authenticated(identity);
    } catch (WebApplicationException e) {
      return e.getResponse();
    } catch (Exception e) {
      throw new IdentityBrokerException("Could not process response from SAML identity provider.",
          e);
    }
  }

  @Override
  public Response handleLogoutResponse(SAMLDocumentHolder holder, StatusResponseType responseType,
      String relayState) {

    throw new NotImplementedException();

  }
}
