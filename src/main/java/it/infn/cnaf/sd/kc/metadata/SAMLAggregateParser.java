package it.infn.cnaf.sd.kc.metadata;

import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.keycloak.dom.saml.v2.metadata.EntitiesDescriptorType;
import org.keycloak.dom.saml.v2.metadata.EntityDescriptorType;
import org.keycloak.dom.saml.v2.metadata.IDPSSODescriptorType;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.processing.core.parsers.saml.SAMLParser;

import com.google.common.collect.Maps;

public class SAMLAggregateParser {


  private Optional<IDPSSODescriptorType> findIdpDescriptor(EntityDescriptorType entityType) {
    for (EntityDescriptorType.EDTChoiceType edtChoiceType : entityType.getChoiceType()) {
      List<EntityDescriptorType.EDTDescriptorChoiceType> descriptors =
          edtChoiceType.getDescriptors();

      if (!descriptors.isEmpty() && descriptors.get(0).getIdpDescriptor() != null) {
        return Optional.of(descriptors.get(0).getIdpDescriptor());
      }
    }

    return Optional.empty();
  }

  private Optional<SAMLIdpDescriptor> parseIdp(EntityDescriptorType entityType) {

    List<EntityDescriptorType.EDTChoiceType> choiceType = entityType.getChoiceType();

    if (choiceType.isEmpty()) {
      return Optional.empty();
    }

    return findIdpDescriptor(entityType)
      .map(d -> SAMLIdpDescriptor.buildFor(entityType.getEntityID(), d));
  }


  public Map<String, SAMLIdpDescriptor> parseMetadata(InputStream mdStream)
      throws ParsingException {

    Object mdRoot = SAMLParser.getInstance().parse(mdStream);
    Map<String, SAMLIdpDescriptor> newMedadataMap = Maps.newHashMap();

    if (mdRoot instanceof EntityDescriptorType) {

      parseIdp((EntityDescriptorType) mdRoot)
        .ifPresent(i -> newMedadataMap.put(i.getEntityId(), i));

      return newMedadataMap;

    } else if (mdRoot instanceof EntitiesDescriptorType) {

      EntitiesDescriptorType root = (EntitiesDescriptorType) mdRoot;

      root.getEntityDescriptor()
        .stream()
        .map(EntityDescriptorType.class::cast)
        .map(this::parseIdp)
        .forEach(idp -> {
          idp.ifPresent(i -> {
            newMedadataMap.put(i.getEntityId(), i);
          });
        });

      return newMedadataMap;

    } else {
      throw new ParsingException(
          "Unrecognized SAML metadata object: " + mdRoot.getClass().getName());
    }
  }
}
