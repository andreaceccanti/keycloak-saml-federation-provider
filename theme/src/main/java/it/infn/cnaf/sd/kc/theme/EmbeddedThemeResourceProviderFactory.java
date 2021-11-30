package it.infn.cnaf.sd.kc.theme;

import org.keycloak.theme.ClasspathThemeResourceProviderFactory;

public class EmbeddedThemeResourceProviderFactory extends ClasspathThemeResourceProviderFactory {

  public EmbeddedThemeResourceProviderFactory() {
    super("embedded-resources", EmbeddedThemeResourceProviderFactory.class.getClassLoader());
  }
}
