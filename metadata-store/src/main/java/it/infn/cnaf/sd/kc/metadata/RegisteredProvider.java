package it.infn.cnaf.sd.kc.metadata;

public class RegisteredProvider {

  private final String providerKey;
  private final String metadataUrl;

  private RegisteredProvider(Builder b) {
    this.providerKey = b.providerKey;
    this.metadataUrl = b.metadataUrl;
  }

  public String getProviderKey() {
    return providerKey;
  }

  public String getMetadataUrl() {
    return metadataUrl;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((providerKey == null) ? 0 : providerKey.hashCode());
    result = prime * result + ((metadataUrl == null) ? 0 : metadataUrl.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    RegisteredProvider other = (RegisteredProvider) obj;
    if (providerKey == null) {
      if (other.providerKey != null)
        return false;
    } else if (!providerKey.equals(other.providerKey))
      return false;
    if (metadataUrl == null) {
      if (other.metadataUrl != null)
        return false;
    } else if (!metadataUrl.equals(other.metadataUrl))
      return false;
    return true;
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private String providerKey;
    private String metadataUrl;

    public Builder() {}

    public Builder providerKey(String key) {
      this.providerKey = key;
      return this;
    }

    public Builder metadataUrl(String url) {
      this.metadataUrl = url;
      return this;
    }

    public RegisteredProvider build() {
      return new RegisteredProvider(this);
    }
  }
}
