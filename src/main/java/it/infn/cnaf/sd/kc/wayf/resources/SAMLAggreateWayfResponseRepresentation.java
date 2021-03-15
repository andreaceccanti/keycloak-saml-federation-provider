package it.infn.cnaf.sd.kc.wayf.resources;

import java.util.List;

public class SAMLAggreateWayfResponseRepresentation {

  String realm;
  String provider;
  String query;

  List<SAMLAggregateIdpRepresentation> results;

  public SAMLAggreateWayfResponseRepresentation() {
    // TODO Auto-generated constructor stub
  }

  public String getRealm() {
    return realm;
  }

  public void setRealm(String realm) {
    this.realm = realm;
  }

  public String getProvider() {
    return provider;
  }

  public void setProvider(String provider) {
    this.provider = provider;
  }

  public String getQuery() {
    return query;
  }

  public void setQuery(String query) {
    this.query = query;
  }

  public List<SAMLAggregateIdpRepresentation> getResults() {
    return results;
  }

  public void setResults(List<SAMLAggregateIdpRepresentation> results) {
    this.results = results;
  }
}
