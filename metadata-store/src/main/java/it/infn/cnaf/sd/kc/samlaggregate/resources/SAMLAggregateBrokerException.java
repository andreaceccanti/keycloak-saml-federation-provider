package it.infn.cnaf.sd.kc.samlaggregate.resources;

public class SAMLAggregateBrokerException extends Exception {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  public SAMLAggregateBrokerException(String message) {
    super(message);
  }

  public SAMLAggregateBrokerException(String message, Throwable e) {
    super(message, e);
  }

}
