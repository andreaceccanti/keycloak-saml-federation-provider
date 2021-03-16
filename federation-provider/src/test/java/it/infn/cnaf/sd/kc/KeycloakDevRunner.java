package it.infn.cnaf.sd.kc;

import org.testcontainers.containers.output.BaseConsumer;
import org.testcontainers.containers.output.OutputFrame;

public class KeycloakDevRunner {

  public static final String KC_IMAGE = "cnafsd/kc-dev:latest";

  public static void main(String[] args) throws Exception {

    var kc = new KeycloakDevContainer(KC_IMAGE);

    kc.withFixedExposedPort(8080, 8080);
    kc.withFixedExposedPort(1044, 1044);
    kc.withClassFolderChangeTrackingEnabled(true);

    // kc.withRealmImportFile("test-realm.json");
    kc.start();

    class StdoutConsumer extends BaseConsumer<StdoutConsumer> {

      @Override
      public void accept(OutputFrame outputFrame) {
        System.out.print(outputFrame.getUtf8String());
      }
    }
    kc.followOutput(new StdoutConsumer().withRemoveAnsiCodes(true));

    System.out.println("Keycloak Running, you can now attach your remote debugger!");
    System.in.read();
    kc.close();
  }

}
