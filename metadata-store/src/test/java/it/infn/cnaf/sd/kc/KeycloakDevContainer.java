package it.infn.cnaf.sd.kc;


import static java.nio.file.StandardWatchEventKinds.ENTRY_CREATE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_DELETE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_MODIFY;
import static java.nio.file.StandardWatchEventKinds.OVERFLOW;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.SelinuxContext;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.shaded.com.google.common.cache.Cache;
import org.testcontainers.shaded.com.google.common.cache.CacheBuilder;
import org.testcontainers.utility.MountableFile;

import dasniko.testcontainers.keycloak.KeycloakContainer;

/**
 * Taken from here:
 * https://github.com/thomasdarimont/keycloak-tc-extension-playground/blob/master/src/test/java/demo/KeycloakDevContainer.java
 *
 */
public class KeycloakDevContainer extends KeycloakContainer {

  private boolean classFolderChangeTrackingEnabled;

  public KeycloakDevContainer(String image) {
    super(image);
  }

  public KeycloakContainer withFixedExposedPort(int hostPort, int containerPort) {
    super.addFixedExposedPort(hostPort, containerPort);
    return this.self();
  }

  @Override
  protected void configure() {
    super.configure();
    this.withExposedPorts(8080, 8443, 1044);
    this.withCommand("-c standalone.xml", "-b 0.0.0.0",
        "-Dkeycloak.profile.feature.upload_scripts=enabled",
        "--debug *:1044");

    String standaloneXmlLocation =
        MountableFile.forClasspathResource("standalone.xml").getResolvedPath();

    String standaloneXmlTargetLocation =
        "/opt/jboss/keycloak/standalone/configuration/standalone.xml";

    String moduleXmlLocation = MountableFile.forClasspathResource("module.xml").getResolvedPath();

    String moduleXmlTargetLocation =
        "/opt/jboss/keycloak/modules/it/infn/sd/keycloak-saml-metadata-store/main/module.xml";

    String mdStoreLocation =
        MountableFile.forClasspathResource(".").getResolvedPath() + "../classes";

    String mdStoreTargetLocation =
        "/opt/jboss/keycloak/modules/it/infn/sd/keycloak-saml-metadata-store/main/keycloak-saml-metadata-store.jar";

    String themeLocation =
        MountableFile.forClasspathResource(".").getResolvedPath() + "../../../theme/target/classes";

    String themeTargetLocation = "/opt/jboss/keycloak/standalone/deployments/eosc-kc-theme.jar";
    String themeDeploymentTrigger = themeTargetLocation + ".dodeploy";

    String deploymentTriggerFile = mdStoreTargetLocation + ".dodeploy";

    addFileSystemBind(mdStoreLocation, mdStoreTargetLocation, BindMode.READ_WRITE,
        SelinuxContext.SINGLE);

    addFileSystemBind(standaloneXmlLocation, standaloneXmlTargetLocation, BindMode.READ_ONLY,
        SelinuxContext.SINGLE);

    addFileSystemBind(moduleXmlLocation, moduleXmlTargetLocation, BindMode.READ_ONLY,
        SelinuxContext.SINGLE);

    addFileSystemBind(themeLocation, themeTargetLocation, BindMode.READ_ONLY,
        SelinuxContext.SINGLE);

    withClasspathResourceMapping("dodeploy", deploymentTriggerFile, BindMode.READ_ONLY);
    withClasspathResourceMapping("dodeploy", themeDeploymentTrigger, BindMode.READ_ONLY);

    if (isClassFolderChangeTrackingEnabled()) {
      registerClassFolderWatcher(Paths.get(mdStoreLocation).normalize(),
          Set.of(new File(deploymentTriggerFile).getName()), (watchEvent) -> {
            System.out.println(
                "Detected change... trigger redeployment. changed file: " + watchEvent.context());
            copyFileToContainer(Transferable.of("true".getBytes(StandardCharsets.UTF_8)),
                deploymentTriggerFile);
            System.out.println("Redeployment triggered");
          });
    }
  }

  private void registerClassFolderWatcher(Path classPath, Set<String> excludes,
      Consumer<WatchEvent<Path>> onChange) {

    Set<String> watchList = Collections.newSetFromMap(new ConcurrentHashMap<>());

    try {
      WatchService watcher = FileSystems.getDefault().newWatchService();

      Cache<String, Boolean> seen =
          CacheBuilder.newBuilder().expireAfterWrite(500, TimeUnit.MILLISECONDS).build();

      Executors.newSingleThreadExecutor().execute(() -> {
        for (;;) {
          try {
            registerFileWatcherRecursively(watchList, watcher, classPath);

            WatchKey key = watcher.take();

            for (WatchEvent<?> event : key.pollEvents()) {
              WatchEvent.Kind<?> kind = event.kind();

              if (kind == OVERFLOW) {
                continue;
              }

              @SuppressWarnings("unchecked")
              WatchEvent<Path> ev = (WatchEvent<Path>) event;
              Path contextPath = ev.context();

              String filename = contextPath.getName(0).toString();
              if (excludes.contains(filename)) {
                continue;
              }

              if (!filename.endsWith(".class")) {
                continue;
              }

              if (seen.getIfPresent(filename) != null) {
                continue;
              } else {
                seen.put(filename, Boolean.TRUE);
              }

              onChange.accept(ev);
              break;
            }

            boolean valid = key.reset();
            if (!valid) {
              System.out.println("Watch key no longer valid, exiting...");
              return;
            }
          } catch (Exception e) {
            e.printStackTrace();
          }
        }
      });
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  private void registerFileWatcherRecursively(Set<String> watchList, WatchService watcher,
      Path classesPath) throws IOException {

    Files.walkFileTree(classesPath, new SimpleFileVisitor<>() {
      @Override
      public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs)
          throws IOException {

        String absolutePath = dir.toFile().getAbsolutePath();
        if (watchList.contains(absolutePath)) {
          return FileVisitResult.CONTINUE;
        }

        dir.register(watcher, ENTRY_CREATE, ENTRY_DELETE, ENTRY_MODIFY);
        return FileVisitResult.CONTINUE;
      }
    });
  }

  public boolean isClassFolderChangeTrackingEnabled() {
    return classFolderChangeTrackingEnabled;
  }

  public KeycloakDevContainer withClassFolderChangeTrackingEnabled(
      boolean classFolderChangeTrackingEnabled) {
    this.classFolderChangeTrackingEnabled = classFolderChangeTrackingEnabled;
    return this;
  }
}
