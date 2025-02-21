module com.hardssh.provider {
    provides java.security.Provider with com.hardssh.provider.SSHProvider;
    exports com.hardssh.provider;

    requires transitive pro.javacard.ssh;
    requires java.logging;
}