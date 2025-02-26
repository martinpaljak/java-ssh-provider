package com.hardssh.provider;

import pro.javacard.ssh.SSHCertificate;
import pro.javacard.ssh.SSHIdentity;
import pro.javacard.ssh.SSHIdentityWithComment;
import pro.javacard.ssh.agent.Sockets;
import pro.javacard.ssh.agent.messages.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;

// KeyStore that redirects to the SSH agent
public final class SSHKeyStoreSpi extends KeyStoreSpi {

    private static final Logger log = Logger.getLogger(SSHKeyStoreSpi.class.getName());

    private Path socket;

    // Keep track of aliases to identities
    private final HashMap<String, KeyStore.Entry> entries = new HashMap<>();

    private KeyStore.Entry resolveAlias(String alias) {
        var a = entries.get(alias);
        if (a == null) {
            try {
                SSHIdentity identity = SSHIdentity.fromString(alias);
                return entries.get(identity.getFingerprint());
            } catch (Exception e) {
                return null;
            }
        }
        return a;
    }

    public SSHKeyStoreSpi() {

    }

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        return Optional.ofNullable(resolveAlias(alias))
                .map(e -> switch (e) {
                    case KeyStore.PrivateKeyEntry privateKeyEntry -> privateKeyEntry.getPrivateKey();
                    case SSHProvider.KeyPairEntry keyPairEntry -> keyPairEntry.privateKey();
                    default -> throw new IllegalStateException("Unexpected value: " + e);
                })
                .orElse(null);
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        var lookup = resolveAlias(alias);
        if (lookup == null) {
            return null;
        }
        return switch (lookup) {
            case KeyStore.PrivateKeyEntry privateKeyEntry -> privateKeyEntry.getCertificateChain();
            default -> null;
        };
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        var lookup = resolveAlias(alias);
        if (lookup == null) {
            return null;
        }
        return switch (lookup) {
            case KeyStore.PrivateKeyEntry privateKeyEntry -> privateKeyEntry.getCertificate();
            default -> null;
        };
    }


    @Override
    public boolean engineEntryInstanceOf(String alias, Class<? extends KeyStore.Entry> entryClass) {
        var lookup = resolveAlias(alias);

        if (lookup == null) {
            return false;
        }
        return entryClass.equals(lookup.getClass());
    }

    @Override
    public KeyStore.Entry engineGetEntry(String alias, KeyStore.ProtectionParameter protParam) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {
        return resolveAlias(alias);
    }

    @SuppressWarnings("JavaUtilDate")
    @Override
    public Date engineGetCreationDate(String alias) {
        var e = resolveAlias(alias);
        // Option 0: creation date of X509 certificate
        if (e instanceof KeyStore.PrivateKeyEntry privateKeyEntry
                && privateKeyEntry.getCertificate() instanceof X509Certificate x509) {
            return x509.getNotBefore();
        }
        // Option 1: return a dummy date
        return new Date();
        // Option 2: return null
        // return null;
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        throw new KeyStoreException("SSH agent keystore is read-only");
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        throw new KeyStoreException("SSH agent keystore is read-only");
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        // Store a new certificate in the agent with the extension
        throw new KeyStoreException("SSH agent keystore is currently read-only");
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        var i = resolveAlias(alias);
        if (i instanceof KeyStore.PrivateKeyEntry privateKeyEntry) {
            var key = privateKeyEntry.getPrivateKey();
            if (key instanceof SSHAgentPrivateKey sshAgentPrivateKey) {
                try {
                    var r = runCommand(socket, new RemoveIdentity(sshAgentPrivateKey.getIdentity()));
                    var code = AgentMessage.identify(r);
                    if (code != AgentMessage.SSH_AGENT_SUCCESS) {
                        throw new KeyStoreException("Could not remove signer: %s".formatted(AgentMessage.name(code)));
                    }
                } catch (IOException e) {
                    throw new KeyStoreException("Could not remove signer: %s".formatted(e.getMessage()));
                }
            }
        }
        throw new KeyStoreException("Can not delete entry: %s".formatted(alias));
    }

    @Override
    public Enumeration<String> engineAliases() {
        try {
            reload(); // TODO: flag if should re-enumerate
        } catch (CertificateException e) {
            // Now we have zero entries
            log.warning("Could not reload identities: " + e.getMessage());
        }

        return new Enumeration<>() {
            private final Iterator<String> i = entries.keySet().iterator();

            @Override
            public boolean hasMoreElements() {
                return i.hasNext();
            }

            @Override
            public String nextElement() {
                return i.next();
            }
        };
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        return resolveAlias(alias) != null;
    }

    @Override
    public int engineSize() {
        return entries.size();
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        var lookup = resolveAlias(alias);
        return lookup instanceof SSHProvider.KeyPairEntry;
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        var lookup = resolveAlias(alias);
        return lookup instanceof KeyStore.PrivateKeyEntry;
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        log.fine("Getting certificate alias: " + cert.getClass().getName());
        if (cert instanceof X509Certificate x509) {
            return entries.entrySet().stream()
                    .filter(e -> e.getValue() instanceof KeyStore.PrivateKeyEntry)
                    .filter(e -> {
                        var chain = ((KeyStore.PrivateKeyEntry) e.getValue()).getCertificateChain();
                        return Arrays.asList(chain).contains(x509);
                    })
                    .map(Map.Entry::getKey)
                    .findFirst()
                    .orElse(null);
        } else {
            return null;
        }
    }

    // Called when KeyStore.store() happens. We do nothing here.
    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        // NOTE: might silently ignore
        throw new UnsupportedOperationException("SSH agent keystore is read-only, in-memory");
    }

    private Set<SSHIdentityWithComment<? extends SSHIdentity>> fetchIdentities() {

        try {
            var reply = runCommand(socket, new RequestIdentities());
            var found = new LinkedHashSet<SSHIdentityWithComment<?>>();

            var type = AgentMessage.identify(reply);
            if (type == AgentMessage.SSH_AGENT_IDENTITIES_ANSWER) {
                var identitiesAnswer = IdentitiesAnswer.fromByteBuffer(reply);
                found.addAll(identitiesAnswer.getIdentities());
            } else {
                log.warning("Could not list identities: " + AgentMessage.name(type));
            }
            return Collections.unmodifiableSet(found);
        } catch (IOException e) {
            log.warning("Could not list identities: " + e.getMessage());
            return Collections.emptySet();
        }
    }

    static ByteBuffer runCommand(Path path, AgentMessage<?> command) throws IOException {
        try (SocketChannel channel = Sockets.connect(path)) {
            return Sockets.transceive(channel, AgentMessage.construct(command));
        }
    }

    // Called when KeyStore.load() happens. We do nothing here.
    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        if (stream != null) {
            throw new NoSuchAlgorithmException("InputStream must be null");
        }
        init();
        // unlock if password given.
        if (password != null && password.length > 0) {
            log.fine("Unlocking SSH agent ...");
            String pass = new String(password);
            var r = runCommand(socket, new LockUnlock(pass, false));
            var code = AgentMessage.identify(r);
            if (code != AgentMessage.SSH_AGENT_SUCCESS) {
                log.fine("Could not unlock SSH agent: " + AgentMessage.name(code));
                // NOTE: throw CertificateException("Could not unlock SSH agent: %s".formatted(AgentMessage.name(code)));
            }
        }
        // populate identities
        reload();
    }

    @Override
    public void engineLoad(KeyStore.LoadStoreParameter param) throws IOException, NoSuchAlgorithmException, CertificateException {
        if (param != null) {
            throw new NoSuchAlgorithmException("LoadStoreParameter must be null");
        }
        init();
        reload();
    }

    private void init() throws IOException {
        if (System.getenv(Sockets.SSH_AUTH_SOCK) == null) {
            throw new ProviderException("$%s not set".formatted(Sockets.SSH_AUTH_SOCK));
        }
        socket = Path.of(System.getenv(Sockets.SSH_AUTH_SOCK));

        // TODO: have a property to omit this.
        if (!Sockets.probe(socket)) {
            throw new IOException("%s does not accept connections".formatted(socket));
        }
    }

    private void reload() throws CertificateException {
        entries.clear();
        var all = fetchIdentities();

        // Extract all keys
        var keys = all.stream().filter(SSHIdentity::isKey).map(SSHIdentity::getKey).collect(Collectors.toSet());

        for (var container : all) {
            var identity = container.identity();
            var priv = new SSHAgentPrivateKey(identity.getKey(), socket);

            if (identity.isCert()) {
                if (keys.contains(identity.getKey())) {
                    var cert = SSHCertificate.of(identity);
                    var e = new KeyStore.PrivateKeyEntry(priv, new Certificate[]{cert});
                    entries.put(identity.getFingerprint(), e);
                }
            } else if (identity.isX509() && identity.asX509().isPresent()) {
                if (keys.contains(identity.getKey())) {
                    var e = new KeyStore.PrivateKeyEntry(priv, new Certificate[]{identity.asX509().get()});
                    entries.put(identity.getFingerprint(), e);
                }
            } else if (identity.isKey()) {
                // plain key, always present
                // NOTE: we can't use PrivateKeyEntry here, as it requires a certificate, which we don't have
                // NOTE2: trying to fake a DummyCertificate will make Java keytool barf with
                // java.lang.NullPointerException: Cannot invoke "java.security.cert.X509Certificate.getIssuerX500Principal()" because "last" is null
                // var e = new KeyStore.PrivateKeyEntry(priv, new Certificate[]{new DummyCertificate(signer.getKey())});

                // This is the only way to get the key back from the keystore
                // keytool will still complain
                // Alias name: ...
                // Creation date: null
                // Unknown Entry Type
                var e = new SSHProvider.KeyPairEntry(identity.getKey().getJavaKey(), priv);
                entries.put(identity.getFingerprint(), e);
            } else {
                throw new CertificateException("Unknown signer type: %s".formatted(identity));
            }
        }
    }

}
