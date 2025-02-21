package com.hardssh.provider;

import pro.javacard.ssh.SSHPublicKey;

import java.security.*;

// https://docs.oracle.com/en/java/javase/17/security/howtoimplaprovider.html
// https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html
public final class SSHProvider extends Provider {

    private static final long serialVersionUID = -7847432705599178241L;
    public static final String NAME = "SSHProvider";

    public SSHProvider() {
        super("SSHProvider", "1.0", "SSH Provider");
        putService(new Provider.Service(this, "KeyStore", "SSH", SSHKeyStoreSpi.class.getName(), null, null));
        putService(new Provider.Service(this, "KeyFactory", "SSH", SSHKeyFactorySpi.class.getName(), null, null));
        putService(new Provider.Service(this, "CertificateFactory", "SSH", SSHCertificateFactorySpi.class.getName(), null, null));

        for (var s : SSHSignatureSpi.nativeAlgos) {
            putService(new ProviderService(this, "Signature", s, SSHSignatureSpi.class.getName()));
        }
        for (var s : SSHSignatureSpi.sshAlgos) {
            putService(new ProviderService(this, "Signature", s, SSHSignatureSpi.class.getName()));
        }
        for (var s : SSHSignatureSpi.fidoAlgos) {
            putService(new ProviderService(this, "Signature", s, SSHSignatureSpi.class.getName()));
        }
        putService(new ProviderService(this, "Signature", "SSHSIG", SSHSIGSignatureSpi.class.getName()));
    }


    private static final class ProviderService extends Provider.Service {
        ProviderService(Provider p, String type, String algo, String cn) {
            super(p, type, algo, cn, null, null);
        }

        @Override
        public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
            String type = getType();
            String algo = getAlgorithm();
            try {
                if (type.equals("Signature")) {
                    if (algo.equals("SSHSIG")) {
                        return new SSHSIGSignatureSpi();
                    }
                    return new SSHSignatureSpi(algo);
                }
            } catch (Exception ex) {
                throw new NoSuchAlgorithmException("Error constructing " + type + " for " + algo + " using SSHProvider", ex);
            }
            throw new ProviderException("No impl for " + algo + " " + type);
        }
    }

    public record KeyPairEntry(PublicKey publicKey, SSHAgentPrivateKey privateKey) implements KeyStore.Entry {

        @Override
        public String toString() {
            return "[KeyPairEntry publicKey=%s privateKey=%s]".formatted(SSHPublicKey.fromJavaKey(publicKey), privateKey);
        }
    }
}
