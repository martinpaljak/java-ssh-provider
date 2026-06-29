// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh;

import pro.javacard.ssh.utils.SSHSerializable;

import java.security.Key;
import java.security.interfaces.ECKey;
import java.security.interfaces.EdECKey;
import java.security.interfaces.RSAKey;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

// Utility class for various key and certificate type mappings and lookups
@SuppressWarnings("ImmutableEnumChecker")
public enum KeyConf {
    SECP256R1("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256-cert-v01@openssh.com", SSHPublicKey.SSHECPublicKey.PARSER, "secp256r1", "nistp256", 32),
    SECP384R1("ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384-cert-v01@openssh.com", SSHPublicKey.SSHECPublicKey.PARSER, "secp384r1", "nistp384", 48),
    SECP521R1("ecdsa-sha2-nistp521", "ecdsa-sha2-nistp521-cert-v01@openssh.com", SSHPublicKey.SSHECPublicKey.PARSER, "secp521r1", "nistp521", 66),
    ED25519("ssh-ed25519", "ssh-ed25519-cert-v01@openssh.com", SSHPublicKey.SSHEdECPublicKey.PARSER, null, null, -1),
    RSA("ssh-rsa", "ssh-rsa-cert-v01@openssh.com", SSHPublicKey.SSHRSAPublicKey.PARSER, null, null, -1),
    FIDO_SECP256R1("sk-ecdsa-sha2-nistp256@openssh.com", "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com", SSHPublicKey.SSHFIDOPublicKey.parser(SSHPublicKey.SSHECPublicKey.PARSER), "secp256r1", "nistp256", -1),
    FIDO_ED25519("sk-ssh-ed25519@openssh.com", "sk-ssh-ed25519-cert-v01@openssh.com", SSHPublicKey.SSHFIDOPublicKey.parser(SSHPublicKey.SSHEdECPublicKey.PARSER), null, null, -1);

    public final String sshType;
    public final String certType;

    public final SSHSerializable.Parser<? extends SSHPublicKey.PublicKeyContainer<?>> parser;
    public final String javaCurve;
    public final String sshCurve;
    public final int curvelen;

    KeyConf(String sshType, String certType, SSHSerializable.Parser<? extends SSHPublicKey.PublicKeyContainer<?>> parser, String javaCurve, String sshCurve, int curvelen) {
        this.sshType = sshType;
        this.parser = parser;
        this.javaCurve = javaCurve;
        this.sshCurve = sshCurve;
        this.curvelen = curvelen;
        this.certType = certType;
    }

    private static <T> T require(T value, String message) {
        if (value == null) {
            throw new IllegalArgumentException(message);
        }
        return value;
    }

    public static final Map<String, KeyConf> sshcurve;
    public static final Map<String, KeyConf> sshtype;
    public static final Map<String, KeyConf> cert;


    // Construct lookup maps
    static {
        sshcurve = Arrays.stream(values())
                .filter(c -> c.sshCurve != null)
                .collect(Collectors.toUnmodifiableMap(conf -> conf.sshCurve,
                        conf -> conf,
                        (existing, replacement) -> existing  // Handle duplicates by keeping existing value
                ));
        sshtype = Arrays.stream(values())
                .collect(Collectors.toUnmodifiableMap(conf -> conf.sshType,
                        conf -> conf,
                        (existing, replacement) -> existing  // Handle duplicates by keeping existing value
                ));

        cert = Arrays.stream(values())
                .collect(Collectors.toUnmodifiableMap(conf -> conf.certType,
                        conf -> conf,
                        (existing, replacement) -> existing  // Handle duplicates by keeping existing value
                ));
    }

    public static KeyConf forKey(Key key) {
        return switch (key) {
            case RSAKey rsa -> RSA;
            case EdECKey ed -> ED25519;
            case ECKey ecKey -> SSHPublicKey.detect_curve(ecKey);
            default -> throw new IllegalArgumentException("Unsupported key type: " + key.getClass().getName());
        };
    }

    public static KeyConf fromSSH(String type) {
        return require(sshtype.get(type), "Unknown SSH public key type: " + type);
    }

    public static KeyConf fromSSHCurve(String curve) {
        return require(sshcurve.get(curve), "Unknown SSH EC curve: " + curve);
    }

    public static KeyConf fromCert(String type) {
        return require(cert.get(type), "Unknown SSH certificate type: " + type);
    }
}
