# SSHProvider.java
The missing bridge between SSH and Java worlds:
- access keys in any [compatible](https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent) agent[<sup>*</sup>](#agents) (as set in `$SSH_AUTH_SOCK`) via Java [`KeyStore`](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/KeyStore.html)
- use agent keys for standard Java signatures
- sign easily with local hardware keys on remote machines with SSH agent forwarding
- work with [`SSHSIG`](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig) and raw SSH signature formats and [SSH certificates](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys) (including [webauthn signatures](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f), WIP)

## How to use
```java
Security.addProvicer(new SSHProvider());

KeyStore ks = KeyStore.getInstance("SSH");

ks.load(null, null); // specify a password to issue "unlock" command to agent

// same as "ssh-add -l"
for (String alias : Collections.list(ks.aliases())) {
    System.out.println(alias); // SHA256:5DmYCoIkCgEoOnbx3K+UXLhHVh8pX8GXgf7IS8i9QPo
}

String alias = "SHA256:5DmYCoIkCgEoOnbx3K+UXLhHVh8pX8GXgf7IS8i9QPo";

PrivateKey key = (PrivateKey) ks.getKey(alias);
Signature sig = Signature.getInstance("SHA256withECDSA")
sig.initSign(key);

// Continue as usual
```

> [!NOTE]
> Keys are reported by their public key fingerprint (as reported by `ssh-add -l`) but can also be addressed via full public key format (as reported by `ssh-add -L`).

## Supported algorithms
- KeyStore (SSH)
- Signature (Ed25519)
- Signature (SHA256withECDSA)
- Signature (SHA384withECDSA)
- Signature (SHA512withECDSA)
- Signature (SHA256withRSA)
- Signature (SHA512withRSA)
- Signature (ssh-ed25519)
- Signature (ssh-ecdsa-nistp256)
- Signature (ssh-ecdsa-nistp384)
- Signature (ssh-ecdsa-nistp521)
- Signature (rsa-sha2-256)
- Signature (rsa-sha2-512)

## Installation

> [!IMPORTANT]
> Requires Java 21+ and currently available for unices only.

With Maven:
```xml
<repositories>
    <repository>
        <id>javacard-pro</id>
        <url>https://mvn.javacard.pro/maven/</url>
    </repository>
</repositories>


<dependencies>
    <dependency>
        <groupId>com.github.martinpaljak</groupId>
        <artifactId>yausa-jca</artifactId>
        <version>25.01.23-SNAPSHOT</version>
    </dependency>
</dependencies>
```

## Agents
- Secretive
- yubikey-agent
- YAUSA
- etc


