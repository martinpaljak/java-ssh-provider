# SSHProvider.java
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/martinpaljak/java-ssh-provider/blob/main/LICENSE)
&nbsp;[![Latest release](https://img.shields.io/github/release/martinpaljak/java-ssh-provider.svg)](https://github.com/martinpaljak/java-ssh-provider/releases/latest)
&nbsp;[![Maven version](https://img.shields.io/maven-metadata/v?label=javacard.pro%20version&metadataUrl=https%3A%2F%2Fmvn.javacard.pro%2Fmaven%2Fcom%2Fgithub%2Fmartinpaljak%2Fsshprovider%2Fmaven-metadata.xml)](https://gist.github.com/martinpaljak/c77d11d671260e24eef6c39123345cae)
&nbsp;[![Build status](https://github.com/martinpaljak/java-ssh-provider/actions/workflows/robot.yml/badge.svg?branch=main)](https://github.com/martinpaljak/java-ssh-provider/actions)
&nbsp;[![Made in Estonia](https://img.shields.io/badge/Made_in-Estonia-blue)](https://estonia.ee)


The missing key management bridge between (Open)SSH and Java worlds. `SSHProvider` (a Java Security Provider) makes SSH **keys**, **certificates** and **signatures** first-class citizens in the Java ecosystem:
- access keys and certificates in any [compatible agent](https://datatracker.ietf.org/doc/draft-ietf-sshm-ssh-agent/) (as set in `$SSH_AUTH_SOCK`) via Java [`KeyStore`](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/KeyStore.html)
- use hardware-backed agent keys with standard Java [`Signature`](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/Signature.html) like normal keys
- verify and create [`SSHSIG`](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig) and raw SSH signature formats, also with [SSH certificates](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys) (including [webauthn signatures](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f#L222-L246))
- use existing OpenSSH [`allowed_signers`](https://man.openbsd.org/ssh-keygen.1#ALLOWED_SIGNERS) trust anchoring files (as used by Git, for example)

[Reproducible](https://reproducible-builds.org) 175K .jar with pure Java and _zero_ 3rd party dependencies.

> [!TIP]
> Sign easily with local hardware keys on remote machines with SSH agent forwarding ❤️

## How to use
There is also a longer [Tutorial](https://github.com/martinpaljak/java-ssh-provider/wiki/Tutorial) (WIP).
## Access keys in agent

Generate standard signatures with a key in hardware via `$SSH_AUTH_SOCK`

> [!NOTE]
> Keys are _reported_ by their public key fingerprint (same as shown by `ssh-add -l`) but can _also_ be addressed by full public key/certificate string (as shown by `ssh-add -L` or available in a `.pub` file).


```java
import com.hardssh.provider.SSHProvider;

Security.addProvider(new SSHProvider()); // Add the provider

KeyStore ks = KeyStore.getInstance("SSH"); // access $SSH_AUTH_SOCK

ks.load(null, null); // a password would send an "unlock" command to the agent (ssh-add -X)

// same output as "ssh-add -l"
for (String alias : Collections.list(ks.aliases())) {
    System.out.println(alias); // SHA256:5DmYCoIkCgEoOnbx3K+UXLhHVh8pX8GXgf7IS8i9QPo
}

String alias = "SHA256:5DmYCoIkCgEoOnbx3K+UXLhHVh8pX8GXgf7IS8i9QPo";

PrivateKey key = (PrivateKey) ks.getKey(alias);
Signature sig = Signature.getInstance("SHA256withECDSA");
sig.initSign(key);

// Continue as usual
```

> [!IMPORTANT]
> If a key has associated SSH certificate(s), a [KeyStore.PrivateKeyEntry](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/KeyStore.PrivateKeyEntry.html) with key + certificate will be available **with the hash of the certificate** (unlike OpenSSH/`ssh-add`, which reports certificates with the fingerprint of the key). `SSHProvider` supports multiple certificates per key. Certificates _without_ an available private key _will not_ be available via `KeyStore`.

### Verify a `SSHSIG` signature created with OpenSSH
After signing a file (`$ echo 'Hello, World!' > /tmp/helloworld.txt`) with OpenSSH:

```console
$ ssh-keygen -t ed25519 -f /tmp/id_ed25519 -N '' -C 'Test key'
$ ssh-keygen -Y sign -n file -f /tmp/id_ed25519 /tmp/helloworld.txt
```

Verify it with Java (or vice-versa):

```java
PublicKey pub = SSHIdentity.fromPath(Paths.get("/tmp/id_ed25519.pub"));
byte[] signature = SSHSIG.fromArmored(Paths.get("/tmp/helloworld.txt.sig"));
Signature sig = Signature.getInstance("SSHSIG");
sig.setParameter(new SSHSIGVerificationSpec("file"));
sig.initVerify(pub);
sig.update(Files.readAllBytes(Paths.get("/tmp/helloworld.txt")))
Assert.assertTrue(sig.verify(signature));
```

## Supported algorithms
> [!NOTE]
> Supported key types are Ed25519, ECDSA, RSA and FIDO with Ed25519 and ECDSA. DSA keys are _actively rejected_.

- KeyStore `SSH`
- Signature `Ed25519` (sign, agent only)
- Signature `SHA256withECDSA` (sign, agent only)
- Signature `SHA384withECDSA` (sign, agent only)
- Signature `SHA512withECDSA` (sign, agent only)
- Signature `SHA256withRSA` (sign, agent only)
- Signature `SHA512withRSA` (sign, agent only)
- Signature `ssh-ed25519` (sign, verify)
- Signature `ssh-ecdsa-nistp256` (sign, verify)
- Signature `ssh-ecdsa-nistp384` (sign, verify)
- Signature `ssh-ecdsa-nistp521` (sign, verify)
- Signature `rsa-sha2-256` (sign, verify)
- Signature `rsa-sha2-512` (sign, verify)
- Signature `sk-ssh-ed25519@openssh.com` (sign (agent only), verify)
- Signature `sk-ecdsa-sha2-nistp256@openssh.com` (sign (agent only), verify)
- Signature `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` (verify)
- Signature `SSHSIG` (sign, verify)
- CertificateFactory `SSH`
- KeyFactory `SSH`
- OpenSSHPublicKeySpec (to/from OpenSSH string format (`~/.ssh/*.pub`))

## Installation

> [!IMPORTANT]
> Requires Java 21+ and currently targeting unices only. Source publish pending on final package re-structuring and cleanups. `com.hardssh.provider.SSHProvider` is here to stay.

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
        <artifactId>sshprovider</artifactId>
        <version>25.02.21</version>
    </dependency>
</dependencies>
```

## Agents
> [!TIP]
> `SSHProvider` does _not_ implement or handle plaintext private keys in any form _by design_.
>
> If you really _have_ to work with your plaintext keys from `~/.ssh`, add them to the standard OpenSSH `ssh-agent`.

`SSHProvider` is regularly tested with and works seamlessly with:

- [Secretive](https://github.com/maxgoedjen/secretive)
- [yubikey-agent](https://github.com/FiloSottile/yubikey-agent)
- [ssh-tpm-agent](https://github.com/Foxboron/ssh-tpm-agent)
- [OpenSSH ssh-agent](https://man.openbsd.org/ssh-agent)
- [YAUSA](https://github.com/martinpaljak/YAUSA)
- anything that follows [the specification](https://datatracker.ietf.org/doc/draft-ietf-sshm-ssh-agent/)

## Other Java/SSH projects
`SSHProvider` was not created in vacuum, there is other software available.

Nothing from the existing open source universe fitted the approach and requirements for building [`HardSSH`](https://hardssh.com), thus `SSHProvider` was born as a minimal and fresh cleanroom implementation for modern Java. The Security Provider builds upon the SSH agent code in [YAUSA](https://github.com/martinpaljak/YAUSA), but is published and packaged separately, due to its generic and re-usable nature.

It reflects on quarter century of ~~pain~~ ~~experience~~ agony with smart cards, secure elements and hardware cryptography. Please don't ask about PKCS#11 (which you _can_ use via OpenSSH `ssh-agent`).

- http://www.jcraft.com/jsch/
- https://github.com/apache/mina-sshd
- https://github.com/eclipse-jgit/jgit/tree/master/org.eclipse.jgit.ssh.apache.agent
- https://github.com/eclipse-jgit/jgit/tree/master/org.eclipse.jgit.ssh.apache/src/org/eclipse/jgit/internal/signing/ssh
- https://github.com/profhenry/sshsig
- https://github.com/sshtools/maverick-synergy
- https://github.com/Tesco/ssh-certificates
- https://github.com/rkeene/ssh-agent-pkcs11

