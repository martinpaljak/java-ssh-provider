package com.hardssh.provider;

import pro.javacard.ssh.openssh.SSHAllowedSigners;
import pro.javacard.ssh.openssh.SSHPatternMatcher;
import pro.javacard.ssh.openssh.SSHSIG;

import java.time.Instant;
import java.util.List;

public final class TrustProvider {
    // this is a wrapper around allowed_signers file

    private final SSHAllowedSigners allowedSigners;

    public TrustProvider(SSHAllowedSigners allowedSigners) {
        this.allowedSigners = allowedSigners;
    }


    // Assumes a certificate. authorization based on identity is done elsewhere
    public boolean can(SSHSIG sig, String namespace, Instant when) {
        var optcert = sig.signer().asCert();
        if (optcert.isEmpty()) {
            return false;
        }
        var who = optcert.get();
        var cert = who.getPayload();


        if (cert.notAfter().isAfter(when) || cert.notBefore().isBefore(when)) {
            return false;
        }
        var entries = allowedSigners.getConfig().entries()
                .filter(e -> e.getOption(SSHAllowedSigners.Option.ValidAfter.class)
                        .map(t -> !when.isAfter(t.timestamp().toInstant()) && cert.notBefore().isBefore(t.timestamp().toInstant()))
                        .orElse(true))
                .filter(e -> e.getOption(SSHAllowedSigners.Option.ValidBefore.class)
                        // A Ca validity can be shortened, which will make this check fail
                        .map(t -> (t.timestamp().toInstant().isAfter(when) && cert.notAfter().isAfter(t.timestamp().toInstant())))
                        .orElse(true))
                .filter(e -> e.getOption(SSHAllowedSigners.Option.Namespaces.class)
                        .map(ns -> SSHPatternMatcher.matches(namespace, ns.values()))
                        .orElse(false))
                .filter(e -> e instanceof SSHAllowedSigners.CertAuthorityEntry ca && ca.key().equals(who.getSignatureKey()))
                .map(SSHAllowedSigners.CertAuthorityEntry.class::cast)
                .filter(e -> cert.principals().stream()
                        .anyMatch(p -> e.principals().stream()
                                .anyMatch(pattern -> SSHPatternMatcher.matches(p, pattern))))
                .toList();
        return !entries.isEmpty();

        // requirement: namespace must match an entry
        // requirement: principal must match an entry
        // requirement: for a CA entry, a principal in the cert must match an entry
        // requirements: for a CA entry, the cert must be issued when the CA entry was valid
        // requirements: for a CA entry, the cert must be valid
    }


    // give a list of principal patterns who can sign in a namespace at given time
    public List<String> whoCan(String namespace, Instant when) {
        List<String> principals = allowedSigners.getConfig().entries()
                .filter(e -> e.getOption(SSHAllowedSigners.Option.ValidAfter.class)
                        .map(t -> !when.isBefore(t.timestamp().toInstant()))
                        .orElse(true))
                .filter(e -> e.getOption(SSHAllowedSigners.Option.ValidBefore.class)
                        .map(t -> t.timestamp().toInstant().isAfter(when))
                        .orElse(true))
                .filter(e -> e.getOption(SSHAllowedSigners.Option.Namespaces.class)
                        .map(ns -> SSHPatternMatcher.matches(namespace, ns.values()))
                        .orElse(false))
                .flatMap(e -> e.principals().stream())
                .toList();
        return principals;
    }

}
