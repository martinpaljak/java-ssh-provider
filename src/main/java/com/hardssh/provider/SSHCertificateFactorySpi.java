package com.hardssh.provider;

import pro.javacard.ssh.SSHIdentity;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.cert.*;
import java.util.Collection;
import java.util.List;

public class SSHCertificateFactorySpi extends CertificateFactorySpi {
    public SSHCertificateFactorySpi() {
    }

    @Override
    public Certificate engineGenerateCertificate(InputStream inStream) throws CertificateException {
        try {
            // TODO: x509
            return SSHIdentity.fromByteBuffer(ByteBuffer.wrap(inStream.readAllBytes())).asCert().orElseThrow(() -> new CertificateException("Not a SSH certificate"));
        } catch (IOException e) {
            throw new CertificateException(e);
        }
    }

    @Override
    public Collection<? extends Certificate> engineGenerateCertificates(InputStream inStream) throws CertificateException {
        return List.of(engineGenerateCertificate(inStream));
    }

    @Override
    public CRL engineGenerateCRL(InputStream inStream) throws CRLException {
        throw new UnsupportedOperationException("CRLs are not supported");
    }

    @Override
    public Collection<? extends CRL> engineGenerateCRLs(InputStream inStream) throws CRLException {
        throw new UnsupportedOperationException("CRLs are not supported");
    }

}
