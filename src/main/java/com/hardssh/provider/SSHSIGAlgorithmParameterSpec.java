package com.hardssh.provider;

import java.security.spec.AlgorithmParameterSpec;

public sealed interface SSHSIGAlgorithmParameterSpec extends AlgorithmParameterSpec permits SSHSIGVerificationParameters, SSHSIGSigningParameters {
    String namespace();

    default String hash() {
        return "SHA-512";
    }
}
