package com.hardssh.provider;

import java.nio.charset.StandardCharsets;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;

public record FIDOSignatureParameters(byte[] appdata, int counter, byte flags) implements AlgorithmParameterSpec {

    public FIDOSignatureParameters {
        Objects.requireNonNull(appdata);
        if (appdata.length == 0) {
            throw new IllegalArgumentException("%s requires non-empty appdata".formatted(getClass().getSimpleName()));
        }
    }

    public FIDOSignatureParameters(byte[] appdata) {
        this(appdata, -1, (byte) 0);
    }

    public FIDOSignatureParameters(String app) {
        this(Objects.requireNonNull(app.getBytes(StandardCharsets.US_ASCII)), -1, (byte) 0);
    }
}
