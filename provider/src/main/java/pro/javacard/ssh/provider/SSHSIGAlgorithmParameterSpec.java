// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.provider;

import java.security.spec.AlgorithmParameterSpec;

public sealed interface SSHSIGAlgorithmParameterSpec extends AlgorithmParameterSpec permits SSHSIGVerificationParameters, SSHSIGSigningParameters {
    String namespace();

    String hash();
}
