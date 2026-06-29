// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.dtbs;

import pro.javacard.ssh.SSHIdentity;
import pro.javacard.ssh.utils.SSHWireFormat;

import java.nio.ByteBuffer;

@SuppressWarnings("ArrayRecordComponent")
public record UserAuthPayload(byte[] dtbs, String username, String connection, String method, boolean has_signature,
                              String pkalg,
                              SSHIdentity pubkey, SSHIdentity serverhost) implements DTBSPayload<UserAuthPayload> {

    public static final Parser<UserAuthPayload> PARSER = UserAuthPayload::fromByteBuffer;

    public static final String HOSTBOUND = "publickey-hostbound-v00@openssh.com";

    public static UserAuthPayload fromByteBuffer(ByteBuffer buffer) {
        var start = buffer.position();
        // Described in https://github.com/openssh/openssh-portable/blob/master/PROTOCOL#L434
        // and https://datatracker.ietf.org/doc/html/rfc4252#page-9
        SSHWireFormat.get_bytes(buffer); // Skip session
        var code = buffer.get();
        if (code == 50) {
            var username = SSHWireFormat.get_safe_string(buffer);
            var connection = SSHWireFormat.get_safe_string(buffer);
            var method = SSHWireFormat.get_safe_string(buffer);
            var has_signature = SSHWireFormat.get_boolean(buffer);
            var pkalg = SSHWireFormat.get_safe_string(buffer);
            var keybytes = SSHWireFormat.get_bytes(buffer);
            var pubkey = SSHIdentity.fromByteBuffer(ByteBuffer.wrap(keybytes));
            final SSHIdentity host;
            if (HOSTBOUND.equals(method)) {
                var hostkey = SSHWireFormat.get_bytes(buffer);
                host = SSHIdentity.fromByteBuffer(ByteBuffer.wrap(hostkey));
            } else {
                host = null;
            }
            byte[] data = new byte[buffer.position() - start];
            buffer.position(start);
            buffer.get(data);
            return new UserAuthPayload(data, username, connection, method, has_signature, pkalg, pubkey, host);
        } else {
            return null;
        }
    }

    @Override
    public String pattern() {
        // TLC: this is not for matching, as for that we need to know the name, but that resolving is left for the upper layer.
        // NOTE: OpenSSH always reports the host _key_ even if using certificates.
        return "auth:" + username + "@" + (serverhost == null ? "" : serverhost.getKey().getFingerprint());
    }
}
