// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.agent.messages;

import pro.javacard.ssh.utils.SSHSerializable;

import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

public abstract class AgentMessage<T> implements SSHSerializable<T> {

    protected final byte code;

    public static final byte SSH_AGENTC_REQUEST_RSA_IDENTITIES = 1;
    public static final byte SSH_AGENT_RSA_IDENTITIES_ANSWER = 2;
    public static final byte SSH_AGENTC_RSA_CHALLENGE = 3;
    public static final byte SSH_AGENT_RSA_RESPONSE = 4;

    public static final byte SSH_AGENT_FAILURE = 5;
    public static final byte SSH_AGENT_SUCCESS = 6;

    public static final byte SSH_AGENTC_ADD_RSA_IDENTITY = 7;
    public static final byte SSH_AGENTC_REMOVE_RSA_IDENTITY = 8;
    public static final byte SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES = 9;

    // Message constants
    public static final byte SSH_AGENTC_REQUEST_IDENTITIES = 11;
    public static final byte SSH_AGENT_IDENTITIES_ANSWER = 12;
    public static final byte SSH_AGENTC_SIGN_REQUEST = 13;
    public static final byte SSH_AGENT_SIGN_RESPONSE = 14;

    public static final byte SSH_AGENTC_ADD_IDENTITY = 17;
    public static final byte SSH_AGENTC_REMOVE_IDENTITY = 18;
    public static final byte SSH_AGENTC_REMOVE_ALL_IDENTITIES = 19;
    public static final byte SSH_AGENTC_ADD_SMARTCARD_KEY = 20;
    public static final byte SSH_AGENTC_REMOVE_SMARTCARD_KEY = 21;
    public static final byte SSH_AGENTC_LOCK = 22;
    public static final byte SSH_AGENTC_UNLOCK = 23;
    public static final byte SSH_AGENTC_ADD_ID_CONSTRAINED = 25;
    public static final byte SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED = 26;

    public static final byte SSH_AGENTC_EXTENSION = 27;
    public static final byte SSH_AGENT_EXTENSION_FAILURE = 28;
    public static final byte SSH_AGENT_EXTENSION_RESPONSE = 29;

    public static final Map<Byte, String> realNames;

    static {
        Map<Byte, String> messageNames = new HashMap<>();

        messageNames.put(SSH_AGENTC_REQUEST_RSA_IDENTITIES, "SSH_AGENTC_REQUEST_RSA_IDENTITIES");
        messageNames.put(SSH_AGENT_RSA_IDENTITIES_ANSWER, "SSH_AGENT_RSA_IDENTITIES_ANSWER");
        messageNames.put(SSH_AGENTC_RSA_CHALLENGE, "SSH_AGENTC_RSA_CHALLENGE");
        messageNames.put(SSH_AGENT_RSA_RESPONSE, "SSH_AGENT_RSA_RESPONSE");

        messageNames.put(SSH_AGENT_FAILURE, "SSH_AGENT_FAILURE");
        messageNames.put(SSH_AGENT_SUCCESS, "SSH_AGENT_SUCCESS");

        messageNames.put(SSH_AGENTC_ADD_RSA_IDENTITY, "SSH_AGENTC_ADD_RSA_IDENTITY");
        messageNames.put(SSH_AGENTC_REMOVE_RSA_IDENTITY, "SSH_AGENTC_REMOVE_RSA_IDENTITY");
        messageNames.put(SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES, "SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES");

        messageNames.put(SSH_AGENTC_REQUEST_IDENTITIES, "SSH_AGENTC_REQUEST_IDENTITIES");
        messageNames.put(SSH_AGENTC_SIGN_REQUEST, "SSH_AGENTC_SIGN_REQUEST");
        messageNames.put(SSH_AGENTC_ADD_IDENTITY, "SSH_AGENTC_ADD_IDENTITY");
        messageNames.put(SSH_AGENTC_REMOVE_IDENTITY, "SSH_AGENTC_REMOVE_IDENTITY");
        messageNames.put(SSH_AGENTC_REMOVE_ALL_IDENTITIES, "SSH_AGENTC_REMOVE_ALL_IDENTITIES");
        messageNames.put(SSH_AGENTC_ADD_SMARTCARD_KEY, "SSH_AGENTC_ADD_SMARTCARD_KEY");
        messageNames.put(SSH_AGENTC_REMOVE_SMARTCARD_KEY, "SSH_AGENTC_REMOVE_SMARTCARD_KEY");
        messageNames.put(SSH_AGENTC_LOCK, "SSH_AGENTC_LOCK");
        messageNames.put(SSH_AGENTC_UNLOCK, "SSH_AGENTC_UNLOCK");
        messageNames.put(SSH_AGENTC_ADD_ID_CONSTRAINED, "SSH_AGENTC_ADD_ID_CONSTRAINED");
        messageNames.put(SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED, "SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED");
        messageNames.put(SSH_AGENTC_EXTENSION, "SSH_AGENTC_EXTENSION");

        messageNames.put(SSH_AGENT_IDENTITIES_ANSWER, "SSH_AGENT_IDENTITIES_ANSWER");
        messageNames.put(SSH_AGENT_SIGN_RESPONSE, "SSH_AGENT_SIGN_RESPONSE");
        messageNames.put(SSH_AGENT_EXTENSION_FAILURE, "SSH_AGENT_EXTENSION_FAILURE");
        messageNames.put(SSH_AGENT_EXTENSION_RESPONSE, "SSH_AGENT_EXTENSION_RESPONSE");

        realNames = Collections.unmodifiableMap(messageNames);
    }

    protected AgentMessage(byte code) {
        this.code = code;
    }

    // Return the _payload_ of the message (no header)
    @Override
    public byte[] toBytes() {
        Logger.getLogger(AgentMessage.class.getName()).warning("default toBytes");
        return new byte[0];
    }

    public static String name(byte cmd) {
        return realNames.getOrDefault(cmd, Integer.toString(cmd));
    }

    // Returns the command code and advances the buffer to the signer
    public static byte identify(ByteBuffer buffer) {
        buffer.rewind();
        buffer.getInt();
        // NOTE: message size is already checked in Sockets.java
        return buffer.get();
    }

    public static ByteBuffer construct(AgentMessage<?> msg) {
        byte[] payload = msg.toBytes();
        var buffer = ByteBuffer.allocate(payload.length + 5);
        buffer.putInt(payload.length + 1);
        buffer.put(msg.code);
        buffer.put(payload);
        buffer.flip();
        return buffer;
    }

    public static ByteBuffer failure() {
        return construct(SSH_AGENT_FAILURE);
    }

    public static ByteBuffer ext_failure() {
        return construct(SSH_AGENT_EXTENSION_FAILURE);
    }

    public static ByteBuffer success() {
        return construct(SSH_AGENT_SUCCESS);
    }

    public static boolean success(ByteBuffer buffer) {
        return identify(buffer) == SSH_AGENT_SUCCESS;
    }

    public static ByteBuffer list() {
        return construct(SSH_AGENTC_REQUEST_IDENTITIES);
    }

    public static ByteBuffer purge() {
        return construct(SSH_AGENTC_REMOVE_ALL_IDENTITIES);
    }

    private static ByteBuffer construct(byte code) {
        var buffer = ByteBuffer.allocate(5);
        buffer.putInt(1);
        buffer.put(code);
        return buffer;
    }
}

