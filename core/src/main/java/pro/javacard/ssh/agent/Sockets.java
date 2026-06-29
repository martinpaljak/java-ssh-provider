// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.agent;

import pro.javacard.ssh.agent.messages.AgentMessage;
import pro.javacard.ssh.utils.Helpers;
import pro.javacard.ssh.utils.SSHWireFormat;

import java.io.EOFException;
import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.logging.Logger;

public final class Sockets {
    public static final String SSH_AUTH_SOCK = "SSH_AUTH_SOCK";
    private static final Logger log = Logger.getLogger(Sockets.class.getName());

    private final static int MAX_MESSAGE_SIZE = SSHWireFormat.MAX_MESSAGE_LENGTH; // Note: might want to increase this
    public final static int OFFSET_LENGTH = 0;
    public final static int OFFSET_TYPE = 4;
    // Indicates if POSIX file permission checks should be done on config files
    static final boolean isPosix = FileSystems.getDefault().supportedFileAttributeViews().contains("posix");

    private Sockets() {
    }

    public static ByteBuffer readMessage(SocketChannel channel) throws IOException {
        var len_buffer = ByteBuffer.allocate(4);
        var n = channel.read(len_buffer);
        if (n == -1) {
            throw new EOFException("EOF");
        }

        var len = len_buffer.getInt(OFFSET_LENGTH);
        if (len < 1 || len > MAX_MESSAGE_SIZE) {
            throw new IOException("Message too long: " + len);
        }

        var buffer = ByteBuffer.allocate(len + 4);
        // put back the length
        buffer.put(len_buffer.array());

        while (buffer.position() != buffer.capacity()) {
            n = channel.read(buffer);
            log.finest("Read %d bytes".formatted(n));
            // Socket closed by other side
            if (n == -1) {
                throw new EOFException("EOF");
            }
        }
        // Mark limit and rewind back to beginning
        return buffer.flip();
    }

    // Returns true if the path is a valid and answering socket
    public static boolean probe(Path p) {
        try (var s = connect(p)) {
            return s.isConnected();
        } catch (IOException e) {
            log.fine("Socket probe failed: %s".formatted(e.getMessage()));
            return false;
        }
    }

    public static void writeMessage(SocketChannel channel, ByteBuffer buffer) throws IOException {
        // Make sure we start from beginning
        buffer.rewind();
        var sent = channel.write(buffer);
        if (sent != buffer.limit()) {
            log.warning("Could not send %d bytes: %d".formatted(buffer.limit(), buffer.position()));
            throw new IOException("Could not send all bytes");
        }
    }

    public static ByteBuffer transceive(SocketChannel s, ByteBuffer buffer) throws IOException {
        return transceive(s, buffer, null);
    }

    public static ByteBuffer transceive(SocketChannel s, ByteBuffer buffer, String name) throws IOException {
        var prefix = name == null ? "" : name + "-";
        var copy = buffer.asReadOnlyBuffer();
        log.fine("%s>>> %s (%s)".formatted(prefix, AgentMessage.name(copy.get(OFFSET_TYPE)), copy.getInt(OFFSET_LENGTH)));
        log.finer("%s>>> %s".formatted(prefix, Helpers.toHex(buffer)));
        writeMessage(s, buffer);
        var response = readMessage(s);
        log.finer("%s<<< %s".formatted(prefix, Helpers.toHex(response)));
        log.fine("%s<<< %s (%s)".formatted(prefix, AgentMessage.name(response.get(OFFSET_TYPE)), response.getInt(OFFSET_LENGTH)));
        return response;
    }

    public static ServerSocketChannel start(Path p) throws IOException {
        var sock = UnixDomainSocketAddress.of(p);
        var serverSocket = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        serverSocket.bind(sock);
        if (isPosix) {
            Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-------"));
        }
        log.info("Agent started at %s".formatted(p));
        return serverSocket;
    }

    public static SocketChannel connect(Path p) throws IOException {
        var s = SocketChannel.open(StandardProtocolFamily.UNIX);
        if (!s.connect(UnixDomainSocketAddress.of(p))) {
            throw new IOException("Could not connect to " + p);
        }
        log.fine("Connected to %s".formatted(p));
        return s;
    }
}
