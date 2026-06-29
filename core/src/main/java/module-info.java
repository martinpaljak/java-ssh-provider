// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
module pro.javacard.ssh {
    requires transitive java.logging;

    exports pro.javacard.ssh;
    exports pro.javacard.ssh.agent.messages;
    exports pro.javacard.ssh.utils;
    exports pro.javacard.ssh.dtbs;
    exports pro.javacard.ssh.openssh;
    exports pro.javacard.ssh.agent;
}