// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.openssh;

import java.io.PrintStream;

// FROM: https://github.com/aflr/CodinGame/blob/main/Easy/Ascii-art-the-drunken-bishop-algorithm/Ascii-art-the-drunken-bishop-algorithm.java
public final class Visalizer {
    private static final int H = 9;
    private static final int W = 17;
    private static final int[][] B = new int[H][W];
    private static final char[] SYMBOLS = {' ', '.', 'o', '+', '=', '*', 'B', 'O', 'X', '@', '%', '&', '#', '/', '^'};
    private static final int[][] MOVES = {{-1, -1}, {-1, +1}, {+1, -1}, {+1, +1}};
    private static int sy = 4, sx = 8;
    private static int ey = 4, ex = 8;

    private Visalizer() {
    }

    public static void runit(byte[] agrs) {
        for (var b : agrs)
            applyPair((byte) (b & 0xFF));
        printBoard(System.out);
    }

    private static void applyPair(int n) {
        for (var i = 0; i < 4; i++)
            move(MOVES[n >> (2 * i) & 0b11]);
    }

    private static void move(int[] movement) {
        if (ey + movement[0] >= 0 && ey + movement[0] < H)
            ey += movement[0];
        if (ex + movement[1] >= 0 && ex + movement[1] < W)
            ex += movement[1];
        B[ey][ex]++;
    }

    private static void printBoard(PrintStream ps) {
        ps.println("+---[CODINGAME]---+");
        for (var i = 0; i < H && ps.printf("%c", '|') != null; ps.println('|'), i++)
            for (var j = 0; j < W; j++)
                if (sy == i && sx == j)
                    ps.print('S');
                else if (ey == i && ex == j)
                    ps.print('E');
                else
                    ps.print(SYMBOLS[B[i][j] % SYMBOLS.length]);
        ps.println("+-----------------+");
    }
}
