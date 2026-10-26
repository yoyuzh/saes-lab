"""Independent, matrix-based oracle transcribed from Appendix D (test-only)."""

BOX = (9, 4, 10, 11, 13, 1, 8, 5, 6, 2, 0, 3, 12, 14, 15, 7)


def multiply(left, right):
    product = 0
    for bit in range(4):
        if right & (1 << bit):
            product ^= left << bit
    for degree in range(6, 3, -1):
        if product & (1 << degree):
            product ^= 0b10011 << (degree - 4)
    return product


def reference_encrypt(plaintext, key):
    words = [key >> 8, key & 255]
    for constant in (0x80, 0x30):
        last = words[-1]
        transformed = (BOX[last & 15] << 4) | BOX[last >> 4]
        words.append(words[-2] ^ constant ^ transformed)
        words.append(words[-1] ^ words[-2])
    state = [[plaintext >> 12, (plaintext >> 4) & 15],
             [(plaintext >> 8) & 15, plaintext & 15]]
    for round_index in range(3):
        if round_index:
            state = [[BOX[value] for value in row] for row in state]
            state[1].reverse()
            if round_index == 1:
                state = [[state[0][column] ^ multiply(4, state[1][column]) for column in range(2)],
                         [multiply(4, state[0][column]) ^ state[1][column] for column in range(2)]]
        for column in range(2):
            state[0][column] ^= words[round_index * 2 + column] >> 4
            state[1][column] ^= words[round_index * 2 + column] & 15
    return (state[0][0] << 12) | (state[1][0] << 8) | (state[0][1] << 4) | state[1][1]
