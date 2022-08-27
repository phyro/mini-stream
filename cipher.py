# Don't trust me with cryptography.

import hashlib


def H(_input):
    utf8_input = _input.encode("utf-8")
    return hashlib.sha256(utf8_input).hexdigest()


def t2b(text):
    return list(
        map(int, "".join([bin(ord(i)).lstrip("0b").rjust(8, "0") for i in text]))
    )


def b2t(bits):
    return "".join(
        chr(int("".join(map(str, bits[i : i + 8])), 2)) for i in range(0, len(bits), 8)
    )


def key_stream_bits(stream_hash, length):
    """Returns a sequence of key stream bits of given length."""
    N = length // 64 + 1
    H_stream = "".join([H(stream_hash + str(i)) for i in range(N)])[:length]
    return [1 if int(key_char, 16) > 7 else 0 for key_char in H_stream]


def enc(S, K, M):
    # Derive the starting hash from the secret key S and nonce K
    rnd_hash = H(K + S)
    # Present the message as a sequence of bits
    M_bits = t2b(M)
    K_bits = key_stream_bits(rnd_hash, len(M_bits))
    # XOR i-th bit with bit at key stream position i and turn the result to text
    return b2t([M_bits[i] ^ K_bits[i] for i in range(len(M_bits))])


text = "Aenean massa. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus."
seed = "super secret seed"
nonce = "my not more than once."

assert enc(seed, nonce, enc(seed, nonce, text)) == text  # OK
assert enc(seed, "k1", enc(seed, nonce, text)) != text  # wrong decryption nonce

encrypted = enc(seed, nonce, text)
decrypted = enc(seed, nonce, encrypted)

print(f"start text: {text}")
print(f"encrypted: {encrypted}")
print(f"decrypted: {decrypted}")
