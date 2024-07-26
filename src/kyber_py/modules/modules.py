from ..polynomials.polynomials import PolynomialRingKyber
from .modules_generic import Module, Matrix
import math

class ModuleKyber(Module):
    def __init__(self):
        self.ring = PolynomialRingKyber()
        self.matrix = MatrixKyber

    def gsvcompression_decode_vector(self, input_bytes, k, is_ntt=False):
        polybytelen = math.ceil(math.log2(self.ring.q) * self.ring.n / 8)
        matrixbytelen = math.ceil(math.log2(self.ring.q) * self.ring.n * k / 8)
        if matrixbytelen != len(input_bytes):
            raise ValueError(
                "Byte length is the wrong length for given k value"
            )

        # Encode each chunk of bytes as a polynomial and create the vector
        s = int.from_bytes(input_bytes)
        elements = []
        for i in range(k):
            elements.append(self.ring.gsvcompression_decode((s % (3329 ** 256)).to_bytes(polybytelen),is_ntt=is_ntt))
            s = s // (3329 ** 256)

        return self.vector(elements)

    def decode_vector(self, input_bytes, k, d, is_ntt=False):
        # Ensure the input bytes are the correct length to create k elements with
        # d bits used for each coefficient
        if self.ring.n * d * k != len(input_bytes) * 8:
            raise ValueError(
                "Byte length is the wrong length for given k, d values"
            )

        # Bytes needed to decode a polynomial
        n = 32 * d

        # Encode each chunk of bytes as a polynomial and create the vector
        elements = [
            self.ring.decode(input_bytes[i : i + n], d, is_ntt=is_ntt)
            for i in range(0, len(input_bytes), n)
        ]

        return self.vector(elements)


class MatrixKyber(Matrix):
    def __init__(self, parent, matrix_data, transpose=False):
        super().__init__(parent, matrix_data, transpose=transpose)

    def encode(self, d):
        output = b""
        for row in self._data:
            for ele in row:
                output += ele.encode(d)
        return output

    def gsvcompression_encode(self):
        s = 0
        k = 0
        for row in self._data:
            for ele in row:
                s += int.from_bytes(ele.gsvcompression_encode()) * (3329 ** (256 * k))
                k += 1
        bytelen = math.ceil(math.log2(3329) * 256 * len(row) / 8)
        return s.to_bytes(bytelen)

    def compress(self, d):
        for row in self._data:
            for ele in row:
                ele.compress(d)
        return self

    def decompress(self, d):
        for row in self._data:
            for ele in row:
                ele.decompress(d)
        return self

    def to_ntt(self):
        data = [[x.to_ntt() for x in row] for row in self._data]
        return self.parent(data, transpose=self._transpose)

    def from_ntt(self):
        data = [[x.from_ntt() for x in row] for row in self._data]
        return self.parent(data, transpose=self._transpose)
