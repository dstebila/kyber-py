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
        s = int.from_bytes(input_bytes,'big')
        elements = []
        for i in range(k):
            elements.append(self.ring.gsvcompression_decode((s % (3329 ** 256)).to_bytes(polybytelen,'big'),is_ntt=is_ntt))
            s = s // (3329 ** 256)

        return self.vector(elements)
    
    def gsvcompression_decode_vector_fast(self, input_bytes, k, is_ntt=False):
        matrixbytelen = math.ceil(math.log2(self.ring.q) * self.ring.n * k / 8)
        if matrixbytelen != len(input_bytes):
            raise ValueError(
                "Byte length is the wrong length for given k value"
            )

        l_bytelen = self.ring.n * k
        # l = input_bytes[:l_bytelen]
        s = int.from_bytes(input_bytes[l_bytelen:],'big')
        elements = []
        for i in range(k):
            coeffs = []
            for j in range(256):
                coeffs.append((s % 13)*256 + (input_bytes[j+(i*256)]))
                s = s // 13
            poly = PolynomialRingKyber()
            elements.append(poly(coeffs,is_ntt=is_ntt))
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
                s += int.from_bytes(ele.gsvcompression_encode(),'big') * (3329 ** (256 * k))
                k += 1
        bytelen = math.ceil(math.log2(3329) * 256 * len(row) / 8)
        return s.to_bytes(bytelen,'big')
    
    def gsvcompression_encode_fast(self):
        s = 0
        l = 0
        k = 0
        l = bytearray(len(self._data[0]) * 256)
        for row in self._data:
            for ele in row: # one ele is one polynomial
                si = 0
                for i in range(256):
                    if ele.coeffs[i] == 3328:
                        return None
                    si += (ele.coeffs[i] >> 8) * 13 ** i
                    l[i + (k*256)] = (ele.coeffs[i] % 256)
                s += si * (13 ** (k*256))
                k += 1
            # # in rejection version:
            # # now check if msb of s is 1 and reject if so.
            # # otherwise...
        s_bytelen = math.ceil(math.log2(13) * 256 * len(row) / 8)
        return l + s.to_bytes(s_bytelen,'big')
    
    def kemeleon_encode(self):
        sb = self.gsvcompression_encode()
        s = int.from_bytes(sb,'big')
        bl = math.ceil(math.log2(3329) * 256 * len(self._data[0]))
        if s >> (bl - 1) == 1:
            return None
        else:
            return sb

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
