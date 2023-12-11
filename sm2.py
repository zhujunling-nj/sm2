#-*-coding:utf8;-*-
''' 素数域上的椭圆曲线(SM2) '''
from sm3 import sm3_hash
from curve import Curve
from fieldp import FP


class CurveSM2(Curve):
    ''' 素数域上的椭圆曲线(SM2)计算 '''
    __slots__ = []
    P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
    B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
    N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
    GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
    GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
    LEN = (P.bit_length() + 7) >> 3
    CACHE = []

CurveSM2.ZERO = CurveSM2(0, 0, False)
CurveSM2.BASE = CurveSM2(CurveSM2.GX, CurveSM2.GY, False)
CurveSM2.CACHE = CurveSM2.create_cache(CurveSM2.BASE)


class SM2PrivateKey(int):
    ''' SM2 Private Key '''
    __slots__ = []

    def public_key(self):
        ''' Get Public Key '''
        return CurveSM2.gmul(self)


class SM2Error(Exception):
    ''' SM2加解密错误 '''
    __slots__ = ['msg']

    def __init__(self, msg):
        super().__init__()
        self.msg = msg

    def __str__(self):
        return self.msg


class SM2:
    '''
        SM2 加密/解密, 签名/验签
        解密/签名使用Private Key
        加密/验签使用Public Key
    '''
    __slots__ = ['public_key', 'private_key', 'cache', 'user_z']
    USER_ID = b'1234567812345678'

    @staticmethod
    def create_private_key():
        ''' Create Private Key '''
        return SM2PrivateKey(CurveSM2.random())

    @staticmethod
    def create_public_key(valuex, valuey=0):
        ''' Create Public Key '''
        return CurveSM2.from_bytes(valuex) \
            if isinstance(valuex, (bytes, bytearray)) \
            else CurveSM2(valuex, valuey)


    def __init__(self, public_key, private_key=None, use_cache=None):
        self.public_key = public_key
        if isinstance(public_key, (bytes, bytearray)):
            self.public_key = CurveSM2.from_bytes(public_key)
        elif not isinstance(public_key, CurveSM2):
            raise SM2Error('Invalid public key.')

        self.user_z = None
        self.cache = use_cache and not private_key and \
                     CurveSM2.create_cache(self.public_key)

        self.private_key = private_key
        if private_key is None:
            return

        if isinstance(private_key, (bytes, bytearray)):
            self.private_key = bytes2int(private_key)
        elif not isinstance(private_key, int):
            raise SM2Error('Invalid private key.')
        if CurveSM2.gmul(self.private_key) != self.public_key:
            raise SM2Error('Public key not matched the private key.')


    def fmul(self, kkk, affine=True):
        ''' 公钥倍乘运算, 使用缓存加速 '''
        if not self.cache:
            return self.public_key * kkk
        result = CurveSM2.ZERO.copy()
        for i in range(32):
            result.fast_add(self.cache[i][kkk & 0xFF])
            kkk >>= 8
        return result.to_affine() if affine else result


    def verify(self, sign, data):
        ''' 验签函数, sign: 签名r||s, data: 待验签的消息(bytes) '''
        rrr, sss = SM2._decode_signed_asn1(sign)
        ttt = (rrr + sss) % CurveSM2.N
        if rrr == 0 or sss == 0 or ttt == 0 or rrr >= CurveSM2.N or sss >= CurveSM2.N:
            return False

        eee = bytes2int(self._get_sign_hash(data))
        point = self.fmul(ttt, False).fast_add(CurveSM2.gmul(sss, False)).to_affine()
        return (eee + point.coord_x) % CurveSM2.N == rrr


    def sign(self, data):
        ''' 签名函数, data: 待签名的消息(bytes) '''
        if self.private_key is None:
            raise SM2Error('No private key specified.')

        eee = bytes2int(self._get_sign_hash(data))
        sss = 0
        while sss == 0:
            kkk = CurveSM2.random()
            point = CurveSM2.gmul(kkk)
            rrr = (eee + point.coord_x) % CurveSM2.N
            if rrr and rrr + kkk != CurveSM2.N:
                sss = FP.divn(CurveSM2.N, kkk - rrr*self.private_key, self.private_key + 1)

        r_bytes = ASN1.encode_int(rrr)
        s_bytes = ASN1.encode_int(sss)
        return ASN1.encode_sequence(r_bytes, s_bytes)


    def encrypt(self, plaintext, mode='asn1'):
        ''' 加密函数, plaintext: 明文(bytes) '''
        if mode not in {'c1c2c3', 'c1c3c2', 'c1c2', 'asn1'}:
            raise SM2Error('The mode shoud be c1c2c3 or c1c3c2 or asn1.')
        if plaintext == b'':
            raise SM2Error('Plaintext is empty.')

        # 生成随机数 k
        kkk = CurveSM2.random()
        # 生成椭圆曲线上的点C1 = k * G, 需要编码到密文中
        point1 = CurveSM2.gmul(kkk)
        # 生成椭圆曲线上的点C2 = k * PK
        point2 = self.fmul(kkk)
        # 根据点C2生成加密密钥
        x2_bytes = point2.bytes_x
        y2_bytes = point2.bytes_y
        key = SM2._kdf(x2_bytes + y2_bytes, len(plaintext))
        # 使用加密密钥加密, xor运算
        ciphertext = bitxor(plaintext, key)
        # 根据点C2及明文件计算校验摘要
        if mode == 'c1c2':
            return bytes(point1) + ciphertext

        hashsrc = x2_bytes + plaintext + y2_bytes
        hashvalue = sm3_hash(hashsrc)
        if mode == 'c1c3c2':
            return bytes(point1) + hashvalue + ciphertext
        if mode == 'c1c2c3':
            return bytes(point1) + ciphertext + hashvalue

        return ASN1.encode_sequence(
            ASN1.encode_int(point1.coord_x),
            ASN1.encode_int(point1.coord_y),
            ASN1.encode_octet(hashvalue),
            ASN1.encode_octet(ciphertext)
        )


    def decrypt(self, data, mode='asn1'):
        ''' 解密函数, data: 密文(bytes) '''
        if mode not in {'c1c2c3', 'c1c3c2', 'c1c2', 'asn1'}:
            raise SM2Error('The mode shoud be c1c2c3 or c1c3c2 or asn1.')
        if self.private_key is None:
            raise SM2Error('No private key specified.')
        point1, ciphertext, hashvalue = SM2._decode_ciphertext_asn1(data) \
                if mode == 'asn1' else SM2._decode_ciphertext(data, mode)

        # 根据私钥生成点C2, 此C2等于加密时的C2
        # 私钥: SK, 公钥: PK = SK * G
        # 加密时: C1 = k * G,  C2 = k * PK = k * (SK * G) = k * SK * G
        # 解密时: C2' = SK * C1 = SK * (k * G) = SK * k * G = C2
        point2 = point1 * self.private_key
        # 根据点C2生成解密密钥
        x2_bytes = point2.bytes_x
        y2_bytes = point2.bytes_y
        key = SM2._kdf(x2_bytes + y2_bytes, len(ciphertext))
        # 使用解密密钥解密, xor运算
        plaintext = bitxor(ciphertext, key)
        if hashvalue is None:
            return plaintext

        # 根据点C2及明文件计算校验摘要
        hashsrc = x2_bytes + plaintext + y2_bytes
        if sm3_hash(hashsrc) != hashvalue:
            raise SM2Error('Hash check failed.')
        return plaintext


    def _get_user_z(self):
        entl = len(self.USER_ID) << 3
        z_bits = bytearray(int2bytes(entl, 2))
        z_bits.extend(SM2.USER_ID)
        z_bits.extend(int2bytes(CurveSM2.A, 32))
        z_bits.extend(int2bytes(CurveSM2.B, 32))
        z_bits.extend(int2bytes(CurveSM2.GX, 32))
        z_bits.extend(int2bytes(CurveSM2.GY, 32))
        z_bits.extend(self.public_key.bytes_x)
        z_bits.extend(self.public_key.bytes_y)
        self.user_z = sm3_hash(z_bits)
        return self.user_z

    def _get_sign_hash(self, data):
        user_z = self.user_z or self._get_user_z()
        return sm3_hash(user_z + data)

    @staticmethod
    def _kdf(z_bits, klen):
        result = bytearray()
        rcnt = (klen + 31) >> 5
        for i in range(1, rcnt + 1):
            data = z_bits + int2bytes(i, 4)
            result.extend(sm3_hash(data))
        return result[:klen]

    @staticmethod
    def _decode_signed_asn1(sign):
        ''' 按ASN.1 BER规则解码签名 '''
        sign, rest = ASN1.decode_sequence(sign)
        if sign == b'' or rest != b'':
            raise SM2Error('Invalid signed bytes.')
        rrr, rest = ASN1.decode_int(sign)
        sss, rest = ASN1.decode_int(rest)
        return rrr, sss

    @staticmethod
    def _decode_ciphertext_asn1(data):
        ''' 按ASN.2 BER规则解码密文 '''
        data, rest = ASN1.decode_sequence(data)
        if data == b'' or rest != b'':
            raise SM2Error('Invalid cipher text.')
        c1x, rest = ASN1.decode_int(data)
        c1y, rest = ASN1.decode_int(rest)
        hashvalue, rest = ASN1.decode_octet(rest)
        ciphertext, rest = ASN1.decode_octet(rest)
        if rest != b'':
            raise SM2Error('Invalid cipher text.')
        return CurveSM2(c1x, c1y), ciphertext, hashvalue

    @staticmethod
    def _decode_ciphertext(data, mode):
        ''' 按C1C2C3或C1C3C2或C1C2顺序解码密文 '''
        dlen = len(data)
        if dlen < 66 or data[0] != 4:
            raise SM2Error('Invalid cipher text.')
        # 取出数据生成点C1
        c1x = bytes2int(data[1:33])
        c1y = bytes2int(data[33:65])
        point = CurveSM2(c1x, c1y)
        # 取出密文及校验哈希
        if mode == 'c1c3c2':
            return point, data[97:], data[65:97]
        if mode == 'c1c2c3':
            return point, data[65:dlen-32], data[dlen-32:]
        # mode == 'c1c2'
        return point, data[65:], None


class ASN1Error(Exception):
    ''' ASN.1编解码错误 '''
    __slots__ = ['msg']

    def __init__(self, msg):
        super().__init__()
        self.msg = msg

    def __str__(self):
        return self.msg


class ASN1:
    ''' ASN.1编解码 '''
    __slots__ = []

    @staticmethod
    def encode_int(value):
        ''' 按ASN.1 BER规则编码整数 '''
        asn_len = (value.bit_length() >> 3) + 1
        asn_bytes = int2bytes(value, asn_len)
        return b'\x02' + ASN1.encode_length(asn_len) + asn_bytes

    @staticmethod
    def encode_octet(octet):
        ''' 按ASN.1 BER规则编码Octet '''
        return b'\x04' + ASN1.encode_length(len(octet)) + octet

    @staticmethod
    def encode_sequence(*args):
        ''' 按ASN.1 BER规则编码序列 '''
        asn_bytes = b''.join(args)
        return b'\x30' + ASN1.encode_length(len(asn_bytes)) + asn_bytes

    @staticmethod
    def encode_length(length):
        ''' 按ASN.1 BER规则编码字段长度 '''
        if length < 0x80:
            return int2bytes(length, 1)
        lenlen = length.bit_length() + 7 >> 3
        return int2bytes(0x80 + lenlen, 1) + int2bytes(length, lenlen)

    @staticmethod
    def decode_int(data):
        ''' 按ASN.1 BER规则解码整数 '''
        if data[0] != 2:
            raise ASN1Error('Integer tag error: ' + data[0])
        asn_len, data = ASN1.decode_length(data[1:])
        if len(data) < asn_len:
            raise ASN1Error('Integer length error.')
        return bytes2int(data[:asn_len]), data[asn_len:]

    @staticmethod
    def decode_octet(data):
        ''' 按ASN.1 BER规则解码Octet '''
        if data[0] != 4:
            raise ASN1Error('Octet tag error: ' + data[0])
        asn_len, data = ASN1.decode_length(data[1:])
        if len(data) < asn_len:
            raise ASN1Error('Octet length error.')
        return data[:asn_len], data[asn_len:]

    @staticmethod
    def decode_sequence(data):
        ''' 按ASN.1 BER规则解码序列 '''
        if data[0] != 0x30:
            raise ASN1Error('Sequence tag error: ' + data[0])
        asn_len, data = ASN1.decode_length(data[1:])
        if len(data) < asn_len:
            raise ASN1Error('Sequence length error.')
        return data[:asn_len], data[asn_len:]

    @staticmethod
    def decode_length(data):
        ''' 按ASN.1 BER规则解码长度字段 '''
        length = data[0]
        if length < 128:
            return length, data[1:]
        if length == 128:
            raise ASN1Error('Indefinite length not supported.')
        pos = length - 127
        length = bytes2int(data[1:pos])
        return length, data[pos:]


def int2bytes(value, length):
    ''' Convert Integer to Bytes '''
    return value.to_bytes(length, 'big')

def bytes2int(bytestr):
    ''' Convert Bytes to Integer '''
    return int.from_bytes(bytestr, 'big')

def bitxor(data1, data2):
    ''' Xor Byte to Byte '''
    return bytes(a ^ b for a, b in zip(data1, data2))
