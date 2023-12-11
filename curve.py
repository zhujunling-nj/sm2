#-*-coding:utf8;-*-
''' 素数域上的椭圆曲线(Curve) '''
from secrets import randbelow
from fieldp import FP


class CurveError(Exception):
    ''' 椭圆曲线错误 '''
    __slots__ = ['coord_x', 'coord_y']

    def __init__(self, coord_x, coord_y):
        super().__init__()
        self.coord_x = coord_x
        self.coord_y = coord_y

    def __str__(self):
        return f'({self.coord_x:#x}, {self.coord_y:#x}) not on the elliptic curve.'


class Curve:
    ''' 素数域上的椭圆曲线计算 '''
    __slots__ = ['coord_x', 'coord_y', 'coord_z']
    P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
    B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
    N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
    GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
    GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
    LEN = (P.bit_length() + 7) >> 3
    CACHE = []

    @classmethod
    def random(cls):
        ''' 随机数发生器 '''
        return 2 + randbelow(cls.N - 2)

    @classmethod
    def create_key_pair(cls):
        ''' 生成私钥, 公钥对 '''
        privatekey  = cls.random()
        publickey = cls.gmul(privatekey)
        return privatekey, publickey

    @classmethod
    def check(cls, coord_x, coord_y):
        ''' 检查(x, y)是否是椭圆曲线上的点 '''
        if coord_x == 0 and coord_y == 0:
            return True
        if not (0 < coord_x < cls.P and 0 < coord_y < cls.P):
            return False
        f_x = ((coord_x*coord_x + cls.A)*coord_x + cls.B) % cls.P
        f_y = coord_y * coord_y % cls.P
        return f_x == f_y

    @classmethod
    def calc_y(cls, coord_x, sign=0):
        ''' 根据x坐标计算y值 '''
        f_x = ((coord_x*coord_x + cls.A)*coord_x + cls.B) % cls.P
        return FP.sqrtp(cls.P, f_x, sign)

    @classmethod
    def from_bytes(cls, data):
        ''' 字节串转换为对象 '''
        len2 = cls.LEN << 1
        if len(data) == len2:
            pk_x = int.from_bytes(data[:cls.LEN], 'big')
            pk_y = int.from_bytes(data[cls.LEN:], 'big')
            return cls(pk_x, pk_y)
        if len(data) == len2 + 1 and data[0] in (4, 6, 7):
            pk_x = int.from_bytes(data[1:cls.LEN+1], 'big')
            pk_y = int.from_bytes(data[cls.LEN+1:], 'big')
            return cls(pk_x, pk_y)
        if len(data) == cls.LEN + 1 and data[0] in (2, 3):
            sign = data[0] & 1
            pk_x = int.from_bytes(data[1:], 'big')
            pk_y = cls.calc_y(pk_x, sign)
            return cls(pk_x, pk_y)
        raise ValueError('Invalid bytes: ' + data.hex())

    def __init__(self, coord_x, coord_y, check=True):
        if check and not self.check(coord_x, coord_y):
            raise CurveError(coord_x, coord_y)
        self.coord_x = coord_x
        self.coord_y = coord_y
        self.coord_z = 1

    @property
    def bytes_x(self):
        ''' 获取x坐标值(bytes) '''
        return self.coord_x.to_bytes(self.LEN, 'big')

    @property
    def bytes_y(self):
        ''' 获取y坐标值(bytes) '''
        return self.coord_y.to_bytes(self.LEN, 'big')

    def __neg__(self):
        ''' 椭圆曲线负值运算 '''
        return self.__class__(self.coord_x, self.P - self.coord_y, False)

    def __sub__(self, other):
        ''' 椭圆曲线减法运算 '''
        return self + (-other)

    def __add__(self, other):
        ''' 椭圆曲线加法运算 '''
        c1x, c1y = self.coord_x, self.coord_y
        c2x, c2y = other.coord_x, other.coord_y
        if c1x == 0 and c1y == 0:
            return other
        if c2x == 0 and c2y == 0:
            return self
        if c1x == c2x and c1y + c2y == self.P:
            return self.ZERO
        scale = FP.divn(self.P, c1x*c1x*3 + self.A, c1y << 1) \
                if c1x == c2x and c1y == c2y else \
                FP.divn(self.P, c2y - c1y, c2x - c1x)
        c3x = (scale*scale - c1x - c2x) % self.P
        c3y = (scale*(c1x - c3x) - c1y) % self.P
        return self.__class__(c3x, c3y, False)

    def __mul__(self, kkk):
        ''' 椭圆曲线倍乘运算 '''
        # GB/T 32918.1 A.3.2 算法二
        kkk %= self.N
        hbits = f'{kkk*3:b}'
        bitlen = len(hbits)
        kbits = f'{kkk:{bitlen}b}'
        negec = self.__neg__()
        result = self.copy()
        for i in range(1, bitlen-1):
            result.fast_double()
            if hbits[i] == '1' and kbits[i] != '1':
                result.fast_add(self)
            elif hbits[i] != '1' and kbits[i] == '1':
                result.fast_add(negec)
        return result.to_affine()

    def __rmul__(self, kkk):
        ''' 椭圆曲线乘法运算, 对象在右侧 '''
        return self * kkk

    def __eq__(self, other):
        ''' 椭圆曲线比较运算 '''
        return self.coord_x == other.coord_x and \
               self.coord_y == other.coord_y

    def __ne__(self, other):
        ''' 椭圆曲线比较运算 '''
        return self.coord_x != other.coord_x or \
               self.coord_y != other.coord_y

    def __str__(self):
        ''' 转换为字符串 '''
        return f'({self.coord_x:#x}, {self.coord_y:#x})'

    __repr__ = __str__

    def __bytes__(self):
        ''' 转换为字节串 '''
        if self.coord_x == 0 and self.coord_y == 0:
            return b'\x00'
        return b'\x04' + self.bytes_x + self.bytes_y

    def to_bytes(self, compress=True):
        ''' 转换为字节串 '''
        if self.coord_x == 0 and self.coord_y == 0:
            return b'\x00'
        return (self.coord_y&1|2).to_bytes(1, 'big') + self.bytes_x \
               if compress else b'\x04' + self.bytes_x + self.bytes_y

    def copy(self):
        ''' 拷贝对象 '''
        newobj = self.__class__(self.coord_x, self.coord_y, False)
        newobj.coord_z = self.coord_z
        return newobj

    def to_affine(self):
        ''' 转换为仿射坐标 '''
        z_inv = FP.invn(self.P, self.coord_z)
        self.coord_x = self.coord_x * z_inv % self.P
        self.coord_y = self.coord_y * z_inv % self.P
        self.coord_z = 1
        return self

    def fast_add(self, other):
        ''' 椭圆曲线标准射影坐标系加运算 '''
        # pylint: disable=too-many-locals
        c1x, c1y, c1z = self.coord_x, self.coord_y, self.coord_z
        c2x, c2y, c2z = other.coord_x, other.coord_y, other.coord_z
        if c1x == 0 and c1y == 0 or c1z == 0:
            self.coord_x = c2x
            self.coord_y = c2y
            self.coord_z = c2z
            return self
        if c2x == 0 and c2y == 0 or c2z == 0:
            return self
        # 射影坐标系计算
        prime = self.P
        tt1 = c1x * c2z % prime
        tt2 = c2x * c1z % prime
        tt3 = (tt1 - tt2) % prime
        tt2 = (tt1 + tt2) % prime
        tt4 = c1y * c2z % prime
        tt5 = (tt4 - c2y * c1z) % prime
        tt6 = c1z * c2z % prime
        tt7 = tt3 * tt3 % prime
        tt8 = tt3 * tt7 % prime
        tt9 = (tt6*tt5*tt5 - tt2*tt7) % prime
        c3x = tt3 * tt9 % prime
        c3y = (tt5*(tt7*tt1 - tt9) - tt4*tt8) % prime
        c3z = tt8 * tt6 % prime
        self.coord_x = c3x
        self.coord_y = c3y
        self.coord_z = c3z
        return self

    def fast_double(self):
        ''' 椭圆曲线标准射影坐标系倍运算 '''
        c1x, c1y, c1z = self.coord_x, self.coord_y, self.coord_z
        # 射影坐标系计算
        prime = self.P
        tt1 = (c1x*c1x*3 + self.A*c1z*c1z) % prime
        tt2 = (c1y * c1z << 1) % prime
        tt3 = c1y * c1y % prime
        tt4 = tt3 * c1x * c1z % prime
        tt5 = tt2 * tt2 % prime
        tt6 = (tt1*tt1 - (tt4 << 3)) % prime
        c3x = tt2 * tt6 % prime
        c3y = (((tt4 << 2) - tt6)*tt1 - tt5*(tt3 << 1)) % prime
        c3z = tt2 * tt5 % prime
        self.coord_x = c3x
        self.coord_y = c3y
        self.coord_z = c3z
        return self

    @classmethod
    def gmul(cls, kkk, affine=True):
        ''' 椭圆曲线基点倍乘运算: G * k '''
        if not cls.CACHE:
            return cls.BASE * kkk
        result = cls.ZERO.copy()
        for i in range(32):
            result.fast_add(cls.CACHE[i][kkk & 0xFF])
            kkk >>= 8
        return result.to_affine() if affine else result

    @classmethod
    def create_cache(cls, base):
        ''' 生成椭圆曲线缓存: 32*256 '''
        cache = []
        base2 = base.copy()
        for i in range(32):
            cache2 = []
            for _ in range(8):
                cache2.append(base2.copy())
                base2.fast_double()
            cache.append([])
            for j in range(256):
                result = cls.ZERO.copy()
                for k in range(8):
                    if j & 1:
                        result.fast_add(cache2[k])
                    if not (j := j >> 1):
                        break
                cache[i].append(result)
        return cache


Curve.BASE = Curve(Curve.GX, Curve.GY, False)
Curve.ZERO = Curve(0, 0, False)
