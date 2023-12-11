#-*-coding:utf8;-*-
''' 素数域FP上的数学运算 '''

class FP:
    ''' 素数域上的数学运算 '''
    __slots__ = []
    POW_2_P_4 = {}  # 2**((P-1)/4)  (mod P)
    FACTOR_P1 = {}  # P-1 = S*2^T

    @staticmethod
    def divn(num, aaa, bbb):
        ''' 模除运算 '''
        return aaa * FP.invn(num, bbb) % num

    @staticmethod
    def invn(num, aaa):
        ''' 模逆运算 '''
        if aaa in {0, 1}:
            return aaa
        xxx, yyy = 1, 0
        bbb = num
        while bbb:
            quotient = aaa // bbb
            xxx, yyy = yyy, xxx - quotient*yyy
            aaa, bbb = bbb, aaa - quotient*bbb
        return xxx % num if aaa == 1 else 0

    @staticmethod
    def pown(num, aaa, exp):
        ''' 模快幂运算 '''
        if aaa in {0, 1}:
            return aaa
        result = aaa
        bits = f'{exp:b}'
        for k in bits[1:]:
            result = result * result % num
            if k == '1':
                result = result * aaa % num
        return result

    @staticmethod
    def is_square(num, aaa):
        ''' 判断是否为平方数(模P的二次剩余) '''
        #return aaa in {0, 1} or FP.pown(num, aaa, num >> 1) == 1
        return aaa in {0, 1} or FP.legendre(num, aaa) == 1

    @staticmethod
    def legendre(num, aaa):
        ''' 计算勒让德符号: 二次互反律 '''
        result = 1
        while aaa != 1:
            if aaa == 0:
                return 0
            ttt = 0
            while aaa & 1 == 0:
                aaa >>= 1
                ttt += 1
            if ttt == 0:
                if (aaa >> 1) * (num >> 1) & 1:
                    result = -result
                aaa, num = num % aaa, aaa
            elif ttt & 1 and (num * num - 1) >> 3 & 1:
                result = -result
        return result

    @staticmethod
    def sqrtp(num, aaa, sign=0):
        ''' 素数域上的平方根运算(模P的二次剩余) '''
        if aaa in {0, 1}:
            return aaa
        #if not FP.is_square(num, aaa):
        #    raise ValueError(f'v={aaa} is not square modulo {num})')

        # 算法1: P == 3 (mod 4)
        if num & 3 == 3:
            xxx = FP.pown(num, aaa, (num >> 2) + 1)
            if xxx * xxx % num == aaa:
                return xxx if xxx & 1 == sign else num - xxx
            # 如果前面已判断, 此语句不会执行
            raise ValueError(f'v={aaa} is not square modulo {num})')

        # 算法2: P == 5 (mod 8)
        if num & 7 == 5:
            xxx = FP.pown(num, aaa, (num >> 3) + 1)
            sqrx = xxx * xxx % num
            if sqrx == aaa:
                return xxx if xxx & 1 == sign else num - xxx
            if sqrx == num - aaa:
                if num not in FP.POW_2_P_4:
                    FP.POW_2_P_4[num] = FP.pown(num, 2, num >> 2)
                xxx = xxx * FP.POW_2_P_4[num] % num
                return xxx if xxx & 1 == sign else num - xxx
            # 如果前面已判断, 此语句不会执行
            raise ValueError(f'v={aaa} is not square modulo {num})')

        # 通用算法, 任意奇素数P
        return FP._sqrtp(num, aaa, sign)

    @staticmethod
    def _sqrtp(num, aaa, sign=0):
        ''' Tonelli-Shanks(托内利-尚克斯)算法 '''
        # 提取p-1的所有2因子: p-1 = s*2^t
        if num not in FP.FACTOR_P1:
            ttt = 0
            sss = num - 1
            while sss & 1 == 0:
                sss >>= 1
                ttt += 1
            ttt = ttt - 1
            fff = 1 << ttt
            FP.FACTOR_P1[num] = sss, ttt, fff
        else:
            sss, ttt, fff = FP.FACTOR_P1[num]

        # 找出一个二次非剩余的数
        for ccc in range(2, num):
            if not FP.is_square(num, ccc):
                break

        inv = FP.invn(num, aaa)
        xxx = FP.pown(num, aaa, (sss + 1) >> 1)
        powcs = FP.pown(num, ccc, sss)
        while ttt:
            fff >>= 1
            if FP.pown(num, inv * xxx * xxx % num, fff) != 1:
                xxx = xxx * powcs % num
            if ttt := ttt - 1:
                powcs = powcs * powcs % num

        if xxx * xxx % num == aaa:
            return xxx if xxx & 1 == sign else num - xxx
        # 如果前面已判断, 此语句不会执行
        raise ValueError(f'v={aaa} is not square modulo {num})')
