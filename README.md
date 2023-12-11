# SM2

国家商用密码算法SM2，纯Python3实现的SM2算法Demo。

## 主要功能

* SM2签名/验签。
* SM2加密/解密。

## 使用样例
```
from sm2 import SM2

private_key = SM2.create_private_key()
public_key = private_key.public_key()
sign_data = '签名/验签测试'.encode()
plaintext = '加密/解密测试'.encode()
mode = 'c1c3c2'  # 支持 c1c2c3, c1c3c2, asn1

sm2_p = SM2(public_key)                # 用于加密/验签
sm2_s = SM2(public_key, private_key)   # 用于解密/签名

# 加密/解密
ciphertext = sm2_p.encrypt(plaintext, mode)
print(sm2_s.decrypt(ciphertext, mode).decode())

# 签名/验签
signed = sm2_s.sign(sign_data)
print(sm2_p.verify(signed, sign_data))
```
