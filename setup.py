""" setup tools """
from setuptools import setup
try:
    from Cython.Build import cythonize
    USE_CYTHON = False
except ImportError:
    USE_CYTHON = False

def main():
    """ Entry of script """
    ext_modules = cythonize(
        ['sm2/fieldp.py', 'sm2/curve.py', 'sm2/sm2.py'],
        language_level=3
    ) if USE_CYTHON else None

    setup(
        name="sm2",
        version="1.2.0",
        description="Python interface for the sm2.",
        author="Zhu Junling",
        author_email="zhujunling_nj@qq.com",
        ext_modules=ext_modules,
        packages=["sm2"],
        requires=["sm3"]
    )

if __name__ == "__main__":
    main()
