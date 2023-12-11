''' setup tools '''
import sys
from setuptools import setup, Extension

def main():
    ''' Entry of script '''
    setup(name="sm2",
          version="1.1.0",
          description="Python interface for the sm2.",
          author="Zhu Junling",
          author_email="jl.zhu@tom.com",
          py_modules=["sm2", "curve", "fieldp"],
          requires=["sm3"]
    )

if __name__ == "__main__":
    main()
