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
          packages=["sm2"],
          requires=["sm3"]
    )

if __name__ == "__main__":
    main()
