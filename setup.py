from setuptools import setup

with open("README.md", "r") as file:
    long_description = file.read()

VERSION = '1.0.0'
DESCRIPTION = 'Simpler to use implementation of the pycryptodome RSA algorithm'

# Setting up
setup(
    name="rapidrsa",
    version=VERSION,
    license="MIT",
    author="JustScott",
    author_email="<justscottmail@protonmail.com>",
    description=DESCRIPTION,
    long_description_content_type="text/markdown",
    long_description=long_description,
    url = "https://github.com/JustScott/RapidRSA",
    project_urls={
        "Bug Reports":"https://github.com/JustScott/RapidRSA/issues",
    },
    package_dir={"":"src"},
    packages=["rapidrsa"],
    install_requires=['pycryptodome>=3.15.0'],
    keywords=['python','encryption','decryption','cryptography'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.8',
        'Topic :: Security :: Cryptography',
    ]
)
