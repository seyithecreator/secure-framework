from setuptools import setup, find_packages

setup(
    name="secure_framework",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "flask",
        "flask-sqlalchemy",
        "flask-security-too",
        "flask-talisman",
        "flask-limiter",
        "flask-wtf",
        "cryptography",
        "pyOpenSSL",
        "pyftpdlib",
        "paramiko",
        "python-decouple",
        "marshmallow",
        "waitress; sys_platform == 'win32'",
        "python-dotenv",
        "reportlab"
    ],
    entry_points={
        'console_scripts': [
            'secure-framework=main:main',
        ],
    },
)
