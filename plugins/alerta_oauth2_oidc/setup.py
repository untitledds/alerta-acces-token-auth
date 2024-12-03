from setuptools import setup, find_packages

setup(
    name="alerta-oauth2-oidc",
    version="0.1.0",
    description="Alerta plugin for OAuth2/OIDC authentication",
    long_description="",
    keywords="alerta, oauth2, oidc, auth, plugin",
    author="untitledds",
    author_email="untitledds@gmail.com",
    url="https://github.com/untitledds/alerta-oauth2-oidc",
    license="MIT",
    include_package_data=True,
    packages=find_packages(exclude=['tests']),
    py_modules=['alerta_oauth2_oidc'],
    install_requires=[
        "requests",
    ],
    classifiers=[
        "Programming Language :: Python",
        "Development Status :: 4 - Beta",
        "Framework :: Flask",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Topic :: Internet :: WWW/HTTP",
    ],
    entry_points={
        'alerta.plugins': [
            'oauth2_oidc = alerta_oauth2_oidc:OAuth2OIDCAuthentication'
        ]
    },
    test_suite='tests'
)