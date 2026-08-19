from setuptools import setup, find_packages

setup(
    name="social-recon",
    version="2.0.0",
    description="Advanced OSINT reconnaissance framework with strong Iranian platform coverage",
    author="Erfix404",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.11",
    install_requires=[
        "httpx[socks]>=0.27.0",
        "requests>=2.31.0",
        "phonenumbers>=8.13.0",
        "dnspython>=2.6.0",
        "fake-useragent>=1.5.0",
    ],
    entry_points={
        "console_scripts": [
            "social-recon=social_recon.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
    ],
)
