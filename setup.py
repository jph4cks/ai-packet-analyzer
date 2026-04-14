from setuptools import setup, find_packages

setup(
    name="ai-packet-analyzer",
    version="1.0.0",
    description="AI-powered network packet analyzer for connectivity troubleshooting and security auditing",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="AI Packet Analyzer Contributors",
    license="MIT",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.9",
    install_requires=[
        "scapy>=2.5.0",
        "pyshark>=0.6",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "ai-packet-analyzer=ai_packet_analyzer.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
)
