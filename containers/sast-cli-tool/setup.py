from setuptools import setup, find_packages

setup(
    name="static_code_analyzer",
    version="0.7.0",
    packages=find_packages(),
    install_requires=[
        "flask==3.1.2",
        "flask-cors==5.0.0",
        "flask-limiter==3.7.0",
        "pyjwt==2.9.0",
        "psycopg2-binary==2.9.9",
        "aiohttp==3.10.5",
        "aiofiles==24.1.0",
        "pyyaml==6.0.2",
        "regex==2024.9.11",
        "tenacity==9.0.0",
        "jsonschema==4.23.0"
    ],
    author="Your Organization",
    author_email="your.email@example.com",
    description="Static Code Analyzer for detecting vulnerabilities",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/static-code-analyzer",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",
)