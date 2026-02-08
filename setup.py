from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="vulncheck",
    version="1.0.0",
    author="VulnCheck Team",
    author_email="security@vulncheck.com",
    description="Advanced Web Vulnerability Scanner with AI-Powered Analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/vulncheck",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "vulncheck=main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "vulncheck": [
            "*.md",
            "*.txt",
            "*.yml",
            "*.yaml",
        ],
    },
    keywords=[
        "vulnerability scanner",
        "web security",
        "OWASP Top 10",
        "XSS detection",
        "SQL injection",
        "security headers",
        "SSL/TLS scanner",
        "CSRF detection",
        "open redirect",
        "AI analysis",
        "penetration testing",
        "security auditing",
        "cybersecurity",
    ],
    project_urls={
        "Bug Reports": "https://github.com/yourusername/vuln-check/issues",
        "Source": "https://github.com/yourusername/vuln-check",
        "Documentation": "https://github.com/yourusername/vuln-check/wiki",
    },
)