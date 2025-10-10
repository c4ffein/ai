.PHONY: help lint lint-check test test-readme install-build-system build-package install-package-uploader upload-package-test upload-package

help:
	@echo "ai - Makefile commands"
	@echo "────────────────────────────────────"
	@echo "  make lint              - Fix linting issues with ruff"
	@echo "  make lint-check        - Check linting without fixing"
	@echo "  make test              - Run tests"
	@echo "  make test-readme       - Check README.md usage is up to date"
	@echo "  make install-build-system   - Install build tools"
	@echo "  make build-package     - Build source distribution"
	@echo "  make install-package-uploader - Install twine for uploading"
	@echo "  make upload-package-test - Upload to TestPyPI"
	@echo "  make upload-package    - Upload to PyPI"

lint:
	ruff check --fix; ruff format

lint-check:
	ruff check --no-fix && ruff format --check

test:
	python3 test.py

test-readme:
	@python3 -c '\
import subprocess; \
actual = subprocess.run(["python3", "ai.py"], capture_output=True, text=True).stdout.strip(); \
readme = open("README.md").read(); \
lines = readme.split("\n"); \
in_block = False; \
usage = []; \
[usage.append(l) if in_block and l.strip() != "```" else (in_block := not in_block) for l in lines if l.strip() == "```" or in_block]; \
readme_usage = "\n".join(usage); \
exit(0) if actual == readme_usage else (print("✗ README.md usage section is out of date!"), exit(1))'

install-build-system:
	python3 -m pip install --upgrade build

build-package:
	python3 -m build --sdist

install-package-uploader:
	python3 -m pip install --upgrade twine

upload-package-test:
	python3 -m twine upload --repository testpypi --verbose dist/*

upload-package:
	python3 -m twine upload --verbose dist/*
