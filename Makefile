.PHONY: clean-pyc clean-build docs clean local-setup

help:
	@echo "clean - remove all build, test, coverage and Python artifacts"
	@echo "clean-build - remove build artifacts"
	@echo "clean-pyc - remove Python file artifacts"
	@echo "clean-test - remove test and coverage artifacts"
	@echo "lint - check style with flake8"
	@echo "bandit - check security with bandit"
	@echo "format - reformat code with black and isort"
	@echo "check-format - check code format/style with black and isort"
	@echo "test - run tests quickly with the default Python"
	@echo "test-all - run tests on every Python version with tox"
	@echo "coverage - check code coverage quickly with the default Python"
	@echo "docs - generate Sphinx HTML documentation, including API docs"
	@echo "release - package and upload a release"
	@echo "dist - package"
	@echo "sync-deps - save dependencies to requirements.txt"
	@echo "local-setup - sets up a linux or macos local directory for contribution by installing poetry and requirements"

clean: clean-build clean-pyc clean-test clean-docs

clean-build:
	rm -fr build/
	rm -fr dist/
	rm -fr *.egg-info

clean-docs:
	rm -fr docs/_build/
	rm -fr docs/_diagrams/

clean-pyc:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

clean-test:
	rm -fr .tox/
	rm -f .coverage
	rm -fr htmlcov/
	rm -fr .pytest_cache

lint:
	flake8 panos tests

bandit:
	bandit -r --ini .bandit

format:
	isort --atomic panos
	black .

check-format:
	isort --atomic --check-only panos
	black --check --diff .

test:
	pytest

test-simple:
	pytest --disable-warnings

test-all:
	tox

coverage:
	pytest --cov=panos

docs: clean-docs
	$(MAKE) -C docs html
	open docs/_build/html/index.html

release: clean
	python setup.py sdist upload
	python setup.py bdist_wheel upload

dist: clean
	python setup.py sdist
	python setup.py bdist_wheel
	ls -l dist

sync-deps:
	poetry export -f requirements.txt > requirements.txt
	poetry2setup > setup.py
	black setup.py

local-setup:
ifeq ($(wildcard ~/.local/bin/poetry),)
	@echo "installing poetry"
	curl -sSL https://install.python-poetry.org | python3 -
else
	@echo "poetry installation found"
endif
	~/.local/bin/poetry install

	
