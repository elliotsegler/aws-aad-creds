TESTS=tests/unit
MODULE=aws_aad_creds/

PE?=pipenv run
PY?=$(PE) python

check:
	###### FLAKE8 #####
	# No unused imports, no undefined vars
	$(PE) flake8 --ignore=E731,W503 --exclude compat.py --max-complexity 10 $(MODULE)
	$(PE) flake8 $(TESTS)
	# Proper docstring conventions according to pep257
	# $(PE) pydocstyle --add-ignore=D100,D101,D102,D103,D104,D105,D204,D301 $(MODULE)

pylint:
	$(PE) pylint --rcfile .pylintrc $(MODULE)

test:
	$(PE) py.test -v $(TESTS)

coverage:
	$(PE) py.test --cov $(MODULE) --cov-report term-missing $(TESTS) --cov-report=xml

htmlcov:
	$(PE) py.test --cov $(MODULE) --cov-report html $(TESTS)
	rm -rf /tmp/htmlcov && mv htmlcov /tmp/
	open /tmp/htmlcov/index.html

prcheck: check pylint test

build:
	$(PY) setup.py sdist bdist_wheel

publish:
	$(PE) twine upload dist/*