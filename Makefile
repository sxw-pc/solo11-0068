PYTHON ?= python

.PHONY: test demo serve lint fixtures clean

test:
	$(PYTHON) -m pytest -q

demo:
	$(PYTHON) -m webvault demo --out build/demo

serve:
	$(PYTHON) -m webvault serve --db build/demo/index.sqlite3

lint:
	$(PYTHON) -m compileall -q src scripts tests
	$(PYTHON) -m webvault --help

fixtures:
	PYTHONPATH=src $(PYTHON) scripts/gen_fixtures.py
	PYTHONPATH=src $(PYTHON) scripts/gen_broken.py

clean:
	rm -rf build .pytest_cache
