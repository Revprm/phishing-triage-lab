.PHONY: demo enrich header test lint clean install help

PY=python3
PIP=pip
SRC=src

help:
	@echo "Phishing Investigation Lab - make targets"
	@echo "  make demo        # mock enrichment on sample IOCs → artifacts/reports/report.md"
	@echo "  make enrich FILE=path  # live enrichment on FILE"
	@echo "  make header FILE=eml   # header forensics on .eml"
	@echo "  make test        # pytest"
	@echo "  make install     # pip install -r requirements.txt"
	@echo "  make lint        # ruff / flake if available"
	@echo "  make clean       # remove reports"
	@echo ""
	@echo "Examples:"
	@echo "  make demo"
	@echo "  make enrich FILE=artifacts/iocs/case-03_confirmed-creds-harvest.txt"
	@echo "  make header FILE=artifacts/headers/case-03_confirmed-creds-harvest.eml"

install:
	$(PIP) install -r requirements.txt

demo:
	@echo ">> Mock enrichment (offline, deterministic) → artifacts/reports/report.md"
	PYTHONPATH=$(SRC) $(PY) enrich.py -f artifacts/iocs/iocs-sample.txt -o artifacts/reports/report.md --mock --json artifacts/reports/report.json --csv artifacts/reports/report.csv
	@echo ">> Done. Highest: $$(grep -m1 'Highest score' artifacts/reports/report.md)"

# Usage: make enrich FILE=artifacts/iocs/case-03_confirmed-creds-harvest.txt
enrich:
ifndef FILE
	@echo "Usage: make enrich FILE=artifacts/iocs/<file>.txt"
	@exit 1
endif
	PYTHONPATH=$(SRC) $(PY) enrich.py -f $(FILE) -o artifacts/reports/$$(basename $(FILE) .txt).md --json artifacts/reports/$$(basename $(FILE) .txt).json --csv artifacts/reports/$$(basename $(FILE) .txt).csv
	@cat artifacts/reports/$$(basename $(FILE) .txt).md | head -20

# Usage: make header FILE=artifacts/headers/sample.eml
header:
ifndef FILE
	@echo "Usage: make header FILE=artifacts/headers/sample.eml"
	@exit 1
endif
	PYTHONPATH=$(SRC) $(PY) -m phishlab.header $(FILE)

test:
	PYTHONPATH=$(SRC) $(PY) -m pytest tests -v

lint:
	@echo ">> lint: ruff if installed, else pyflakes"
	@ruff check $(SRC) enrich.py 2>/dev/null || pyflakes $(SRC) enrich.py 2>/dev/null || echo "No linter found (pip install ruff)"

clean:
	rm -f artifacts/reports/report.md artifacts/reports/report.json artifacts/reports/report.csv
	rm -f artifacts/reports/case-*.md artifacts/reports/case-*.json artifacts/reports/case-*.csv
	@echo "Cleaned artifacts/reports/"
