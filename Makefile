.PHONY: install test lint api ui
install:
	python -m pip install -e ".[dev]"
test:
	pytest
lint:
	ruff check src tests
api:
	uvicorn cyberguard.api.app:app --reload --port 8000
ui:
	streamlit run src/cyberguard/ui/Home.py
