PYTHON ?= python

.PHONY: help setup pull ingest reseed attack report app test clean

help:
	@echo "Targets:"
	@echo "  setup    Install Python dependencies"
	@echo "  pull     Pull required Ollama models (llama3.1, nomic-embed-text)"
	@echo "  ingest   Build the Chroma vector store from data/corpus"
	@echo "  reseed   Regenerate canary tokens in the confidential doc"
	@echo "  attack   Run the full red-team harness (both modes) + report + charts"
	@echo "  report   Rebuild report.csv + charts from the latest run (no LLM calls)"
	@echo "  app      Launch the Streamlit app"
	@echo "  test     Run the unit tests"
	@echo "  clean    Remove the vector store and generated results"

setup:
	$(PYTHON) -m pip install -r requirements.txt

pull:
	ollama pull llama3.1
	ollama pull nomic-embed-text

ingest:
	$(PYTHON) -m src.rag.ingest

reseed:
	$(PYTHON) -c "from src.common.canary import reseed_confidential_doc as r; print(r())"

attack:
	$(PYTHON) -m src.redteam.runner

report:
	$(PYTHON) -m src.redteam.evaluator

app:
	$(PYTHON) -m streamlit run src/app/streamlit_app.py

test:
	$(PYTHON) -m pytest -q

clean:
	rm -rf .chroma results/runs/*.jsonl results/report.csv results/charts/*.png
