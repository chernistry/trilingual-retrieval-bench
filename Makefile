# KB: directory of the external search engine (kb_index.py, kb_eval.py); set it on the
# command line or in the environment. PY: Python interpreter that can run the engine.
KB ?=
PY ?= python3
export KB_TABLE := chunks_synth
CORPUS := $(CURDIR)/corpus

.PHONY: check test index eval
check:
	@for f in gold/*.files; do $(PY) tools/check_corpus.py $$(basename $$f .files) || exit 1; done

# Offline: the scrubber's unit tests (needs pytest), then the acceptance check for batches b01..b10.
test:
	cd scrubber && $(PY) -m pytest -q
	@for b in b01 b02 b03 b04 b05 b06 b07 b08 b09 b10; do $(PY) tools/check_corpus.py $$b || exit 1; done

# The corpus goes into its own LanceDB table; the live `chunks` table is never touched.
index:
	@test -n "$(KB)" || { echo "set KB to the search engine directory"; exit 1; }
	$(PY) $(KB)/kb_index.py --root $(CORPUS) --rebuild --report out/index-report.json

gold/all.jsonl: gold/b*.jsonl
	$(PY) tools/merge_gold.py > $@

eval: gold/all.jsonl
	@test -n "$(KB)" || { echo "set KB to the search engine directory"; exit 1; }
	mkdir -p out
	$(PY) $(KB)/kb_eval.py gold --gold gold/all.jsonl --out out/eval-$$(date +%Y%m%d-%H%M).json
