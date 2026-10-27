PYTHON ?= python3
EVIDENCE_ROOT ?= $(HOME)/.local/state/wirevpn-harness
TOOLCHAIN ?=
SHELL_LINT_TOOLS ?= $(HOME)/.cache/wirevpn-harness/shell-lint
RUNNER := tests/harness/run.py
SHELL_LINT := tests/harness/shell_lint.py
TOOLCHAIN_FLAG = $(if $(strip $(TOOLCHAIN)),--toolchain "$(TOOLCHAIN)",)

.PHONY: verify-harness verify-vectors verify-bash-static verify-shell-lint characterize-bash verify-public rebind

verify-harness: verify-vectors
	$(PYTHON) $(RUNNER) self-test --evidence-root "$(EVIDENCE_ROOT)" $(TOOLCHAIN_FLAG)

verify-vectors:
	$(PYTHON) $(RUNNER) validate --evidence-root "$(EVIDENCE_ROOT)" $(TOOLCHAIN_FLAG)

verify-bash-static:
	$(PYTHON) $(RUNNER) static --evidence-root "$(EVIDENCE_ROOT)" $(TOOLCHAIN_FLAG)

verify-shell-lint:
	$(PYTHON) $(SHELL_LINT) provision --output-dir "$(SHELL_LINT_TOOLS)"
	$(PYTHON) $(SHELL_LINT) check --tool-dir "$(SHELL_LINT_TOOLS)"

characterize-bash:
	$(PYTHON) $(RUNNER) characterize --evidence-root "$(EVIDENCE_ROOT)" $(TOOLCHAIN_FLAG)

verify-public: verify-bash-static verify-shell-lint
	git diff --check
	git diff --cached --check

rebind:
	$(PYTHON) $(RUNNER) rebind
