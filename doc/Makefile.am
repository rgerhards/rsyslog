# Automake integration for Sphinx documentation builds

SPHINXBUILD = @SPHINXBUILD@
SPHINXOPTS = @SPHINXOPTS@
O =

SPHINX_SOURCE = $(srcdir)/source
SPHINX_BUILDDIR = $(builddir)/build

.PHONY: doc-help doc-clean doc-html doc-singlehtml doc-json doc-alljson html singlehtml json alljson help

doc-help:
	@$(SPHINXBUILD) -M help "$(SPHINX_SOURCE)" "$(SPHINX_BUILDDIR)" $(SPHINXOPTS) $(O)

doc-clean:
	rm -rf "$(SPHINX_BUILDDIR)"

doc-html:
	@$(SPHINXBUILD) -M html "$(SPHINX_SOURCE)" "$(SPHINX_BUILDDIR)" $(SPHINXOPTS) $(O)

doc-singlehtml:
	@$(SPHINXBUILD) -M singlehtml "$(SPHINX_SOURCE)" "$(SPHINX_BUILDDIR)" -t minimal_build $(SPHINXOPTS) -D rst_epilog='' $(O)
	@echo
	@echo "Build finished. The minimal single page HTML is in $(SPHINX_BUILDDIR)/singlehtml."

doc-json:
	@$(SPHINXBUILD) -b json "$(SPHINX_SOURCE)" "$(SPHINX_BUILDDIR)/json" $(SPHINXOPTS) $(O)

doc-alljson: doc-json
	@$(SPHINXBUILD) -b json "$(SPHINX_SOURCE)" "$(SPHINX_BUILDDIR)" $(SPHINXOPTS) $(O)

doc-%:
	@$(SPHINXBUILD) -M $* "$(SPHINX_SOURCE)" "$(SPHINX_BUILDDIR)" $(SPHINXOPTS) $(O)

html: doc-html
singlehtml: doc-singlehtml
json: doc-json
alljson: doc-alljson
help: doc-help

clean-local: doc-clean
