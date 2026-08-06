.PHONY: install lint test validate matrix package clean

install:
	python3 -m pip install -e '.[dev]'
	ansible-galaxy collection install -r collections/requirements.yml

lint:
	ruff check src tests
	python3 scripts/verify_supply_chain.py
	yamllint config examples inventories kubernetes playbooks roles .github .gitlab-ci.yml
	ansible-lint playbooks roles

format:
	ruff format src tests

test:
	pytest --cov=certweaver --cov-report=term-missing

validate:
	./scripts/validate-all.sh

matrix:
	certweaver matrix

package:
	mkdir -p dist
	git archive --format=tar.gz --prefix=certweaver-v0.1.0/ -o dist/certweaver-v0.1.0.tar.gz HEAD
	git archive --format=zip --prefix=certweaver-v0.1.0/ -o dist/certweaver-v0.1.0.zip HEAD
	cd dist && sha256sum certweaver-v0.1.0.* > SHA256SUMS

clean:
	rm -rf .pytest_cache .ruff_cache .coverage htmlcov build dist *.egg-info src/*.egg-info .certweaver
