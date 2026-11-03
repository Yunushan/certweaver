.PHONY: install lint test validate matrix package clean

install:
	python3 scripts/install-python-deps.py dev --editable
	ansible-galaxy collection install -r collections/requirements.yml

lint:
	ruff check src tests scripts/*.py ci/*.py roles/pki_adapter/files/verify-git-checkout roles/cluster_addons/files/protect-kubeconfig setup.py
	python3 scripts/check-release-workflows.py
	python3 scripts/check-adapter-acquisition.py
	yamllint config examples inventories kubernetes playbooks roles .github .gitlab-ci.yml
	ansible-lint playbooks roles

format:
	ruff format src tests

test:
	pytest --cov=certweaver --cov-report=term-missing
	python3 scripts/check-coverage.py

validate:
	./scripts/validate-all.sh

matrix:
	certweaver matrix

package:
	python3 scripts/build-package.py --commit "$$(git rev-parse HEAD)"
	python3 scripts/check-package-reproducibility.py --commit "$$(git rev-parse HEAD)"
	python3 scripts/check-wheel.py dist/*.whl
	git archive --format=tar.gz --prefix=certweaver-v0.1.0/ -o dist/certweaver-v0.1.0.tar.gz HEAD
	git archive --format=zip --prefix=certweaver-v0.1.0/ -o dist/certweaver-v0.1.0.zip HEAD
	cd dist && sha256sum *.whl *.tar.gz *.zip > SHA256SUMS

clean:
	rm -rf .pytest_cache .ruff_cache .coverage htmlcov build dist *.egg-info src/*.egg-info .certweaver
