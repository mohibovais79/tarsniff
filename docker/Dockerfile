# GuardDog scanner image. Samples are mounted read-only and scanned with no network.
FROM python:3.13-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir guarddog==3.2.0 \
 && useradd -m -u 10001 scanner \
 && R=$(python -c "import os,importlib.util as u;print(os.path.join(os.path.dirname(u.find_spec('guarddog').origin),'analyzer/metadata/resources'))") \
 && chown -R scanner "$R"

USER scanner
# Prime the popular-package caches (typosquatting lists) while network is available at build time.
RUN guarddog --version
WORKDIR /home/scanner
ENTRYPOINT ["guarddog"]
