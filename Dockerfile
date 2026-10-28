# syntax=docker/dockerfile:1
FROM rust:1.90.0-slim-bookworm@sha256:64232e656c058f4468e8d024e990acff04f0fd5a5c0a88a574dc37773d7325c9 AS rust-toolchain

FROM python:3.13.11-slim-bookworm@sha256:20080e807bfc404f8450b185cf0fc95d553462673598549613735f70a5b4d5d0 AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 CARGO_HOME=/usr/local/cargo RUSTUP_HOME=/usr/local/rustup
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl xz-utils bzip2 util-linux gcc g++ make git \
    libstdc++6 libgcc-s1 libfontconfig1 fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*
COPY --from=rust-toolchain /usr/local/cargo /usr/local/cargo
COPY --from=rust-toolchain /usr/local/rustup /usr/local/rustup
ENV PATH=/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin
WORKDIR /opt/camact
COPY locks/requirements-runtime.lock locks/requirements-bootstrap.lock /tmp/
RUN python -m pip install --no-compile --require-hashes -r /tmp/requirements-bootstrap.lock \
    && python -m pip install --no-compile --require-hashes -r /tmp/requirements-runtime.lock \
    && python -m pip check
COPY . /opt/camact
RUN bash scripts/install-runtimes.sh && python scripts/build-codecs.py \
    && rm -rf .tools/_install-cache /root/.npm /root/.cache
RUN python -m compileall -q benchmark harness evaluation camact_eval camact_harness release deployment \
    && python -c 'from evaluation.camact_eval.environment import evaluation_environment; evaluation_environment(require_formal=True)' \
    && find . -type d -name __pycache__ -prune -exec rm -rf {} +

FROM python:3.13.11-slim-bookworm@sha256:20080e807bfc404f8450b185cf0fc95d553462673598549613735f70a5b4d5d0 AS runner
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates util-linux procps libstdc++6 libgcc-s1 libfontconfig1 fonts-dejavu-core \
    ripgrep=13.0.0-4+b2 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 camact && useradd -u 10001 -g 10001 -M -d /run/camact/home camact
COPY --from=build /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=build /opt/camact /opt/camact
WORKDIR /opt/camact
RUN for member in tasks users runtime environment benchmark_manifest.json checksums.json release_manifest.json tasks.jsonl task.schema.json; do \
      ln -s /run/camact/benchmark/$member /opt/camact/benchmark/$member; \
    done \
    && ln -s /usr/local/bin/python3 /usr/bin/python3 \
    && mkdir -p /var/lib/camact /run/camact \
    && chown 10001:10001 /var/lib/camact /run/camact \
    && chmod -R a+rX /opt/camact
ARG VERSION=local
ARG SOURCE_REVISION=source-snapshot
LABEL org.opencontainers.image.title="CamAct" \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$SOURCE_REVISION
ENV CAMACT_DATA_ROOT=/var/lib/camact CAMACT_RESULTS_ROOT=/var/lib/camact/results \
    CAMACT_SCRATCH_ROOT=/var/lib/camact/scratch CAMACT_GVISOR_STATE_ROOT=/var/lib/camact/scratch/gvisor \
    CAMACT_OPENCLAW_TMPDIR=/run/camact/openclaw \
    HF_HOME=/var/lib/camact/cache/huggingface HF_XET_CACHE=/var/lib/camact/cache/huggingface/xet \
    HF_HUB_DISABLE_IMPLICIT_TOKEN=1 HF_HUB_DISABLE_TELEMETRY=1 HF_HUB_DISABLE_PROGRESS_BARS=1 \
    CAMACT_IMAGE_VERSION=$VERSION CAMACT_SOURCE_REVISION=$SOURCE_REVISION \
    CAMACT_TEST_OUTPUT=/tmp/camact-tests CAMACT_TEST_ARCHIVE=/tmp/camact-tests \
    HOME=/run/camact/home PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    PYTHONPATH="/opt/camact:/opt/camact/benchmark:/opt/camact/deployment:/opt/camact/harness/camact_multi_harness_v1:/opt/camact/harness/claude code:/opt/camact/harness/baseline harness" \
    PATH=/opt/camact/.tools/node/bin:/usr/local/bin:/usr/bin:/bin
USER 10001:10001
ENTRYPOINT ["python", "-B", "-m", "release.runner"]
CMD ["check"]
