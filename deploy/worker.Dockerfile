# BuildKit is required for the transient CA mount. No credentials enter layers.
# Multi-architecture official Python 3.12.15 image index observed 2026-10-15 UTC.
FROM python:3.12.15-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --chmod=0444 requirements.lock /app/requirements.lock
RUN --mount=type=secret,id=proxy_ca,required=true \
    python -m pip --isolated install --no-cache-dir --disable-pip-version-check \
      --index-url https://pypi.org/simple --cert /run/secrets/proxy_ca \
      --only-binary=:all: --require-hashes -r /app/requirements.lock \
    && python -m pip --isolated check
COPY --chmod=0444 integration/__init__.py integration/client.py integration/live_model.py integration/live_worker.py /app/integration/
COPY --chmod=0444 deploy/agentcore_worker.py /app/deploy/agentcore_worker.py
RUN chmod 0555 /app /app/integration /app/deploy
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python", "-m", "deploy.agentcore_worker"]
