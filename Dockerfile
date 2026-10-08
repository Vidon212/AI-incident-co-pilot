# syntax=docker/dockerfile:1
FROM python:3.13-slim AS builder
WORKDIR /build
COPY pyproject.toml requirements.txt LICENSE README.md ./
COPY src/incident_copilot ./src/incident_copilot
RUN python -m pip wheel --no-cache-dir --no-deps --wheel-dir /wheels -r requirements.txt

FROM python:3.13-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
COPY --from=builder /wheels /wheels
RUN python -m pip install --no-cache-dir --no-index --no-deps /wheels/*.whl \
    && rm -rf /wheels
COPY examples ./examples
USER 10001:10001
ENTRYPOINT ["python", "-m"]
CMD ["incident_copilot", "--context", "examples/checkout_503_context.json", "--diagnosis", "examples/checkout_503_diagnosis.json"]
