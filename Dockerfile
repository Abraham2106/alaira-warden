FROM python:3.12-slim AS builder
WORKDIR /build
COPY pyproject.toml uv.lock ./
RUN pip install --no-cache-dir uv==0.11.3 \
    && uv export --frozen --no-dev --no-emit-project --no-hashes -o requirements.txt \
    && pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt
COPY src ./src
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /wheels .

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels alaira-warden \
    && rm -rf /wheels && useradd --create-home --uid 10001 warden
COPY migrations ./migrations
USER warden
EXPOSE 8000
CMD ["uvicorn", "alaira_warden.main:app", "--host", "0.0.0.0", "--port", "8000"]

