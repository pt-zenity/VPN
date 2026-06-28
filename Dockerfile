# ── Etapa de construcción: instala las dependencias en un venv aislado ──────
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src

# Solo el manifiesto primero, para aprovechar la caché de capas.
COPY pyproject.toml README.md ./
COPY vpn_manager/ ./vpn_manager/
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install .

# ── Etapa de ejecución: imagen mínima, usuario sin privilegios ──────────────
FROM python:3.12-slim AS runtime

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    VPNM_HOST=0.0.0.0 \
    VPNM_PORT=8200

# Usuario sin privilegios.
RUN useradd --create-home --uid 10001 vpnm

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY vpn_manager/ ./vpn_manager/
COPY sandbox/ ./sandbox/
COPY pyproject.toml README.md ./

# El usuario necesita escribir en sandbox (datos de demo: usuarios, auditoría…).
RUN chown -R vpnm:vpnm /app/sandbox
USER vpnm

EXPOSE 8200
HEALTHCHECK --interval=30s --timeout=4s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8200/health',timeout=3).status==200 else 1)"

CMD ["python", "-m", "vpn_manager"]
