# syntax=docker/dockerfile:1

ARG PYTHON_IMAGE=python:3.12-alpine

# --- builder: install the app and its (pure-Python) dependencies into a venv
FROM ${PYTHON_IMAGE} AS builder

WORKDIR /src
COPY pyproject.toml README.md ./
COPY src/ src/

# The venv gets no pip of its own; the builder's pip installs into it.
# Bytecode is compiled here so the read-only runtime doesn't recompile on start.
RUN python -m venv --without-pip /opt/venv \
 && pip --python /opt/venv/bin/python install \
        --no-cache-dir --disable-pip-version-check . \
 && find /opt/venv -depth -type d \( -name tests -o -name test \) -exec rm -rf {} + \
 && python -m compileall -q -j0 /opt/venv

# --- rootfs: base image + venv, minus everything only needed for building
FROM ${PYTHON_IMAGE} AS rootfs

COPY --from=builder /opt/venv /opt/venv
RUN cd /usr/local/lib/python3.12 \
 && rm -rf site-packages/pip* ensurepip idlelib tkinter turtledemo turtle.py \
           lib2to3 pydoc_data __phello__ \
 && rm -f /usr/local/bin/pip* /usr/local/bin/idle* /usr/local/bin/pydoc* \
 && rm -rf /var/cache/apk/* /root/.cache \
 && adduser -D -H -u 1000 -h /app app \
 && install -d -o app -g app /app /app/exports

# --- final: the trimmed filesystem as a single layer
FROM scratch

COPY --from=rootfs / /

ENV PATH=/opt/venv/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=C.UTF-8 \
    TERM=xterm-256color \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
USER app

# Exports land in /app/exports; mount a host directory there to keep them.
VOLUME ["/app/exports"]
ENTRYPOINT ["python", "-m", "dnsviz_tui"]
