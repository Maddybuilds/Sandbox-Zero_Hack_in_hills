FROM python:3.13-slim AS base
WORKDIR /app
RUN useradd --uid 10001 --create-home sandbox && mkdir /data && chown sandbox:sandbox /data
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

FROM base AS catalogue
COPY --chown=10001:10001 catalog.py scenarios.py policy.py build_red_catalog.py ./
USER root
RUN python build_red_catalog.py
USER 10001:10001

FROM base AS red
COPY participants.py ./
COPY --from=catalogue /app/red_cases.json ./
CMD ["python", "participants.py", "--role", "red", "--host", "0.0.0.0", "--port", "9000"]

FROM base AS blue
COPY participants.py policy.py ./
CMD ["python", "participants.py", "--role", "blue", "--host", "0.0.0.0", "--port", "9000"]

FROM base AS target
COPY target_worker.py fixture_runtime.py ./
CMD ["python", "target_worker.py", "--host", "0.0.0.0", "--port", "9000"]

FROM base AS gateway
COPY engine.py server.py catalog.py evidence.py scenarios.py policy.py participants.py envfile.py ./
COPY fixture_runtime.py ./
COPY ml_runtime.py ml_lab.py blue_ml.py red_ml.py duel_cases.py models.lock.json ./
COPY proofs.py boundary_probe.py verify_proof.py ./
COPY local_target.py windows_boundary.py ./
COPY web ./web
CMD ["python", "server.py", "--host", "0.0.0.0"]
