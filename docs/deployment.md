# Deployment

## Local workstation

Run FastAPI on port 8000 and Streamlit on port 8501. This is the recommended MVP mode.

## Docker Compose

`docker compose up --build` starts both services and mounts `./data` into the API container.

## Production considerations

The MVP has no authentication. A production deployment requires an authenticated reverse proxy, TLS, network restrictions, durable encrypted storage, secrets management, audit logging, backups, retention policy, observability, dependency scanning, and tested recovery. Run containers as non-root and pin reviewed image digests.
