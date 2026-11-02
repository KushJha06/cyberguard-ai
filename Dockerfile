FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .
RUN mkdir -p data/runtime data/uploads
EXPOSE 8000
CMD ["uvicorn", "cyberguard.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
