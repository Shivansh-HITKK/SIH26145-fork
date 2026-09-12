FROM python:3.12-slim

WORKDIR /workspace

COPY backend/pyproject.toml /workspace/backend/pyproject.toml
COPY backend/src /workspace/backend/src

RUN apt-get update \
	&& apt-get install -y --no-install-recommends libpcap0.8 \
	&& rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir -e "./backend[live,ml,appwrite]"

COPY data /workspace/data

CMD ["uvicorn", "sih_detector.api:app", "--app-dir", "backend/src", "--host", "0.0.0.0", "--port", "8000"]