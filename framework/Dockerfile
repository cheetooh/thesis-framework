# GenAI DAST framework — published to GHCR and run by the target's CI pipeline.
FROM python:3.11-slim

WORKDIR /app

# Ground truth travels with the image so the scanner is self-contained.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY genai_dast ./genai_dast

# OPENAI_API_KEY is provided at runtime (CI secret). OPENAI_MODEL is overridable.
ENV OPENAI_MODEL=gpt-4o
ENV PYTHONUNBUFFERED=1

# Args after the image name go to the scanner, e.g.:
#   docker run --rm -e OPENAI_API_KEY ghcr.io/<owner>/thesis-framework \
#       --target http://host:5002 --mode vulnerable --out /work
ENTRYPOINT ["python", "-m", "genai_dast.scan"]
