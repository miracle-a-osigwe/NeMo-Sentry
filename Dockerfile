# ==============================================================================
# Stage 1: Build the React 19 + TypeScript + Vite Frontend
# ==============================================================================
FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# ==============================================================================
# Stage 2: Python 3.11 FastAPI Backend + Static Frontend Host
# ==============================================================================
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8001

WORKDIR /app/backend

# Install Python dependencies
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy backend application source
COPY backend/ ./

# Copy built frontend static assets so FastAPI mounts them at "/"
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist

# Expose default port (7860 works automatically on Hugging Face Spaces;
# Railway/Render/Fly override $PORT dynamically via run.py)
EXPOSE 7860 8001

CMD ["python", "run.py"]
