FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /opt/agents/intake/code_review /opt/agents/lib
COPY config.py /opt/agents/lib/config.py
EXPOSE 5009
CMD ["python", "app.py"]
