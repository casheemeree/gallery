FROM python:3.14-slim

WORKDIR /app
COPY . .

ENV HOST=0.0.0.0 PORT=8080
EXPOSE 8080

CMD ["python", "server.py"]
