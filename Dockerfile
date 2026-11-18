FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TZ=UTC
WORKDIR /app
COPY scanner.py report_server.py notifier.py scan_control.py osv_severity.py /app/
RUN useradd --system --uid 10001 --home-dir /app scanner && mkdir -p /reports && chown -R scanner:scanner /app /reports
USER scanner
VOLUME ["/reports"]
CMD ["python", "-u", "/app/scanner.py"]
