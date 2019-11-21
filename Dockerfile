FROM python:3.5-slim

# Install prerequisites
RUN apt-get update && apt-get install -y ca-certificates xmlsec1 libffi6 \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# We copy just the requirements.txt first to leverage Docker cache
# (avoid rebuilding the requirements layer when application changes)
COPY ./requirements.txt /app/requirements.txt
WORKDIR /app
RUN pip install -r requirements.txt

# Copy the full application in a single layer
COPY . /app

EXPOSE 8088
VOLUME /app/conf

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python", "spid-testenv.py"]
