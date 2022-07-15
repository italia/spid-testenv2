FROM python:3.7-slim

# Install prerequisites
RUN apt-get update \
    && apt-get install -y \
        ca-certificates \
        xmlsec1 \
        libffi7 \
        build-essential \
        libpq-dev \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# We copy just the requirements.txt first to leverage Docker cache
# (avoid rebuilding the requirements layer when application changes)
COPY ./requirements.txt /app/requirements.txt
WORKDIR /app
RUN pip install -r requirements.txt

# When started, the container checks for the required configuration files
# and if it can't find them, it uses the example files to make the server
# start.
#
# The example files won't be available if the user rebinds /app/conf,
# so we make a copy somewhere else.
COPY conf/*.example conf/*.example /usr/local/share/spid-testenv2/

# Copy the full application in a single layer
COPY . /app

EXPOSE 8088
VOLUME /app/conf

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python", "spid-testenv.py"]
