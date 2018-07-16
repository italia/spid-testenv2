FROM python:3.5

# Install prerequisites
RUN apt-get update -y && apt-get install -y xmlsec1 libffi6

# We copy just the requirements.txt first to leverage Docker cache
# (avoid rebuilding the requirements layer when application changes)
COPY ./requirements.txt /app/requirements.txt
WORKDIR /app
RUN pip install -r requirements.txt

# Copy the full application in a single layer
COPY . /app

EXPOSE 8088
VOLUME /app/conf

ENTRYPOINT ["python"]
CMD ["spid-testenv.py"]
