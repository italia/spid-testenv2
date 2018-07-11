FROM python:3.5
RUN apt-get update -y && apt-get install -y xmlsec1 libffi6
COPY ./requirements.txt /app/requirements.txt
WORKDIR /app
RUN pip install -r requirements.txt
COPY . /app
ENTRYPOINT ["python"]
CMD ["spid-testenv.py"]
