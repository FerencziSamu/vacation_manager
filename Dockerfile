FROM python:alpine3.7
ADD . ./app
WORKDIR /app
RUN pip install -r requirements.txt
EXPOSE 5000:5000
CMD python ./app/main.py