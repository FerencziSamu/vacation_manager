FROM python:alpine3.7
ADD  . ./app
WORKDIR /app
RUN apk update &&\
    apk add --no-cache --virtual build-deps gcc python3-dev musl-dev &&\
    apk add --no-cache postgresql-dev &&\
   pip install -r requirements.txt &&\
   apk del build-deps
EXPOSE 5000:5000
CMD python ./app/main.py