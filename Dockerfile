FROM python:3.7
ADD  requirements.txt ./requirements.txt
RUN pip install -r requirements.txt
ADD  . ./app
WORKDIR /app
EXPOSE 5000:5000
CMD python ./main.py