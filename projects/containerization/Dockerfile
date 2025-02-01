FROM python:3.10
WORKDIR /usr/src/app
COPY requirements.txt ./
RUN pip3 install -r requirements.txt
COPY . .
ENV PORT=8000
ENV GOOGLE_APPLICATION_CREDENTIALS='./baldesc-cs493-p8.json'
EXPOSE ${PORT}
CMD [ "python", "main.py" ]
