FROM python:3.8.0-alpine

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

ADD ../../requirements.txt ./requirements.txt
ADD ../../ecr-pull.py ./ecr-pull.py
ADD ../../ecr-push.py ./ecr-push.py

RUN apk add --no-cache --virtual .build-deps gcc g++ build-base freetype-dev libpng-dev openblas-dev py3-scipy
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

EXPOSE 80 8080 443

WORKDIR .

ENTRYPOINT ["/bin/project"]
CMD ["-h"]