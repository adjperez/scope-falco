# Start from weaveworks/scope, so that we have a docker client built in.
FROM python:3
MAINTAINER Alfonso Perez <adjperez@gmail.com>
LABEL works.weave.role=system

#RUN pip install docker-py
RUN pip install -U docker

# Add our plugin
#ADD ./example.txt example.txt
ADD ./falco-logs.py /usr/bin/falco-logs.py
ENTRYPOINT ["/usr/bin/falco-logs.py"]
