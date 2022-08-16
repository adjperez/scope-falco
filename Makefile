.PHONY: run clean

SUDO=$(shell docker info >/dev/null 2>&1 || echo "sudo -E")
EXE=falco-logs.py
ORGANIZATION=weaveworksplugins
IMAGE=$(ORGANIZATION)/scope-falco
NAME=$(ORGANIZATION)-scope-falco
UPTODATE=.falco-logs.uptodate

run: $(UPTODATE)
	$(SUDO) docker run --rm --privileged -it \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v /var/run/scope/plugins:/var/run/scope/plugins \
		--name $(NAME) $(IMAGE)

$(UPTODATE): $(EXE) Dockerfile
	$(SUDO) docker build -t $(IMAGE) .
	touch $@

clean:
	- rm -rf $(UPTODATE)
	- $(SUDO) docker rmi $(IMAGE)
