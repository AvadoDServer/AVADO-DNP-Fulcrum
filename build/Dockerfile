# AVADO Electrum Server image: Fulcrum plus the AVADO status page.
#
# Build context is the repository root (docker-compose.yml: context ".",
# dockerfile "build/Dockerfile"), so the image can read the package version
# from dappnode_package.json. See /.dockerignore for what is sent.

# Fulcrum's own image (Debian 13), pinned by digest (multi-arch index digest).
# Update tag and digest together: `docker buildx imagetools inspect
# cculianu/fulcrum:<tag>` ("Digest:" line).
ARG FULCRUM_IMAGE=cculianu/fulcrum:v2.1.4@sha256:3de5dc10d6fd331a61adf54bc238bc01d1fc9618f2f763e2454e21b4e6d888b1

FROM --platform=linux/amd64 ${FULCRUM_IMAGE}
# python3 and openssl are already in the image. libcap2-bin only to give python
# the right to open port 80 without root (file capability), then removed.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libcap2-bin tini \
    && setcap cap_net_bind_service=+ep "$(readlink -f /usr/bin/python3)" \
    && getcap "$(readlink -f /usr/bin/python3)" | grep -q cap_net_bind_service \
    && apt-get purge -y libcap2-bin && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* \
    && Fulcrum --version | head -1

COPY build/app /app
COPY dappnode_package.json /tmp/dappnode_package.json
RUN python3 -c 'import json,re; v=json.load(open("/tmp/dappnode_package.json"))["version"]; \
assert re.fullmatch(r"[0-9A-Za-z.+-]+", v), "bad package version"; open("/app/package-version","w").write(v+"\n")' \
    && rm /tmp/dappnode_package.json \
    && cd /app && python3 -m unittest discover -s tests -q \
    && rm -rf /app/tests /app/__pycache__ \
    && useradd --uid 1000 --create-home --shell /usr/sbin/nologin fulcrum \
    && mkdir -p /data && chown fulcrum:fulcrum /data

USER fulcrum
ENV DATA_DIR=/data PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
VOLUME /data
EXPOSE 80 50001 50002
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python3", "/app/main.py"]
