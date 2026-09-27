FROM python:3.9-slim

ARG maxmind_key=""

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libpcap-dev make patch git qemu-system openvpn binutils iprange wget tar e2tools \
    && git clone --depth 1 https://github.com/radareorg/radare2 /radare2 \
    && /radare2/sys/install.sh \
    && useradd -m lisa \
    && wget -q https://github.com/danieluhricek/linux-images/archive/v1.0.1.tar.gz -O - | tar xz -C /home/lisa \
    && mv /home/lisa/linux-images-1.0.1 /home/lisa/images

COPY --chown=lisa:lisa ./data /home/lisa/data
COPY --chown=lisa:lisa ./docker /home/lisa/docker
COPY --chown=lisa:lisa ./lisa /home/lisa/lisa
COPY --chown=lisa:lisa ./requirements.ixf.txt /home/lisa/requirements.txt

ENV PYTHONPATH=/home/lisa
WORKDIR /home/lisa

RUN pip install --no-cache-dir -r requirements.txt \
    && (iprange -j data/blacklists/* > data/ipblacklist 2>/dev/null || touch data/ipblacklist) \
    && (./docker/worker/maxmind.sh "${maxmind_key}" || true) \
    && apt-get purge -y --auto-remove gcc g++ make patch git \
    && rm -rf /var/lib/apt/lists/* /radare2

CMD ["./docker/worker/init.sh"]
