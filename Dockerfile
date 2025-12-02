FROM golang:1.25-alpine AS builder

RUN apk add --no-cache \
	git \
	build-base \
	libpcap-dev \
	cargo \
	bash \
	perl \
	openssl-dev \
	openssl-libs-static

ENV CGO_ENABLED=1

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
	go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
	go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
	go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest && \
	go install -v github.com/tomnomnom/assetfinder@latest && \
	go install -v github.com/tomnomnom/anew@latest && \
	go install -v github.com/projectdiscovery/notify/cmd/notify@latest

RUN git clone https://github.com/Findomain/Findomain.git /tmp/findomain && \
	cd /tmp/findomain && \
	cargo build --release

FROM python:3.12-alpine

RUN apk add --no-cache \
	ca-certificates \
	libcap \
	libpcap \
	libgcc \
	libstdc++ \
	bash \
	perl \
	git

COPY --from=builder /go/bin/* /usr/local/bin/
COPY --from=builder /tmp/findomain/target/release/findomain /usr/local/bin/

WORKDIR /app

COPY provider-config.yaml /app/
COPY subenum.py /app/
COPY requirements.txt /app/

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "-u", "subenum.py"]
