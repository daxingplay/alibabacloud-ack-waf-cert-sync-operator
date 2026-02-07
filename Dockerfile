FROM flant/shell-operator:latest

# Install system dependencies
RUN apk add --no-cache bash openssl jq curl

# Install Alibaba Cloud CLI
RUN curl -L https://aliyuncli.alicdn.com/aliyun-cli-linux-latest-amd64.tgz -o aliyun.tgz \
    && tar -xvzf aliyun.tgz \
    && mv aliyun /usr/local/bin/ \
    && rm aliyun.tgz

# Copy the parameterized script
COPY sync-cert.sh /hooks/sync-cert.sh
RUN chmod +x /hooks/sync-cert.sh