# Build stage: compile the Lambda apiserver binary from the lambda module.
FROM golang:1.24 AS builder

WORKDIR /workspace

COPY kubernetes/ kubernetes/
COPY lambda/ lambda/

WORKDIR /workspace/lambda

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -o /lambda-apiserver \
    ./cmd/apiserver

# Generate service account key pair for token signing in builder stage.
RUN mkdir -p /etc/kubernetes/pki && \
    openssl genrsa -out /etc/kubernetes/pki/sa.key 2048 && \
    openssl rsa -in /etc/kubernetes/pki/sa.key -pubout -out /etc/kubernetes/pki/sa.pub && \
    chmod 0755 /etc/kubernetes /etc/kubernetes/pki && \
    chmod 0644 /etc/kubernetes/pki/sa.key /etc/kubernetes/pki/sa.pub

# Static token auth file used by the generated kubeconfig.
# Format: token,username,uid,"group1,group2"
RUN mkdir -p /etc/kubernetes/auth && \
    printf "devtoken123,lambda-user,uid-lambda,\"system:masters\"\n" > /etc/kubernetes/auth/tokens.csv && \
    chmod 0755 /etc/kubernetes/auth && \
    chmod 0644 /etc/kubernetes/auth/tokens.csv

FROM public.ecr.aws/lambda/provided:al2023 AS runtime

ENV AWS_SDK_LOAD_CONFIG=1 \
    AWS_SHARED_CREDENTIALS_FILE=/root/.aws/credentials \
    AWS_CONFIG_FILE=/root/.aws/config \
    AWS_EC2_METADATA_DISABLED=true

COPY --from=builder /lambda-apiserver ${LAMBDA_RUNTIME_DIR}/bootstrap
COPY --from=builder /etc/kubernetes/pki /etc/kubernetes/pki
COPY --from=builder /etc/kubernetes/auth /etc/kubernetes/auth

CMD ["lambda-apiserver"]
