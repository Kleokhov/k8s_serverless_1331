# Serverless Control Plane Pipeline

This path runs a Lambda apiserver plus the Lambda scheduler/dispatcher/controllers
with EC2 worker nodes. The EC2 nodes run only kubelet/containerd; they do not need
an EC2 control-plane node.

Script layout (after the recent reorg):

```
scripts/
├── deploy_lambda_apiserver.sh          # step 1: apiserver stack + Dynamo + SSM + seed
├── deploy_lambda_scheduler.sh          # step 2: scheduler/dispatcher/controllers stack
├── deploy_serverless_kubelet.sh        # step 3: provision EC2 workers + install kubelet
├── deploy_serverless_pipeline.sh       # one-shot wrapper for steps 1+2 (+ optional seed)
├── precreate_dynamo_tables.sh          # helper called by the apiserver deploy
├── seed_lambda_apiserver_raw.sh        # helper called by the apiserver deploy
├── _ec2_bootstrap/                     # per-node install scripts copied onto workers
├── ec2_k8s/                            # non-serverless kubeadm path (not used here)
├── local/                              # local-only dev flows (not used here)
└── shutdown/
    ├── shutdown_serverless.sh          # apiserver | scheduler | workers | all
    └── shutdown_ec2_partial_cluster.sh # older kubeadm cluster teardown
```

## 1. Deploy the Lambda apiserver

```bash
AWS_REGION=us-east-1 \
SERVERLESS_RESOURCE_PREFIX=ctrlless-serverless \
./scripts/deploy_lambda_apiserver.sh
```

This script:

- precreates the DynamoDB tables used by the apiserver storage backend
  (via `scripts/precreate_dynamo_tables.sh`)
- builds and deploys `lambda/cmd/apiserver` via SAM
- writes `_serverless_out/lambda-apiserver.kubeconfig`
- publishes that kubeconfig to SSM as `/${SERVERLESS_RESOURCE_PREFIX}/admin-kubeconfig`
- seeds `default`, `kube-system`, `kube-public`, and `kube-node-lease`

The seed step uses raw Kubernetes REST endpoints through
`scripts/seed_lambda_apiserver_raw.sh`. It intentionally avoids `kubectl apply`
because kubectl performs discovery/OpenAPI calls even with validation disabled,
and discovery can fail in this handler-only apiserver MVP.

If the stack already deployed and only the seed step failed, resume with:

```bash
AWS_REGION=us-east-1 \
SERVERLESS_RESOURCE_PREFIX=ctrlless-serverless \
./scripts/deploy_lambda_apiserver.sh --seed-only
```

## 2. Deploy scheduler, dispatcher, and controllers

```bash
AWS_REGION=us-east-1 \
SERVERLESS_RESOURCE_PREFIX=ctrlless-serverless \
./scripts/deploy_lambda_scheduler.sh
```

The scheduler stack reads the same full kubeconfig from SSM and deploys the
dispatcher, scheduler (`ScheduleOneFunction` + `BinderFunction`), backoff-flush,
unschedulable-flush, pod GC controller, job controller, TTL-after-finished
controller, and namespace controller.

## 3. Create and bootstrap EC2 workers

By default this creates two `t3.large` Ubuntu workers, writes
`_serverless_out/workers.env`, builds the patched kubelet/kubectl, and installs
the serverless kubelet on both nodes:

```bash
AWS_REGION=us-east-1 \
SERVERLESS_RESOURCE_PREFIX=ctrlless-serverless \
./scripts/deploy_serverless_kubelet.sh \
  --identity-file ~/.ssh/your-key.pem
```

To change the worker count or type:

```bash
./scripts/deploy_serverless_kubelet.sh \
  --workers 3 \
  --instance-type t3.xlarge \
  --identity-file ~/.ssh/your-key.pem
```

To reuse existing standalone EC2 workers, pass each public IP or DNS name:

```bash
./scripts/deploy_serverless_kubelet.sh \
  --host 203.0.113.10 \
  --host 203.0.113.11 \
  --identity-file ~/.ssh/your-key.pem \
  --kubeconfig _serverless_out/lambda-apiserver.kubeconfig \
  --node-prefix ctrlless-worker
```

To reuse workers described by an env file, pass that env file. This works with
the `_serverless_out/workers.env` file written by step 3, and also with the
older `scripts/ec2_k8s/aws_setup.sh` `_ec2_out/cluster.env` file:

```bash
./scripts/deploy_serverless_kubelet.sh \
  --skip-provision \
  --cluster-env _serverless_out/workers.env
```

The worker bootstrap (from `scripts/_ec2_bootstrap/bootstrap_serverless_worker.sh`)
installs containerd, CNI bridge plugins, the patched kubelet and kubectl, and
configures kubelet to use the Lambda apiserver kubeconfig directly. It does not
use kubeadm bootstrap or certificate rotation.

## 4. Verify

```bash
kubectl --kubeconfig _serverless_out/lambda-apiserver.kubeconfig \
  get --raw /api/v1/namespaces

kubectl --kubeconfig _serverless_out/lambda-apiserver.kubeconfig \
  get --raw /api/v1/nodes

kubectl --kubeconfig _serverless_out/lambda-apiserver.kubeconfig \
  get --raw /api/v1/namespaces/default/pods
```

Expected MVP limits: no watch support, no kube-controller-manager, no kube-proxy,
no CoreDNS unless you add those pieces separately, and no guarantee that kubectl
commands requiring discovery work yet. This is enough for typed clients and raw
REST calls to create pods, for the Lambda scheduler to bind them, and for patched
kubelets to poll the Lambda apiserver for assigned pods.

## 5. Tear down

Use `scripts/shutdown/shutdown_serverless.sh`. Modes are idempotent and each
mode cleans up its CloudFormation stack, any associated DynamoDB tables created
outside CloudFormation, CloudWatch `/aws/lambda/<fn>` log groups, the shared
SAM-managed artifact bucket, and local state files under `_serverless_out/`.

```bash
# Nuke everything (workers -> scheduler -> apiserver, safe order):
./scripts/shutdown/shutdown_serverless.sh all -y

# Or tear down a single component:
./scripts/shutdown/shutdown_serverless.sh apiserver -y
./scripts/shutdown/shutdown_serverless.sh scheduler -y
./scripts/shutdown/shutdown_serverless.sh workers   -y
```

Shared VPC/subnet/security-group/IAM-role resources are intentionally NOT
deleted; they are reused across deploys and managed by
`scripts/ec2_k8s/setup_ec2.sh`. Run `./scripts/shutdown/shutdown_serverless.sh --help`
for the full option set (`--keep-dynamo`, `--keep-ssm`, `--keep-log-groups`,
`--keep-sam-bucket`, `--keep-local-files`, custom stack/prefix overrides, etc.).
