# HoodMe Deployment Guide

## Overview
This document provides comprehensive deployment instructions for HoodMe, covering containerization, Kubernetes orchestration, CI/CD pipelines, and infrastructure setup.

## Prerequisites

### Required Tools
```bash
# Container and orchestration tools
Docker (v20.10+)
Docker Compose (v2.0+)
Kubernetes CLI (kubectl v1.25+)
Helm (v3.10+)

# Cloud CLI tools
AWS CLI (v2.x) / Azure CLI (v2.x)
Terraform (v1.3+)

# Development tools
Node.js (v18+)
npm/yarn
Git
```

### Cloud Resources Setup
```bash
# AWS Resources needed
- EKS Cluster
- RDS PostgreSQL instance
- ElastiCache Redis cluster
- S3 buckets for storage
- CloudFront distribution
- Route53 for DNS
- IAM roles and policies
- Secrets Manager
- Application Load Balancer

# Azure Alternative
- AKS Cluster
- Azure Database for PostgreSQL
- Azure Cache for Redis
- Azure Blob Storage
- Azure CDN
- Azure DNS
- Azure Key Vault
- Azure Application Gateway
```

## Docker Configuration

### Base Dockerfile
```dockerfile
# Multi-stage build for Node.js microservices
FROM node:18-alpine AS base
WORKDIR /app
RUN apk add --no-cache dumb-init

FROM base AS dependencies
COPY package*.json ./
RUN npm ci --only=production --silent

FROM base AS build
COPY package*.json ./
RUN npm ci --silent
COPY . .
RUN npm run build
RUN npm prune --production

FROM base AS runtime
ENV NODE_ENV=production
ENV PORT=3000

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001

# Copy production dependencies and built application
COPY --from=dependencies --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=build --chown=nodejs:nodejs /app/dist ./dist
COPY --from=build --chown=nodejs:nodejs /app/package.json ./

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "const http=require('http');const req=http.request({host:'localhost',port:process.env.PORT,path:'/health',timeout:2000},res=>{process.exit(res.statusCode===200?0:1)});req.on('error',()=>process.exit(1));req.end();"

USER nodejs
EXPOSE 3000

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/index.js"]
```

### Service-Specific Dockerfiles

#### API Gateway Service
```dockerfile
FROM HoodMe/base-node:latest AS base

COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

EXPOSE 3000
CMD ["node", "dist/gateway.js"]
```

#### Messaging Service (with Socket.io)
```dockerfile
FROM HoodMe/base-node:latest AS base

COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

# Messaging service needs sticky sessions
EXPOSE 3004
CMD ["node", "dist/messaging-server.js"]
```

### Docker Compose for Local Development
```yaml
version: '3.8'

services:
  # Database services
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: HoodMe_dev
      POSTGRES_USER: HoodMe
      POSTGRES_PASSWORD: development_password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/init-db.sql:/docker-entrypoint-initdb.d/init.sql
    command: >
      postgres
      -c shared_buffers=256MB
      -c max_connections=200
      -c wal_buffers=16MB

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data

  elasticsearch:
    image: elasticsearch:8.8.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ports:
      - "9200:9200"
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data

  # Core services
  auth-service:
    build:
      context: ./services/auth
      dockerfile: Dockerfile
    environment:
      DATABASE_URL: postgresql://HoodMe:development_password@postgres:5432/HoodMe_dev
      REDIS_URL: redis://redis:6379
      JWT_SECRET: development-secret-key
    ports:
      - "3001:3000"
    depends_on:
      - postgres
      - redis

  user-service:
    build:
      context: ./services/user
      dockerfile: Dockerfile
    environment:
      DATABASE_URL: postgresql://HoodMe:development_password@postgres:5432/HoodMe_dev
      REDIS_URL: redis://redis:6379
    ports:
      - "3002:3000"
    depends_on:
      - postgres
      - redis

  social-service:
    build:
      context: ./services/social
      dockerfile: Dockerfile
    environment:
      DATABASE_URL: postgresql://HoodMe:development_password@postgres:5432/HoodMe_dev
      REDIS_URL: redis://redis:6379
      ELASTICSEARCH_URL: http://elasticsearch:9200
    ports:
      - "3003:3000"
    depends_on:
      - postgres
      - redis
      - elasticsearch

  messaging-service:
    build:
      context: ./services/messaging
      dockerfile: Dockerfile
    environment:
      DATABASE_URL: postgresql://HoodMe:development_password@postgres:5432/HoodMe_dev
      REDIS_URL: redis://redis:6379
    ports:
      - "3004:3000"
    depends_on:
      - postgres
      - redis

  api-gateway:
    build:
      context: ./services/gateway
      dockerfile: Dockerfile
    environment:
      AUTH_SERVICE_URL: http://auth-service:3000
      USER_SERVICE_URL: http://user-service:3000
      SOCIAL_SERVICE_URL: http://social-service:3000
      MESSAGING_SERVICE_URL: http://messaging-service:3000
      REDIS_URL: redis://redis:6379
    ports:
      - "3000:3000"
    depends_on:
      - auth-service
      - user-service
      - social-service
      - messaging-service

volumes:
  postgres_data:
  redis_data:
  elasticsearch_data:

networks:
  default:
    name: HoodMe-network
```

## Kubernetes Deployment

### Namespace and Configuration
```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: HoodMe
  labels:
    name: HoodMe
    environment: production
---
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: HoodMe
data:
  NODE_ENV: "production"
  API_VERSION: "v1"
  LOG_LEVEL: "info"
  PORT: "3000"
  REDIS_HOST: "redis-service"
  ELASTICSEARCH_HOST: "elasticsearch-service"
  # Nigerian-specific configurations
  DEFAULT_TIMEZONE: "Africa/Lagos"
  DEFAULT_CURRENCY: "NGN"
  DEFAULT_LANGUAGE: "en"
  SMS_PROVIDER: "termii"
  PAYMENT_PROVIDER: "paystack"
```

### Secrets Management
```yaml
# k8s/secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
  namespace: HoodMe
type: Opaque
stringData:
  DATABASE_URL: "postgresql://user:password@postgres-service:5432/HoodMe"
  REDIS_PASSWORD: "redis-production-password"
  JWT_PRIVATE_KEY: |
    -----BEGIN PRIVATE KEY-----
    [RSA Private Key Content]
    -----END PRIVATE KEY-----
  JWT_PUBLIC_KEY: |
    -----BEGIN PUBLIC KEY-----
    [RSA Public Key Content]
    -----END PUBLIC KEY-----
  PAYSTACK_SECRET_KEY: "sk_live_[paystack_secret]"
  FLUTTERWAVE_SECRET_KEY: "FLWSECK_TEST-[flutterwave_secret]"
  TERMII_API_KEY: "[termii_api_key]"
  AWS_ACCESS_KEY_ID: "[aws_access_key]"
  AWS_SECRET_ACCESS_KEY: "[aws_secret_key]"
  GOOGLE_MAPS_API_KEY: "[google_maps_key]"
  SENDGRID_API_KEY: "[sendgrid_key]"
```

### Core Service Deployments

#### Auth Service Deployment
```yaml
# k8s/auth-service.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
  namespace: HoodMe
  labels:
    app: auth-service
    version: v1
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 1
  selector:
    matchLabels:
      app: auth-service
  template:
    metadata:
      labels:
        app: auth-service
        version: v1
    spec:
      serviceAccountName: HoodMe-service-account
      containers:
      - name: auth-service
        image: HoodMe/auth-service:latest
        ports:
        - containerPort: 3000
          name: http
        env:
        - name: NODE_ENV
          valueFrom:
            configMapKeyRef:
              name: app-config
              key: NODE_ENV
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: DATABASE_URL
        - name: JWT_PRIVATE_KEY
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: JWT_PRIVATE_KEY
        - name: REDIS_URL
          value: "redis://$(REDIS_HOST):6379"
        envFrom:
        - configMapRef:
            name: app-config
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /ready
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        securityContext:
          runAsNonRoot: true
          runAsUser: 1001
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: logs
          mountPath: /app/logs
      volumes:
      - name: tmp
        emptyDir: {}
      - name: logs
        emptyDir: {}
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - auth-service
              topologyKey: kubernetes.io/hostname
---
apiVersion: v1
kind: Service
metadata:
  name: auth-service
  namespace: HoodMe
  labels:
    app: auth-service
spec:
  selector:
    app: auth-service
  ports:
  - port: 3000
    targetPort: 3000
    name: http
  type: ClusterIP
```

#### Messaging Service with Sticky Sessions
```yaml
# k8s/messaging-service.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: messaging-service
  namespace: HoodMe
spec:
  replicas: 3
  selector:
    matchLabels:
      app: messaging-service
  template:
    metadata:
      labels:
        app: messaging-service
    spec:
      containers:
      - name: messaging-service
        image: HoodMe/messaging-service:latest
        ports:
        - containerPort: 3000
          name: http
        - containerPort: 3001
          name: websocket
        env:
        - name: REDIS_ADAPTER_HOST
          value: "redis-service"
        - name: REDIS_ADAPTER_PORT
          value: "6379"
        # Socket.io clustering configuration
        - name: SOCKET_IO_REDIS_ADAPTER
          value: "true"
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: messaging-service
  namespace: HoodMe
  annotations:
    # Enable session affinity for WebSocket connections
    service.beta.kubernetes.io/aws-load-balancer-backend-protocol: tcp
spec:
  selector:
    app: messaging-service
  ports:
  - port: 3000
    targetPort: 3000
    name: http
  - port: 3001
    targetPort: 3001
    name: websocket
  sessionAffinity: ClientIP
  sessionAffinityConfig:
    clientIP:
      timeoutSeconds: 10800  # 3 hours
```

### Horizontal Pod Autoscaler
```yaml
# k8s/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: auth-service-hpa
  namespace: HoodMe
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: auth-service
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: social-service-hpa
  namespace: HoodMe
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: social-service
  minReplicas: 3
  maxReplicas: 15
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

### Ingress Configuration
```yaml
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: HoodMe-ingress
  namespace: HoodMe
  annotations:
    kubernetes.io/ingress.class: "aws-load-balancer"
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/target-type: ip
    alb.ingress.kubernetes.io/ssl-redirect: '443'
    alb.ingress.kubernetes.io/certificate-arn: "arn:aws:acm:us-east-1:ACCOUNT:certificate/CERT-ID"
    alb.ingress.kubernetes.io/listen-ports: '[{"HTTP": 80}, {"HTTPS": 443}]'
    alb.ingress.kubernetes.io/healthcheck-path: /health
    alb.ingress.kubernetes.io/healthcheck-interval-seconds: '30'
    alb.ingress.kubernetes.io/healthcheck-timeout-seconds: '5'
    alb.ingress.kubernetes.io/success-codes: '200'
    # Rate limiting
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/rate-limit-window: "1m"
spec:
  rules:
  - host: api.HoodMe.com
    http:
      paths:
      - path: /api/v1/auth
        pathType: Prefix
        backend:
          service:
            name: auth-service
            port:
              number: 3000
      - path: /api/v1/users
        pathType: Prefix
        backend:
          service:
            name: user-service
            port:
              number: 3000
      - path: /api/v1/posts
        pathType: Prefix
        backend:
          service:
            name: social-service
            port:
              number: 3000
      - path: /api/v1/events
        pathType: Prefix
        backend:
          service:
            name: social-service
            port:
              number: 3000
      - path: /api/v1/marketplace
        pathType: Prefix
        backend:
          service:
            name: marketplace-service
            port:
              number: 3000
      - path: /api/v1/messaging
        pathType: Prefix
        backend:
          service:
            name: messaging-service
            port:
              number: 3000
      - path: /socket.io
        pathType: Prefix
        backend:
          service:
            name: messaging-service
            port:
              number: 3001
  tls:
  - hosts:
    - api.HoodMe.com
    secretName: HoodMe-tls
```

## CI/CD Pipeline

### GitHub Actions Workflow
```yaml
# .github/workflows/deploy.yml
name: Build and Deploy to Production

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  AWS_REGION: eu-west-1
  EKS_CLUSTER_NAME: HoodMe-production
  ECR_REPOSITORY: HoodMe

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: HoodMe_test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
      
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v3
    
    - name: Setup Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '18'
        cache: 'npm'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Run linting
      run: npm run lint
    
    - name: Run type checking
      run: npm run type-check
    
    - name: Run unit tests
      run: npm run test:unit
      env:
        NODE_ENV: test
    
    - name: Run integration tests
      run: npm run test:integration
      env:
        NODE_ENV: test
        DATABASE_URL: postgresql://postgres:postgres@localhost:5432/HoodMe_test
        REDIS_URL: redis://localhost:6379
    
    - name: Run security audit
      run: npm audit --audit-level high
    
    - name: Upload test coverage
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage/lcov.info

  security-scan:
    runs-on: ubuntu-latest
    steps:
    - name: Checkout code
      uses: actions/checkout@v3
    
    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'fs'
        scan-ref: '.'
        format: 'sarif'
        output: 'trivy-results.sarif'
    
    - name: Upload Trivy scan results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'

  build-and-push:
    needs: [test, security-scan]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    strategy:
      matrix:
        service: [auth, user, social, messaging, marketplace, notification, gateway]
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v3
    
    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v2
      with:
        aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
        aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        aws-region: ${{ env.AWS_REGION }}
    
    - name: Login to Amazon ECR
      id: login-ecr
      uses: aws-actions/amazon-ecr-login@v1
    
    - name: Build Docker image
      env:
        ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
        IMAGE_TAG: ${{ github.sha }}
      run: |
        docker build \
          -t $ECR_REGISTRY/$ECR_REPOSITORY-${{ matrix.service }}:$IMAGE_TAG \
          -t $ECR_REGISTRY/$ECR_REPOSITORY-${{ matrix.service }}:latest \
          ./services/${{ matrix.service }}
    
    - name: Scan Docker image for vulnerabilities
      env:
        ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
        IMAGE_TAG: ${{ github.sha }}
      run: |
        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
          aquasec/trivy:latest image \
          --exit-code 1 --severity HIGH,CRITICAL \
          $ECR_REGISTRY/$ECR_REPOSITORY-${{ matrix.service }}:$IMAGE_TAG
    
    - name: Push Docker image to ECR
      env:
        ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
        IMAGE_TAG: ${{ github.sha }}
      run: |
        docker push $ECR_REGISTRY/$ECR_REPOSITORY-${{ matrix.service }}:$IMAGE_TAG
        docker push $ECR_REGISTRY/$ECR_REPOSITORY-${{ matrix.service }}:latest

  deploy:
    needs: build-and-push
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v3
    
    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v2
      with:
        aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
        aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        aws-region: ${{ env.AWS_REGION }}
    
    - name: Update kubeconfig
      run: |
        aws eks update-kubeconfig --name $EKS_CLUSTER_NAME --region ${{ env.AWS_REGION }}
    
    - name: Deploy to Kubernetes
      env:
        ECR_REGISTRY: ${{ secrets.ECR_REGISTRY }}
        IMAGE_TAG: ${{ github.sha }}
      run: |
        # Update image tags in deployment files
        for service in auth user social messaging marketplace notification gateway; do
          kubectl set image deployment/${service}-service \
            ${service}-service=$ECR_REGISTRY/$ECR_REPOSITORY-${service}:$IMAGE_TAG \
            -n HoodMe
        done
    
    - name: Verify deployment
      run: |
        kubectl rollout status deployment/auth-service -n HoodMe --timeout=300s
        kubectl rollout status deployment/social-service -n HoodMe --timeout=300s
        kubectl rollout status deployment/messaging-service -n HoodMe --timeout=300s
    
    - name: Run smoke tests
      run: |
        # Wait for services to be ready
        kubectl wait --for=condition=available deployment --all -n HoodMe --timeout=300s
        
        # Run smoke tests against the deployed services
        npm run test:smoke
      env:
        API_BASE_URL: https://api.HoodMe.com
        SMOKE_TEST_API_KEY: ${{ secrets.SMOKE_TEST_API_KEY }}
    
    - name: Notify deployment status
      if: always()
      uses: 8398a7/action-slack@v3
      with:
        status: ${{ job.status }}
        channel: '#deployments'
        webhook_url: ${{ secrets.SLACK_WEBHOOK }}
        fields: repo,message,commit,author,action,eventName,ref,workflow
```

### Rollback Strategy
```bash
#!/bin/bash
# scripts/rollback.sh

set -e

NAMESPACE="HoodMe"
SERVICES=("auth-service" "user-service" "social-service" "messaging-service" "marketplace-service")

echo "Starting rollback process..."

for service in "${SERVICES[@]}"; do
    echo "Rolling back $service..."
    
    # Check if there's a previous revision
    REVISION=$(kubectl rollout history deployment/$service -n $NAMESPACE | tail -2 | head -1 | awk '{print $1}')
    
    if [ ! -z "$REVISION" ]; then
        kubectl rollout undo deployment/$service -n $NAMESPACE --to-revision=$REVISION
        echo "Waiting for $service rollback to complete..."
        kubectl rollout status deployment/$service -n $NAMESPACE --timeout=300s
    else
        echo "No previous revision found for $service"
    fi
done

echo "Rollback completed successfully!"

# Run health checks
echo "Running post-rollback health checks..."
for service in "${SERVICES[@]}"; do
    kubectl wait --for=condition=available deployment/$service -n $NAMESPACE --timeout=60s
done

echo "All services are healthy after rollback."
```

## Infrastructure as Code

### Terraform Configuration
```hcl
# terraform/main.tf
terraform {
  required_version = ">= 1.3"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.16"
    }
  }
  
  backend "s3" {
    bucket = "HoodMe-terraform-state"
    key    = "production/terraform.tfstate"
    region = "eu-west-1"
    
    dynamodb_table = "HoodMe-terraform-locks"
    encrypt        = true
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "HoodMe"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# VPC and Networking
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  
  name = "HoodMe-vpc"
  cidr = "10.0.0.0/16"
  
  azs             = ["${var.aws_region}a", "${var.aws_region}b", "${var.aws_region}c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
  
  enable_nat_gateway = true
  enable_vpn_gateway = false
  enable_dns_hostnames = true
  enable_dns_support = true
  
  tags = {
    Name = "HoodMe-vpc"
  }
}

# EKS Cluster
module "eks" {
  source = "terraform-aws-modules/eks/aws"
  
  cluster_name    = "HoodMe-${var.environment}"
  cluster_version = "1.27"
  
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets
  
  cluster_endpoint_public_access = true
  cluster_endpoint_private_access = true
  
  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
    }
    aws-ebs-csi-driver = {
      most_recent = true
    }
  }
  
  eks_managed_node_groups = {
    general = {
      min_size     = 3
      max_size     = 10
      desired_size = 5
      
      instance_types = ["t3.medium"]
      capacity_type  = "ON_DEMAND"
      
      k8s_labels = {
        Environment = var.environment
        NodeGroup   = "general"
      }
      
      update_config = {
        max_unavailable_percentage = 25
      }
    }
    
    compute = {
      min_size     = 1
      max_size     = 5
      desired_size = 2
      
      instance_types = ["c5.large"]
      capacity_type  = "SPOT"
      
      k8s_labels = {
        Environment = var.environment
        NodeGroup   = "compute"
      }
      
      taints = {
        dedicated = {
          key    = "compute-intensive"
          value  = "true"
          effect = "NO_SCHEDULE"
        }
      }
    }
  }
}

# RDS PostgreSQL
resource "aws_db_instance" "postgres" {
  identifier = "HoodMe-postgres-${var.environment}"
  
  engine         = "postgres"
  engine_version = "15.3"
  instance_class = var.db_instance_class
  
  allocated_storage     = 100
  max_allocated_storage = 1000
  storage_type          = "gp3"
  storage_encrypted     = true
  
  db_name  = "HoodMe"
  username = "HoodMe"
  password = var.db_password
  
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.postgres.name
  
  backup_retention_period = 30
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  skip_final_snapshot = false
  final_snapshot_identifier = "HoodMe-postgres-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}"
  
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn
  
  performance_insights_enabled = true
  
  tags = {
    Name = "HoodMe-postgres"
  }
}

# ElastiCache Redis
resource "aws_elasticache_replication_group" "redis" {
  replication_group_id         = "HoodMe-redis-${var.environment}"
  description                  = "Redis cluster for HoodMe"
  
  node_type                    = var.redis_node_type
  port                         = 6379
  parameter_group_name         = "default.redis7"
  
  num_cache_clusters           = 3
  automatic_failover_enabled   = true
  multi_az_enabled            = true
  
  subnet_group_name           = aws_elasticache_subnet_group.redis.name
  security_group_ids          = [aws_security_group.redis.id]
  
  at_rest_encryption_enabled  = true
  transit_encryption_enabled  = true
  auth_token                  = var.redis_auth_token
  
  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.redis_slow_log.name
    destination_type = "cloudwatch-logs"
    log_format       = "text"
    log_type         = "slow-log"
  }
  
  tags = {
    Name = "HoodMe-redis"
  }
}

# S3 Buckets
resource "aws_s3_bucket" "media" {
  bucket = "HoodMe-media-${var.environment}-${random_id.bucket_suffix.hex}"
  
  tags = {
    Name = "HoodMe-media"
    Type = "media-storage"
  }
}

resource "aws_s3_bucket_versioning" "media" {
  bucket = aws_s3_bucket.media.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "media" {
  bucket = aws_s3_bucket.media.id
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

# CloudFront Distribution
resource "aws_cloudfront_distribution" "media_cdn" {
  origin {
    domain_name = aws_s3_bucket.media.bucket_regional_domain_name
    origin_id   = "S3-${aws_s3_bucket.media.id}"
    
    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.media.cloudfront_access_identity_path
    }
  }
  
  enabled = true
  
  default_cache_behavior {
    allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3-${aws_s3_bucket.media.id}"
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
    
    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
    
    min_ttl     = 0
    default_ttl = 86400
    max_ttl     = 31536000
  }
  
  price_class = "PriceClass_100"  # Use only North America and Europe edge locations
  
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
  
  viewer_certificate {
    cloudfront_default_certificate = true
  }
  
  tags = {
    Name = "HoodMe-media-cdn"
  }
}
```

### Environment-Specific Variables
```hcl
# terraform/environments/production/terraform.tfvars
aws_region = "eu-west-1"
environment = "production"

# Database configuration
db_instance_class = "db.r5.xlarge"
db_password = "secure-production-password"

# Redis configuration
redis_node_type = "cache.r6g.large"
redis_auth_token = "secure-redis-token"

# EKS configuration
eks_node_instance_types = ["t3.medium", "t3.large"]
eks_min_nodes = 5
eks_max_nodes = 20
eks_desired_nodes = 8

# Application configuration
domain_name = "HoodMe.com"
api_domain = "api.HoodMe.com"
```

This comprehensive deployment guide provides a production-ready setup for HoodMe with proper security, scalability, and monitoring in place.