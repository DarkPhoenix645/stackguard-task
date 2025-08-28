# Teams Security Connector (Golang)

A Golang-based Microsoft Teams security connector that scans messages for secrets in real-time, masks sensitive values, emits alerts, and provides a lightweight dashboard.

- Written in Go using Fiber
- WebSocket-powered live dashboard
- Heuristics based secret detection via regex + entropy and context scoring
- Dockerized, AWS-ready and deployed
- Automated GitHub Actions Workflow which rebuilds and deploys the container for CI/CD on the main branch

## Contents

- [Teams Security Connector (Golang)](#teams-security-connector-golang)
  - [Contents](#contents)
  - [Architecture](#architecture)
  - [Features](#features)
  - [Setup \& Configuration](#setup--configuration)
  - [Running](#running)
    - [Local (Development)](#local-development)
    - [Local (Go)](#local-go)
    - [Docker](#docker)
  - [Future Enhancement: Microsoft Graph Integration](#future-enhancement-microsoft-graph-integration)
  - [API Endpoints](#api-endpoints)
  - [Web Dashboard](#web-dashboard)
  - [Detection Rules \& False Positives](#detection-rules--false-positives)
    - [Error Handling \& Edge Cases](#error-handling--edge-cases)
  - [Deploying to AWS](#deploying-to-aws)
  - [Testing \& Development](#testing--development)
  - [Notes](#notes)

## Architecture

- `cmd/server/main.go`: App entrypoint, Fiber setup, routes, middleware, graceful shutdown, WebSocket hub wiring.
- `internal/config`: Loads environment configuration (.env or direct env).
- `internal/api`: HTTP handlers for health, stats, detections, test utilities, and webhook ingress.
- `internal/detector`: Regex patterns, masking strategies, and confidence scoring with false-positive mitigation.
- `internal/services`:
  - `teams.go`: Message processing, scanning, persistence, and WebSocket alert fan-out.
  - `alerting.go`: Formats and broadcasts alerts (mock Teams posting, real-time WS broadcast).
- `internal/storage`: Thread-safe in-memory store for detections and stats.
- `internal/websocket`: Hub to manage connections and broadcast detections/alerts.
- `web/static`: Minimal UI (dashboard and live messages) consuming REST + WebSocket.

## Features

- Secret detection using curated regex patterns and entropy/context scoring
- False-positive filtering (e.g., AKIA…TEST, example/sample tokens)
- Masking sensitive values in all outputs and alerts
- Handles large messages via chunked scanning with overlap
- Live dashboard via WebSockets, plus REST stats and filtering
- Detection lifecycle: update status to `acknowledged`/`resolved`/`false_positive`

## Setup & Configuration

Environment variables (see `internal/config/config.go`):

- `TEAMS_CLIENT_ID` (required)
- `TEAMS_CLIENT_SECRET` (required)
- `TENANT_ID` (required)
- `SECURITY_CHANNEL_ID` (required) – target channel for alerts
- `PORT` (default: `8080`)
- `MONITORING_INTERVAL` (default: `30`) – seconds
- `MOCK_MODE` (default: `true`) – when true, alert posting to Teams is mocked and logged; WebSockets still broadcast
- `LOG_LEVEL` (default: `info`)

Create a `.env` in the project root:

```
TEAMS_CLIENT_ID=your_app_client_id
TEAMS_CLIENT_SECRET=your_app_client_secret
TENANT_ID=your_tenant_id
SECURITY_CHANNEL_ID=your_security_channel_id
PORT=8080
MONITORING_INTERVAL=30
MOCK_MODE=true
LOG_LEVEL=info
```

## Running

### Local (Development)

This project supports hot reload with the [Air](https://github.com/air-verse/air) package. Make sure you have a valid Golang and Air installation, then run the project with the following in project root:

```bash
air
```

### Local (Go)

```bash
# from project root
export $(grep -v '^#' .env | xargs -d'\n' -I{} echo {}) 2>/dev/null || true
go run ./cmd/server/main.go
# Dashboard: http://localhost:8080/
# Health:    http://localhost:8080/api/health
```

### Docker

```bash
docker build -t stackguard-task:latest .
docker run --rm -p 8080:8080 --env-file .env stackguard-task:latest
```

## Future Enhancement: Microsoft Graph Integration

This submission includes the full scanning, masking, alert broadcasting, webhook handling, and dashboard. Posting alerts back to Teams is implemented with a mocked sender in `MOCK_MODE`. To connect to Microsoft Graph:

1. Register an Azure AD app with the Microsoft Graph permissions needed to read channel messages and post messages to a security channel (e.g., `ChannelMessage.Read.All`, `ChannelMessage.Send`). Grant admin consent.
2. Use client credentials flow to obtain an access token for Microsoft Graph using `TEAMS_CLIENT_ID`, `TEAMS_CLIENT_SECRET`, and `TENANT_ID`.
3. Implement a poller or subscription/webhook for Teams messages:
   - Webhook subscription: subscribe to `teams/{id}/channels/{id}/messages` and point to `/api/webhook/teams` to receive messages in near real-time.
   - Polling: periodically call Graph endpoints to fetch recent messages for monitored channels at `MONITORING_INTERVAL`.
4. Replace the mock in `internal/services/alerting.go` with real Graph API calls to post alerts into `SECURITY_CHANNEL_ID`.

Where to wire in production code:

- Receive messages: enhance `internal/api/handlers.go: TeamsWebhook` or add a Graph poller using `services.TeamsService.ProcessMessage`.
- Post alerts: replace the mock section in `AlertService.SendAlert` with a Graph client that posts to the `SECURITY_CHANNEL_ID`.

## API Endpoints

Base URL: `/api`

- `GET /health` – service health
- `GET /stats` – dashboard stats (totals, by severity/type, recent, channels)
- `GET /detections?limit=50` – recent detections
- `GET /detections/channel/:channelId` – detections for a channel
- `GET /detections/status/:status` – detections by status (`new`, `acknowledged`, `resolved`, `false_positive`)
- `PUT /detections/:id/status` – update detection status; body: `{ "status": "acknowledged" }`
- `DELETE /detections/clear` – clear all detections
- `POST /webhook/teams` – webhook receiver for Teams messages; body: `models.WebhookPayload`
- `POST /test/detect` – utility to test detection; body: `{ "text": "...", "channelId": "...", "userName": "..." }`

WebSockets:

- `/ws` – broadcasts `models.SecretDetection` JSON for live dashboard
- `/ws/messages` – broadcasts formatted alert messages (used by messages page)

Static UI:

- `/` – dashboard (`web/static/index.html`)
- `/messages.html` – live messages (`web/static/messages.html`)

## Web Dashboard

- Shows total detections, counts by severity, affected channels.
- Lists active and acknowledged detections, supports acknowledge action.
- Real-time updates via WebSocket (`/ws`).

Open locally after starting the server: `http://localhost:8080/`.

## Detection Rules & False Positives

Defined in `internal/detector/scanner.go`:

- AWS Access Key, AWS Secret Key
- GitHub Token, JWT Token
- Generic API Key
- Database URLs (mongodb/mysql/postgres/redis)
- Private Keys (PEM blocks)
- Slack Tokens, Google API Keys

Masking (`internal/detector/masker.go`):

- Intelligently redacts info so that a max of 20% of the key is visible on the dashboard and in alerts
- This is just enough for identification but still masks the key for security
- Special handling for multiline secrets, URLs, JWTs
- Full secret value never serialized in the API

### Error Handling & Edge Cases

1. Large Messages and Retries
   - Large messages: scanned in overlapping chunks (4096 char with 512 char overlap) to catch boundary-spanning secrets
   - API rate limits / transient errors: WebSocket writes include small retries; Graph posting should implement retry with backoff when replacing mock
   - Missing/invalid requests: consistent JSON errors, central Fiber error handler
   - Status validation: only accepts known states
2. False-positive handling:
   - Context checks to determine if the key being sent is actually real (e.g., `test`, `example`, `demo`, `placeholder`)
   - Hard-coded ignore patterns for common example key formats
   - Confidence scored with: pattern specificity, entropy, context, length, composition
   - Deduplication keeps the highest-confidence overlapping detection

## Deploying to AWS

Gist: ECR + EC2 + GitHub Actions (OIDC). On push to `main`, GitHub Actions will rebuild and push the image to ECR, then SSH into EC2 to pull and run the latest container.

- Create ECR repo and set env vars: `AWS_REGION`, `AWS_ACCOUNT_ID`, `ECR_URI`, `ECR_REPOSITORY`.
- Launch EC2 (Amazon Linux 2), open port 8080, install Docker; attach an IAM instance profile that can pull from ECR.
- In IAM, add GitHub OIDC provider and a role restricted to the repo’s `main` branch; grant ECR push permissions.
- Add GitHub secrets: `AWS_REGION`, `AWS_ACCOUNT_ID`, `ECR_REPOSITORY`, `ECR_URI`, `EC2_INSTANCE_PUBLIC_IP`, `EC2_SSH_PRIVATE_KEY`.
- Add `.github/workflows/deploy.yml`:
  - build
  - push to ECR
  - SSH into EC2
  - `docker pull`
  - `docker run -d -p 8080:8080 --restart unless-stopped`.
- Verify: `http://<EC2_PUBLIC_IP>:8080/` and `/api/health`.
- Cleanup AWS resources when done.

## Testing & Development

Check out the [Postman Collection](https://app.getpostman.com/join-team?invite_code=c41410dcb413861c3d014e1432861983b3beb48e95fc6469cf77fe50c2015ba9&target_code=bcc665efce0f4876109a955c4bf8dd0d) for the same to get a detailed view of API req / res structure.

## Notes

- In `MOCK_MODE=true`, alerts are logged and broadcast over WebSockets.
- The in-memory store is for demo purposes; swap with DynamoDB/RDS/Redis for persistence and scale.
- The regex set is intentionally focused; can be extended as needed.
