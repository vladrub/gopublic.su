# Server Implementation Walkthrough

## Overview
I have implemented the core Server component of `gopublic` with support for HTTPS, Automatic Routing, Client Builds, and **Telegram Authentication**.

## Components Implemented

### 1. Dashboard & Authentication (`internal/dashboard`)
- **UI**: Server-side rendered HTML using Go Templates (`templates/`).
- **Auth**: Uses **Telegram Login Widget**.
    - User authenticates via widget on `app.DOMAIN_NAME/login`.
    - Server verifies the HMAC hash of the data received from Telegram using `TELEGRAM_BOT_TOKEN`.
    - Creates/Updates user in SQLite database (`TelegramID`, `FirstName`, `PhotoURL`).
    - Sets a `user_id` cookie (simple session).
- **Features**:
    - Shows the user's **Auth Token** (generated on first login).
    - Lists assigned subdomains.
    - Logout functionality.

### 2. Domain Routing (`internal/ingress`)
The Ingress listener smartly routes traffic based on the `Host` header:
- **`DOMAIN_NAME`** (e.g. `example.com`): Serves the **Landing Page**.
- **`app.DOMAIN_NAME`** (e.g. `app.example.com`): Serves the **Dashboard** (routes `/`, `/login`, `/auth/telegram` delegated to Dashboard Handler).
- **`*.DOMAIN_NAME`** (e.g. `foo.example.com`): Routes to the active **User Tunnel**.

### 3. Client Build System (`Makefile`)
The client binary needs to know where the server is. Instead of config files, we bake the address in at build time.
- **Variable**: `main.ServerAddr` in `cmd/client/main.go`.
- **Injection**: The `Makefile` uses `go build -ldflags "-X main.ServerAddr=..."` to set this variable.
- **Command**: `make build-client SERVER_ADDR=your-vps.com:4443`

### 4. HTTPS
- Integrated `autocert` for automatic Let's Encrypt certificates.
- Supports On-Demand TLS for all subdomains.

## Usage

### Server
Deploy with Docker:
1. Create `.env`:
    ```ini
    DOMAIN_NAME=example.com
    EMAIL=admin@example.com
    TELEGRAM_BOT_TOKEN=123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11
    TELEGRAM_BOT_NAME=MyGopublicBot
    ```
2. Run:
    ```bash
    docker-compose up -d --build
    ```

### Client
Build the client for your server:
```bash
make build-client SERVER_ADDR=example.com:4443
```
Running the client:
```bash
./bin/gopublic-client
```
The client will connect (using token from dashboard), authenticates, and listen for requests.
