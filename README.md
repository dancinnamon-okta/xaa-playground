# XAA Playground

A playground application for learning the Cross App Access Protocol (Identity Assertion JWT Authorization Grant).

## Features

- **OIDC Authentication**: Secure login using Okta with the Authorization Code flow
- **PKCE**: Proof Key for Code Exchange for enhanced security
- **Token Dashboard**: View decoded ID tokens, access tokens, and their claims

## Setup

### 1. Create an Okta Application

1. Log in to your Okta Admin Console
2. Navigate to **Applications** > **Applications**
3. Click **Create App Integration**
4. Select **OIDC - OpenID Connect** and **Web Application**
5. Configure the application:
   - **Sign-in redirect URIs**: `http://localhost:3000/callback`
   - **Sign-out redirect URIs**: `http://localhost:3000/`
   - **Grant types**: Authorization Code
   - **Require PKCE**: Yes (if available)
6. Note your **Client ID** and your **Okta domain**

### 2. Configure Environment Variables

Copy the example environment file and fill in your values:

```bash
cp .env.example .env
```

Edit `.env` with your Okta configuration:

```
OKTA_ISSUER=https://your-domain.okta.com/oauth2/default
OKTA_CLIENT_ID=your-client-id
OKTA_REDIRECT_URI=http://localhost:3000/callback
SESSION_SECRET=your-secure-random-secret
```

### 3. Install Dependencies

```bash
npm install
```

### 4. Start the Application

```bash
npm start
```

Visit `http://localhost:3000` in your browser.

## Usage

1. Click the **Login with Okta** button in the navigation bar
2. Authenticate with your Okta credentials
3. After successful authentication, you'll be redirected to the **Dashboard**
4. The dashboard displays:
   - User information from the ID token
   - Token overview (type, expiration, scopes)
   - Full ID token and access token claims
   - DPoP confirmation details (if available)
   - Raw JWT tokens (expandable)

## Security Features

### PKCE (Proof Key for Code Exchange)
- Generates a cryptographic code verifier and challenge
- Protects against authorization code interception attacks
- Required for public clients, recommended for all clients


## Project Structure

```
xaa-playground/
├── app.js              # Express server with OIDC routes
├── package.json        # Dependencies
├── .env.example        # Example environment configuration
├── views/
│   ├── index.ejs       # Home page with XAA protocol info
│   ├── dashboard.ejs   # Authenticated user dashboard
│   └── error.ejs       # Error page
└── public/
    └── css/
        └── styles.css  # Application styles
```

## License

Apache 2.0
