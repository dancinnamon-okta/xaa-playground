require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const { OktaAuth } = require('@okta/okta-auth-js');
const util = require('./utils')
const redis = require('redis')
const RedisStore = require('connect-redis')

// Load configuration
const oktaConfig = {
  issuer: process.env.OKTA_ISSUER,
  clientId: process.env.OKTA_CLIENT_ID,
  clientSecret: process.env.OKTA_CLIENT_SECRET,
  redirectUri: process.env.OKTA_REDIRECT_URI || `http://localhost:${PORT}/callback`,
  scopes: ['openid', 'profile', 'email', 'offline_access'],
  pkce: true
};

// Load the XAA client private key if configured
let xaaPrivateKey = null;

if(process.env.XAA_CLIENT_PRIVATE_KEY_CONTENT) {
  xaaPrivateKey = process.env.XAA_CLIENT_PRIVATE_KEY_CONTENT
  console.log('XAA client private key loaded from environment variable successfully.');
}
else if (process.env.XAA_CLIENT_PRIVATE_KEY_FILE) {
  try {
    const keyFilePath = path.resolve(process.env.XAA_CLIENT_PRIVATE_KEY_FILE);
    xaaPrivateKey = fs.readFileSync(keyFilePath, 'utf8');
    console.log('XAA client private key loaded from file successfully.');
  } catch (error) {
    console.warn('Warning: Could not load XAA client private key:', error.message);
  }
}

// XAA Client configuration (uses private_key_jwt authentication)
const xaaClientConfig = {
  clientId: process.env.XAA_CLIENT_ID,
  privateKeyFile: process.env.XAA_CLIENT_PRIVATE_KEY_FILE,
  privateKeyId: process.env.XAA_CLIENT_PRIVATE_KEY_ID,
  privateKey: xaaPrivateKey
};

const oktaAuth = new OktaAuth({
  issuer: oktaConfig.issuer,
  clientId: oktaConfig.clientId,
  redirectUri: oktaConfig.redirectUri,
  scopes: oktaConfig.scopes,
  pkce: oktaConfig.pkce
});

//ExpressJS Init.
const app = express();
const PORT = process.env.PORT || 3000;

// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, 'public')));

// Parse JSON and URL-encoded bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session middleware
if(process.env.REDIS_URL) {
  const redisClient = redis.createClient({ url: redisURL });
  redisClient.connect();
  const redisStore = new RedisStore.RedisStore({client: redisClient})

  app.use(session({
    store: redisStore,
    secret: process.env.SESSION_SECRET || 'xaa-playground-dev-secret-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
  }));

}
else {
  app.use(session({
    secret: process.env.SESSION_SECRET || 'xaa-playground-dev-secret-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
  }));
}


// Middleware to check authentication
const isAuthenticated = (req, res, next) => {
  if (req.session && req.session.tokens) {
    return next();
  }
  res.redirect('/');
};

// Routes

//Public welcome page.
app.get('/', (req, res) => {
  res.render('index', { 
    isLoggedIn: !!(req.session && req.session.tokens),
    user: req.session?.userInfo
  });
});

// Login route - initiates OIDC authorization code flow with PKCE
app.get('/login', async (req, res) => {
  try {
    // Use prepareTokenParams to generate PKCE values, state, and nonce
    const tokenParams = await oktaAuth.token.prepareTokenParams({
      scopes: oktaConfig.scopes,
      redirectUri: oktaConfig.redirectUri
    });
    
    // Store PKCE code verifier and state in session for later verification
    req.session.pkceCodeVerifier = tokenParams.codeVerifier;
    req.session.oauthState = tokenParams.state;
    req.session.oauthNonce = tokenParams.nonce;
    
    // Build the authorization URL
    const authUrl = new URL(`${oktaConfig.issuer}/oauth2/v1/authorize`);
    authUrl.searchParams.set('client_id', oktaConfig.clientId);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', oktaConfig.scopes.join(' '));
    authUrl.searchParams.set('redirect_uri', oktaConfig.redirectUri);
    authUrl.searchParams.set('state', tokenParams.state);
    authUrl.searchParams.set('nonce', tokenParams.nonce);
    authUrl.searchParams.set('code_challenge', tokenParams.codeChallenge);
    authUrl.searchParams.set('code_challenge_method', tokenParams.codeChallengeMethod);
    
    await req.session.save();
    res.redirect(authUrl.toString());
  } catch (error) {
    console.error('Login error:', error);
    res.render('error', { message: 'Failed to initiate login', error: error.message });
  }
});

// Callback route - handles the authorization code exchange
app.get('/callback', async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;
    
    // Check for OAuth errors
    if (error) {
      throw new Error(`OAuth error: ${error} - ${error_description}`);
    }
    
    // Verify state
    if (state !== req.session.oauthState) {
      throw new Error('Invalid state parameter');
    }
    
    // Get stored values from session
    const codeVerifier = req.session.pkceCodeVerifier;
    
    if (!codeVerifier) {
      throw new Error('Missing PKCE code verifier');
    }
    
    // Token endpoint URL
    const tokenUrl = `${oktaConfig.issuer}/oauth2/v1/token`;
    
    // Exchange code for tokens
    const tokenResponse = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: oktaConfig.clientId,
        client_secret: oktaConfig.clientSecret,
        redirect_uri: oktaConfig.redirectUri,
        code: code,
        code_verifier: codeVerifier
      })
    });

    const tokenData = await tokenResponse.json();
    
    if (tokenData.error) {
      throw new Error(`Token exchange failed: ${tokenData.error} - ${tokenData.error_description}`);
    }
    
    // Decode tokens for display
    let idTokenPayload, accessTokenPayload;
    
    idTokenPayload = util.decodeJwtPayload(tokenData.id_token);
    accessTokenPayload = util.decodeJwtPayload(tokenData.access_token);
    
    // Store tokens in session
    req.session.tokens = {
      accessToken: tokenData.access_token,
      idToken: tokenData.id_token,
      refreshToken: tokenData.refresh_token,
      tokenType: tokenData.token_type,
      expiresIn: tokenData.expires_in,
      scope: tokenData.scope
    };
    
    req.session.tokenDetails = {
      idTokenPayload,
      accessTokenPayload,
      rawIdToken: tokenData.id_token,
      rawAccessToken: tokenData.access_token,
      tokenType: tokenData.token_type,
      expiresIn: tokenData.expires_in,
      scope: tokenData.scope
    };
    
    req.session.userInfo = {
      name: idTokenPayload?.name || idTokenPayload?.preferred_username || 'Unknown',
      email: idTokenPayload?.email,
      sub: idTokenPayload?.sub
    };
    
    // Clean up PKCE and OAuth state
    delete req.session.pkceCodeVerifier;
    delete req.session.oauthState;
    delete req.session.oauthNonce;

    await req.session.save();
    res.redirect('/dashboard');
  } catch (error) {
    console.error('Callback error:', error);
    res.render('error', { message: 'Authentication failed', error: error.message });
  }
});

// Dashboard route - protected, shows token details
app.get('/dashboard', isAuthenticated, (req, res) => {
  res.render('dashboard', {
    user: req.session.userInfo,
    tokenDetails: req.session.tokenDetails,
    tokens: req.session.tokens,
    xaaResult: req.session.xaaResult || null
  });
});

// XAA Token Exchange route - performs the Identity Assertion JWT Authorization Grant flow
app.post('/xaa-exchange', isAuthenticated, async (req, res) => {
  try {
    const { audience, scopes } = req.body;
    
    if (!audience) {
      throw new Error('Destination audience is required');
    }

    // Determine which client to use for XAA exchange
    const xaaClientId = xaaClientConfig.clientId;
    
    if (xaaClientConfig.clientId && !xaaPrivateKey) {
      throw new Error('XAA client ID is configured but private key is not available');
    }
    
    const idToken = req.session.tokens?.idToken;
    if (!idToken) {
      throw new Error('No ID token available for exchange');
    }
    
    // Step 1: Token Exchange with IdP to get ID-JAG
    // Per the spec, we exchange our ID token for an Identity Assertion JWT Authorization Grant
    const tokenExchangeUrl = `${oktaConfig.issuer}/oauth2/v1/token`;
    
    const tokenExchangeParams = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      requested_token_type: 'urn:ietf:params:oauth:token-type:id-jag',
      audience: audience,
      subject_token: idToken,
      subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
      client_id: xaaClientId,
      scope: scopes.trim()
    });

    // Add authentication based on configuration
    const clientAssertion = util.createClientAssertionJwt(xaaClientConfig, tokenExchangeUrl);
    tokenExchangeParams.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    tokenExchangeParams.set('client_assertion', clientAssertion);

    const tokenExchangeResponse = await fetch(tokenExchangeUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: tokenExchangeParams
    });

    const tokenExchangeData = await tokenExchangeResponse.json();
    
    if (tokenExchangeData.error) {
      throw new Error(`Token exchange failed: ${tokenExchangeData.error} - ${tokenExchangeData.error_description || ''}`);
    }
    
    // The ID-JAG is returned in the access_token field per RFC 8693
    const idJag = tokenExchangeData.access_token;
    const idJagPayload = util.decodeJwtPayload(idJag);

    console.log("JAG Retrieved Successfully!")
    console.log(idJag)
    
    // Step 2: Exchange the ID-JAG for an access token at the Resource Authorization Server
    // Per the spec, we use the jwt-bearer grant type
    const resourceTokenUrl = `${audience}/v1/token`;
    
    const resourceTokenParams = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: idJag,
      client_id: xaaClientId
    });

    // Add authentication based on configuration
    const resourceClientAssertion = util.createClientAssertionJwt(xaaClientConfig, resourceTokenUrl);
    resourceTokenParams.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    resourceTokenParams.set('client_assertion', resourceClientAssertion);

    
    const resourceTokenResponse = await fetch(resourceTokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: resourceTokenParams
    });
    
    const resourceTokenData = await resourceTokenResponse.json();
    
    if (resourceTokenData.error) {
      // Store partial result with ID-JAG even if the second exchange fails
      req.session.xaaResult = {
        success: false,
        partialSuccess: true,
        error: `Resource token exchange failed: ${resourceTokenData.error} - ${resourceTokenData.error_description || ''}`,
        idJag: idJag,
        idJagPayload: idJagPayload,
        requestedAudience: audience,
        requestedScopes: scopes,
        timestamp: new Date().toISOString()
      };
      await req.session.save();
      return res.redirect('/dashboard');
    }

    const xaaAccessToken = resourceTokenData.access_token;
    const xaaAccessTokenPayload = util.decodeJwtPayload(xaaAccessToken);
    
    // Store successful XAA exchange result in session
    req.session.xaaResult = {
      success: true,
      idJag: idJag,
      idJagPayload: idJagPayload,
      accessToken: xaaAccessToken,
      accessTokenPayload: xaaAccessTokenPayload,
      tokenType: resourceTokenData.token_type,
      expiresIn: resourceTokenData.expires_in,
      scope: resourceTokenData.scope,
      requestedAudience: audience,
      requestedScopes: scopes,
      timestamp: new Date().toISOString()
    };
    
    await req.session.save();
    res.redirect('/dashboard');
    
  } catch (error) {
    console.error('XAA Exchange error:', error);
    req.session.xaaResult = {
      success: false,
      error: error.message,
      requestedAudience: req.body.audience,
      requestedScopes: req.body.scopes,
      timestamp: new Date().toISOString()
    };
    await req.session.save();
    res.redirect('/dashboard');
  }
});

// Clear XAA result route
app.post('/clear-xaa', isAuthenticated, async (req, res) => {
  delete req.session.xaaResult;
  await req.session.save();
  res.redirect('/dashboard');
});

// Logout route
app.get('/logout', async (req, res) => {
  const idToken = req.session.tokens?.idToken;
  
  req.session.destroy((err) => {
    if (err) {
      console.error('Session destruction error:', err);
    }
    
    // If we have an id_token, redirect to Okta logout
    if (idToken && oktaConfig.issuer) {
      const logoutUrl = new URL(`${oktaConfig.issuer}/oauth2/v1/logout`);
      logoutUrl.searchParams.set('id_token_hint', idToken);
      logoutUrl.searchParams.set('post_logout_redirect_uri', `http://localhost:${PORT}/`);
      res.redirect(logoutUrl.toString());
    } else {
      res.redirect('/');
    }
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`XAA Playground is running at http://localhost:${PORT}`);
  if (!process.env.OKTA_ISSUER || !process.env.OKTA_CLIENT_ID) {
    console.warn('Warning: OKTA_ISSUER and OKTA_CLIENT_ID environment variables are not set.');
    console.warn('Please create a .env file with your Okta configuration.');
  }
});
