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
const PORT = process.env.PORT || 3000;
let issuer = process.env.OKTA_DOMAIN
let oauthPathPrefix = process.env.OKTA_DOMAIN

if(!issuer) {
  console.log("The OKTA_DOMAIN variable has not been properly set.")
  throw new Error(`The application has not been properly configured. Please ensure all environment variables are set!`);
}

if(process.env.OKTA_CUSTOM_AUTHZ_SERVER_ID) {
  console.log("This application hass been configured with a custom authorization server. Using that as the issuer.")
  issuer = `${issuer}/oauth2/${process.env.OKTA_CUSTOM_AUTHZ_SERVER_ID}`
  oauthPathPrefix = issuer
}
else {
  oauthPathPrefix = `${oauthPathPrefix}/oauth2`
}

const oktaConfig = {
  issuer: issuer,
  oauthPathPrefix: oauthPathPrefix,
  oktaDomain: process.env.OKTA_DOMAIN,
  clientId: process.env.OKTA_CLIENT_ID,
  clientSecret: process.env.OKTA_CLIENT_SECRET,
  redirectUri: process.env.OKTA_REDIRECT_URI || `http://localhost:${PORT}/callback`,
  logoutUri: process.env.OKTA_LOGOUT_URI || `http://localhost:${PORT}`,
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

const approvalConfig = {
  approvalApiAudience: process.env.APPROVAL_API_AUDIENCE,
  approvalApiScope: 'submit_approval'
}

//ExpressJS Init.
const app = express();

app.set('trust proxy', 1);
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
  const redisClient = redis.createClient({ url: process.env.REDIS_URL });
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
    const authUrl = new URL(`${oktaConfig.oauthPathPrefix}/v1/authorize`);
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
    const tokenUrl = `${oktaConfig.oauthPathPrefix}/v1/token`;
    
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
    xaaResult: req.session.xaaResult || null,
    approvalRequest: req.session.approvalRequest || null,
    sampleAudience: process.env.SAMPLE_AUDIENCE || '',
    sampleScope: process.env.SAMPLE_SCOPE || ''
  });
});

// XAA Token Exchange route - performs the Identity Assertion JWT Authorization Grant flow
app.post('/xaa-exchange', isAuthenticated, async (req, res) => {
  try {
    const { audience, scopes } = req.body;
    
    if (!audience) {
      throw new Error('Destination audience is required');
    }

    if (xaaClientConfig.clientId && !xaaPrivateKey) {
      throw new Error('XAA client ID is configured but private key is not available');
    }
    
    const idToken = req.session.tokens?.idToken;
    const accessToken = req.session.tokens?.accessToken;

    const { idJag, idJagPayload } = await util.getIdJag(idToken, accessToken, audience, scopes, xaaClientConfig, oktaConfig);
    console.log("JAG Retrieved Successfully!");
    console.log(idJag);
    
    // Step 2: Exchange the ID-JAG for an access token at the Resource Authorization Server via util
    const resourceTokenData = await util.exchangeJagForAccessToken(idJag, audience, xaaClientConfig);
    
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

// Begin Approval route - captures approval request intent from dashboard
app.post('/begin-approval', isAuthenticated, async (req, res) => {
  try {
    const { requestType } = req.body;

    if (!requestType) {
      throw new Error('Request type is required');
    }

    const idToken = req.session.tokens?.idToken;
    const accessToken = req.session.tokens?.accessToken;

    // Load action description mapping
    let actionDescriptions;
    try {
      const descPath = path.join(__dirname, 'actionDescriptions.json');
      const raw = fs.readFileSync(descPath, 'utf8');
      actionDescriptions = JSON.parse(raw);
    } catch (e) {
      throw new Error('Could not load actionDescriptions.json');
    }

    const actionDescription = actionDescriptions[requestType];

    // First step: initiate approval via external endpoint
    const initUrl = process.env.INIT_APPROVAL_URL;
    if (!initUrl) {
      throw new Error('INIT_APPROVAL_URL is not configured');
    }

    
    console.log("Obtaining JAG for raising an approval request...")
    const approvalIdJag = await util.getIdJag(idToken, accessToken, approvalConfig.approvalApiAudience, approvalConfig.approvalApiScope, xaaClientConfig, oktaConfig)
    
    console.log(approvalIdJag.idJag)

    console.log("JAG Obtrained... Obtaining accesss token.")
    const approvalAccessToken = await util.exchangeJagForAccessToken(approvalIdJag.idJag, approvalConfig.approvalApiAudience, xaaClientConfig)
    console.log("Access Token Obtained... making approval request now!")

    console.log(approvalAccessToken)

    const initResp = await fetch(initUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'authorization': `Bearer ${approvalAccessToken.access_token}`
      },
      body: JSON.stringify({
        scope: requestType,
        actionDescription: actionDescription
      })
    });

    let initData = await initResp.json();

    // Persist lightweight approval request context in session for UI feedback
    req.session.approvalRequest = {
      requestType,
      state: {
        success: initData.success,
        message: initData.message,
        requestId: initData.requestId,
        currentStatus: 'PENDING',
        decision: ''
      },
      requestedFor: req.session.userInfo?.email || null,
      timestamp: new Date().toISOString()
    };

    req.session.tokens.approvalAccessToken = approvalAccessToken.access_token

    await req.session.save();
    return res.redirect('/dashboard');
  } catch (error) {
    console.error('Begin Approval error:', error);
    req.session.approvalRequest = {
      error: error.message,
      timestamp: new Date().toISOString()
    };
    await req.session.save();
    return res.redirect('/dashboard');
  }
});

// Clear XAA result route
app.post('/clear-xaa', isAuthenticated, async (req, res) => {
  delete req.session.xaaResult;
  await req.session.save();
  res.redirect('/dashboard');
});

// Clear Elevated Approval state route
app.post('/clear-elevated', isAuthenticated, async (req, res) => {
  // Remove approval flow context and any related tokens
  delete req.session.approvalRequest;
  if (req.session.tokens) {
    delete req.session.tokens.approvalAccessToken;
    delete req.session.tokens.elevatedAccessToken;
  }
  await req.session.save();
  res.redirect('/dashboard');
});

// Poll for approval status route
app.post('/poll-request', isAuthenticated, async (req, res) => {
  try {
    const pollUrl = process.env.POLL_APPROVAL_URL;
    if (!pollUrl) {
      throw new Error('POLL_APPROVAL_URL is not configured');
    }

    const approvalToken = req.session.tokens?.approvalAccessToken;
    if (!approvalToken) {
      throw new Error('Approval access token is missing. Start a new approval first.');
    }

    const requestId = req.session.approvalRequest?.state?.requestId;
    if (!requestId) {
      throw new Error('Approval requestId is missing. Start a new approval first.');
    }

    const pollResp = await fetch(pollUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'authorization': `Bearer ${approvalToken}`
      },
      body: JSON.stringify({ requestId: requestId })
    });

    let pollData = await pollResp.json();
    
    if (!pollResp.ok) {
      const apiErr = pollData?.error || pollData?.message || `HTTP ${pollResp.status}`;
      throw new Error(`Polling failed: ${apiErr}`);
    }

    // Persist poll result alongside existing approvalRequest context
    req.session.approvalRequest.state.currentStatus = pollData.status
    req.session.approvalRequest.state.decision = pollData.decision

    await req.session.save();
    return res.redirect('/dashboard');

  } catch (error) {
    console.error('Poll Request error:', error);

    // Surface error in approvalRequest block for UI feedback
    req.session.approvalRequest.state.success = false
    req.session.approvalRequest.state.message = error.message
    await req.session.save();

    return res.redirect('/dashboard');
  }
});

// TODO: Retrieve Elevated Access Token route (stub)
// This route will retrieve an elevated access token after approval is APPROVED.
// Implementation will be added later.
app.post('/get-elevated-access', isAuthenticated, async (req, res) => {
  try {
    // Ensure approval flow context exists and has been approved
    const approvalCtx = req.session.approvalRequest;
    if (!approvalCtx || !approvalCtx.state || approvalCtx.state.decision !== 'APPROVED') {
      throw new Error('Approval has not been granted yet. Please complete approval before requesting elevated access.');
    }

    if (xaaClientConfig.clientId && !xaaPrivateKey) {
      throw new Error('XAA client ID is configured but private key is not available');
    }

    // Scopes for elevated access come from the approved request type selection
    const requestedScope = approvalCtx.requestType;
    if (!requestedScope) {
      throw new Error('Missing approved request type for elevated access scope');
    }

    // Audience is the approval API audience
    const audience = approvalConfig.approvalApiAudience;
    if (!audience) {
      throw new Error('APPROVAL_API_AUDIENCE is not configured');
    }

    const idToken = req.session.tokens?.idToken;
    const accessToken = req.session.tokens?.accessToken;

    // Obtain an ID-JAG for the approval API with the approved scope
    const { idJag, idJagPayload } = await util.getIdJag(
      idToken,
      accessToken,
      audience,
      requestedScope,
      xaaClientConfig,
      oktaConfig
    );

    // Exchange the ID-JAG for an elevated access token at the same audience
    const elevatedTokenData = await util.exchangeJagForAccessToken(idJag, audience, xaaClientConfig);

    if (elevatedTokenData.error) {
      // Persist error details inside approval context for UI/debugging
      req.session.approvalRequest.elevatedAccess = {
        success: false,
        error: `Elevated token exchange failed: ${elevatedTokenData.error} - ${elevatedTokenData.error_description || ''}`,
        idJag,
        idJagPayload,
        requestedAudience: audience,
        requestedScopes: requestedScope,
        timestamp: new Date().toISOString()
      };

      await req.session.save();
      return res.redirect('/dashboard');
    }

    const elevatedAccessToken = elevatedTokenData.access_token;
    const elevatedAccessTokenPayload = util.decodeJwtPayload(elevatedAccessToken);

    // Store the elevated token in session for potential subsequent API calls/UI
    req.session.tokens.elevatedAccessToken = elevatedAccessToken;
    req.session.approvalRequest.elevatedAccess = {
      success: true,
      idJag,
      idJagPayload,
      accessToken: elevatedAccessToken,
      accessTokenPayload: elevatedAccessTokenPayload,
      tokenType: elevatedTokenData.token_type,
      expiresIn: elevatedTokenData.expires_in,
      scope: elevatedTokenData.scope,
      requestedAudience: audience,
      requestedScopes: requestedScope,
      timestamp: new Date().toISOString()
    };

    await req.session.save();
    return res.redirect('/dashboard');
  } catch (error) {
    console.error('Get Elevated Access (stub) error:', error);
    return res.redirect('/dashboard');
  }
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
      const logoutUrl = new URL(`${oktaConfig.oauthPathPrefix}/v1/logout`);
      logoutUrl.searchParams.set('id_token_hint', idToken);
      logoutUrl.searchParams.set('post_logout_redirect_uri', oktaConfig.logoutUri);
      res.redirect(logoutUrl.toString());
    } else {
      res.redirect('/');
    }
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`XAA Playground is running at http://localhost:${PORT}`);
});
