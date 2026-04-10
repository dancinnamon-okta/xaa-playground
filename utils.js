// Helper function to create a client_assertion JWT for private_key_jwt authentication
const njwt = require('njwt');
const crypto = require('crypto');

function createClientAssertionJwt(xaaClientConfig, audience) {
  if (!xaaClientConfig.privateKey) {
    throw new Error('XAA client private key not configured');
  }

  const claims = {
    "iss": xaaClientConfig.clientId,
    "sub": xaaClientConfig.clientId,
    "aud": audience
  }

  var token = njwt.create(claims, xaaClientConfig.privateKey, "RS256")

  token.setHeader('alg', 'RS256')
  token.setHeader('typ', 'JWT')
  token.setHeader('kid', xaaClientConfig.privateKeyId)

  var now = new Date().getTime()
  var exp = token.body.iat * 1000 + (3 * 60 * 1000)
  token.setExpiration(exp)
  token.setJti(crypto.randomUUID())
  token = token.compact()

  return token
}

// Helper function to decode JWT payload
function decodeJwtPayload(token) {
  try {
    // JWT format: header.payload.signature
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }
    // Decode the payload (second part) from base64url
    const payload = parts[1];
    const decoded = Buffer.from(payload, 'base64url').toString('utf8');
    return JSON.parse(decoded);
  } catch (error) {
    console.debug('Error decoding JWT:', error.message);
    return null;
  }
}

module.exports.createClientAssertionJwt = createClientAssertionJwt
module.exports.decodeJwtPayload = decodeJwtPayload

// Perform ID-JAG exchange with Okta org-level auth server
// Inputs:
// - idToken: string | undefined
// - accessToken: string | undefined
// - audience: string
// - scopes: string
// - xaaClientConfig: object (expects clientId, privateKey, privateKeyId)
// - oktaConfig: object (expects oktaDomain, issuer)
// Returns: { idJag, idJagPayload }
async function getIdJag(idToken, accessToken, audience, scopes, xaaClientConfig, oktaConfig) {
  if (!audience) {
    throw new Error('Destination audience is required');
  }

  const xaaClientId = xaaClientConfig.clientId;

  if (xaaClientConfig.clientId && !xaaClientConfig.privateKey) {
    throw new Error('XAA client ID is configured but private key is not available');
  }

  if (!idToken && !accessToken) {
    throw new Error('No ID token available for exchange');
  }

  const tokenExchangeUrl = `${oktaConfig.oktaDomain}/oauth2/v1/token`;

  const useIdToken = oktaConfig.issuer == oktaConfig.oktaDomain;
  const subjectToken = useIdToken ? idToken : accessToken;
  const subjectTokenType = useIdToken
    ? 'urn:ietf:params:oauth:token-type:id_token'
    : 'urn:ietf:params:oauth:token-type:access_token';

  const tokenExchangeParams = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    requested_token_type: 'urn:ietf:params:oauth:token-type:id-jag',
    audience: audience,
    subject_token: subjectToken,
    subject_token_type: subjectTokenType,
    client_id: xaaClientId,
    scope: scopes.trim()
  });

  const clientAssertion = createClientAssertionJwt(xaaClientConfig, tokenExchangeUrl);
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

  const idJag = tokenExchangeData.access_token;
  const idJagPayload = decodeJwtPayload(idJag);

  return { idJag, idJagPayload };
}

module.exports.getIdJag = getIdJag

// Exchange ID-JAG for access token at the Resource Authorization Server
// Inputs:
// - idJag: string (the Identity Assertion JWT Authorization Grant)
// - audience: string (base URL of the resource authorization server)
// - xaaClientConfig: object (expects clientId, privateKey, privateKeyId)
// Returns: parsed JSON response from the resource server token endpoint
async function exchangeJagForAccessToken(idJag, audience, xaaClientConfig) {
  if (!idJag) {
    throw new Error('ID-JAG is required');
  }
  if (!audience) {
    throw new Error('Audience is required to exchange JAG for access token');
  }
  if (!xaaClientConfig?.clientId) {
    throw new Error('XAA client configuration missing clientId');
  }

  const resourceTokenUrl = `${audience}/v1/token`;

  const resourceTokenParams = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: idJag,
    client_id: xaaClientConfig.clientId
  });

  const resourceClientAssertion = createClientAssertionJwt(xaaClientConfig, resourceTokenUrl);
  resourceTokenParams.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
  resourceTokenParams.set('client_assertion', resourceClientAssertion);

  const resourceTokenResponse = await fetch(resourceTokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: resourceTokenParams
  });

  return resourceTokenResponse.json();
}

module.exports.exchangeJagForAccessToken = exchangeJagForAccessToken