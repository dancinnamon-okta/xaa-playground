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
  console.log("Token used for client authentication")
  console.log(token)
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