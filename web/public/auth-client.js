// Native browser WebAuthn. Server challenges and verification remain authoritative.
function bytes(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

function encoded(value) {
  let binary = '';
  for (const byte of new Uint8Array(value)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function createPasskey(options, signal) {
  const publicKey = {
    ...options,
    challenge: bytes(options.challenge),
    user: { ...options.user, id: bytes(options.user.id) },
    excludeCredentials: (options.excludeCredentials ?? []).map((entry) => ({ ...entry, id: bytes(entry.id) })),
  };
  const credential = await navigator.credentials.create({ publicKey, signal });
  if (!credential) throw new Error('The browser did not create a passkey.');
  return {
    id: credential.id,
    rawId: encoded(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      attestationObject: encoded(credential.response.attestationObject),
      clientDataJSON: encoded(credential.response.clientDataJSON),
      transports: credential.response.getTransports?.() ?? [],
    },
  };
}

export async function getPasskey(options, signal) {
  const publicKey = {
    ...options,
    challenge: bytes(options.challenge),
    allowCredentials: (options.allowCredentials ?? []).map((entry) => ({ ...entry, id: bytes(entry.id) })),
  };
  const credential = await navigator.credentials.get({ publicKey, signal });
  if (!credential) throw new Error('The browser did not return a passkey.');
  return {
    id: credential.id,
    rawId: encoded(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      authenticatorData: encoded(credential.response.authenticatorData),
      clientDataJSON: encoded(credential.response.clientDataJSON),
      signature: encoded(credential.response.signature),
      userHandle: credential.response.userHandle ? encoded(credential.response.userHandle) : null,
    },
  };
}
