import forge from 'node-forge';

export const encryptCredentials = (publicKeyPEM, email, password) => {
  try {
    // Parse the PEM public key
    const publicKey = forge.pki.publicKeyFromPem(publicKeyPEM);
    
    // Create credentials string
    const credentials = `${email}:${password}`;
    
    // Convert string to bytes
    const bytes = forge.util.encodeUtf8(credentials);
    
    // Encrypt using PKCS#1 v1.5
    const encrypted = publicKey.encrypt(bytes, 'RSAES-PKCS1-V1_5');
    
    // Convert to base64
    return forge.util.encode64(encrypted);
  } catch (error) {
    console.error('Encryption error:', error);
    throw new Error('Failed to encrypt credentials');
  }
};

export const verifyAttestation = async (attestationResponse) => {
  try {
    if (!attestationResponse || !attestationResponse.document || !attestationResponse.timestamp) {
      throw new Error('Invalid attestation format');
    }

    // Parse the base64 document
    const decodedDoc = forge.util.decode64(attestationResponse.document);
    
    // In a production environment, you would:
    // 1. Parse the CBOR-encoded document
    // 2. Extract and verify PCR measurements
    // 3. Validate the certificate chain
    // 4. Verify the document signature
    // 5. Check the timestamp is recent
    
    // For now, we'll do basic validation of the structure
    if (decodedDoc.length < 100) { // Basic size check
      throw new Error('Attestation document too small');
    }

    // Check if timestamp is recent (within last hour)
    const timestamp = new Date(attestationResponse.timestamp);
    const now = new Date();
    const hourAgo = new Date(now.getTime() - 60 * 60 * 1000);
    
    if (timestamp < hourAgo) {
      throw new Error('Attestation document is too old');
    }

    return true;
  } catch (error) {
    console.error('Attestation verification error:', error);
    throw new Error(`Failed to verify attestation: ${error.message}`);
  }
}; 