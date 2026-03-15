import axios from 'axios';

const API_BASE_URL = 'http://3.145.135.218:8080';

export const whoopApi = {
  getPublicKey: async () => {
    const response = await axios.get(`${API_BASE_URL}/api/pk`);
    return response.data.public_key;
  },

  getAttestation: async () => {
    console.log('Getting attestation');
    const response = await axios.get(`${API_BASE_URL}/api/attestation`);
    return response.data;
  },

  startDownload: async (encryptedCredentials) => {
    const response = await axios.post(`${API_BASE_URL}/api/download`, {
      encrypted_credentials: encryptedCredentials
    });
    return response.data;
  },

  checkJobStatus: async (jobId) => {
    const response = await axios.get(`${API_BASE_URL}/api/job/${jobId}`);
    return response.data;
  },

  trainModel: async () => {
    const response = await axios.post(`${API_BASE_URL}/api/train`);
    return response.data;
  }
}; 