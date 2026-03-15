import React, { useState, useEffect } from 'react';
import { 
  Box, 
  TextField, 
  Button, 
  Typography, 
  CircularProgress,
  Alert,
  Paper
} from '@mui/material';
import { whoopApi } from '../api/whoopApi';
import { encryptCredentials } from '../utils/crypto';

const LoginForm = ({ onLoginSuccess }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [publicKey, setPublicKey] = useState('');
  const [jobId, setJobId] = useState(null);

  useEffect(() => {
    // Get public key when component mounts
    const fetchPublicKey = async () => {
      try {
        const key = await whoopApi.getPublicKey();
        setPublicKey(key);
      } catch (err) {
        setError('Failed to get encryption key from server');
      }
    };
    fetchPublicKey();
  }, []);

  useEffect(() => {
    // Poll job status if jobId exists
    let interval;
    if (jobId) {
      interval = setInterval(async () => {
        try {
          const status = await whoopApi.checkJobStatus(jobId);
          if (status.status === 'Completed') {
            clearInterval(interval);
            onLoginSuccess(status);
          } else if (status.status === 'Failed') {
            clearInterval(interval);
            setError(status.message || 'Download failed');
            setLoading(false);
          }
        } catch (err) {
          clearInterval(interval);
          setError('Failed to check job status');
          setLoading(false);
        }
      }, 2000);
    }
    return () => interval && clearInterval(interval);
  }, [jobId, onLoginSuccess]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      // Encrypt credentials
      const encrypted = encryptCredentials(publicKey, email, password);

      // Start download
      const response = await whoopApi.startDownload(encrypted);
      setJobId(response.job_id);
    } catch (err) {
      setError(err.message || 'Failed to start download');
      setLoading(false);
    }
  };

  return (
    <Paper elevation={3} sx={{ p: 4, maxWidth: 400, mx: 'auto', mt: 4 }}>
      <Box component="form" onSubmit={handleSubmit}>
        <Typography variant="h5" gutterBottom>
          WHOOP Login
        </Typography>
        
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <TextField
          fullWidth
          label="Email"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          margin="normal"
          required
          disabled={loading}
        />

        <TextField
          fullWidth
          label="Password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          margin="normal"
          required
          disabled={loading}
        />

        <Button
          fullWidth
          type="submit"
          variant="contained"
          disabled={loading || !publicKey}
          sx={{ mt: 2 }}
        >
          {loading ? <CircularProgress size={24} /> : 'Download Data'}
        </Button>

        {loading && (
          <Typography sx={{ mt: 2, textAlign: 'center' }}>
            Downloading your data...
          </Typography>
        )}
      </Box>
    </Paper>
  );
};

export default LoginForm; 