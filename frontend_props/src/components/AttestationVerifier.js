import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  CircularProgress,
  Alert,
  Paper,
  Button,
  List,
  ListItem,
  ListItemText,
  TextField
} from '@mui/material';
import { whoopApi } from '../api/whoopApi';
import { verifyAttestation } from '../utils/crypto';

const AttestationVerifier = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [attestationStatus, setAttestationStatus] = useState(null);
  const [attestationDoc, setAttestationDoc] = useState(null);
  const [lastVerified, setLastVerified] = useState(null);

  const fetchAttestation = async () => {
    setLoading(true);
    setError('');
    try {
      // Get attestation document
      const response = await whoopApi.getAttestation();
      console.log('Received attestation:', response);
      
      // Validate response structure
      if (!response || !response.document || !response.timestamp) {
        throw new Error('Invalid response format from server');
      }
      
      setAttestationDoc(response);
      setLastVerified(new Date().toISOString());
      
      // Automatically verify the attestation when we get it
      try {
        const isValid = await verifyAttestation(response);
        setAttestationStatus(isValid);
      } catch (verifyErr) {
        console.error('Verification error:', verifyErr);
        setError(verifyErr.message || 'Failed to verify environment');
        setAttestationStatus(false);
      }
    } catch (err) {
      console.error('Fetch error:', err);
      setError('Failed to fetch attestation document');
      setAttestationStatus(false);
    } finally {
      setLoading(false);
    }
  };

  const verifyEnvironment = async () => {
    if (!attestationDoc) {
      setError('No attestation document to verify');
      return;
    }

    setLoading(true);
    setError('');
    try {
      const isValid = await verifyAttestation(attestationDoc);
      setAttestationStatus(isValid);
    } catch (err) {
      console.error('Verification error:', err);
      setError(err.message || 'Failed to verify environment');
      setAttestationStatus(false);
    } finally {
      setLoading(false);
    }
  };

  // Fetch attestation on component mount
  useEffect(() => {
    fetchAttestation();
  }, []);

  return (
    <Paper elevation={3} sx={{ p: 4, maxWidth: 800, mx: 'auto', mt: 4 }}>
      <Typography variant="h6" gutterBottom>
        Environment Security Status
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Box sx={{ my: 2 }}>
        {loading ? (
          <CircularProgress />
        ) : (
          <>
            {attestationStatus !== null && (
              <Alert severity={attestationStatus ? "success" : "error"} sx={{ mb: 2 }}>
                Environment is {attestationStatus ? "verified" : "not verified"}
              </Alert>
            )}
            
            {attestationDoc && (
              <Box sx={{ mt: 2 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Attestation Document:
                </Typography>
                <TextField
                  multiline
                  fullWidth
                  rows={8}
                  value={JSON.stringify(attestationDoc, null, 2)}
                  variant="outlined"
                  InputProps={{
                    readOnly: true,
                    sx: { fontFamily: 'monospace', fontSize: '0.875rem' }
                  }}
                  sx={{ mb: 2 }}
                />
                
                <Typography variant="subtitle2" gutterBottom>
                  Document Details:
                </Typography>
                <List dense>
                  <ListItem>
                    <ListItemText 
                      primary="Timestamp"
                      secondary={attestationDoc.timestamp}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText 
                      primary="Document Size"
                      secondary={`${attestationDoc.document.length} bytes`}
                    />
                  </ListItem>
                </List>
              </Box>
            )}
            
            {lastVerified && (
              <Typography variant="body2" sx={{ mt: 2, color: 'text.secondary' }}>
                Last fetched: {new Date(lastVerified).toLocaleString()}
              </Typography>
            )}

            <Box sx={{ mt: 2, display: 'flex', gap: 2, justifyContent: 'center' }}>
              <Button
                variant="outlined"
                onClick={fetchAttestation}
                disabled={loading}
              >
                Fetch New Attestation
              </Button>
              <Button
                variant="contained"
                onClick={verifyEnvironment}
                disabled={loading || !attestationDoc}
                color="primary"
              >
                Verify Attestation
              </Button>
            </Box>
          </>
        )}
      </Box>
    </Paper>
  );
};

export default AttestationVerifier; 