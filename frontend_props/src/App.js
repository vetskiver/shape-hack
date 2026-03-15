import React, { useState } from 'react';
import { Container, Box, Typography, Button } from '@mui/material';
import LoginForm from './components/LoginForm';
import AttestationVerifier from './components/AttestationVerifier';
import { whoopApi } from './api/whoopApi';

function App() {
  const [downloadComplete, setDownloadComplete] = useState(false);
  const [trainingStarted, setTrainingStarted] = useState(false);

  const handleLoginSuccess = (status) => {
    setDownloadComplete(true);
  };

  const handleStartTraining = async () => {
    try {
      setTrainingStarted(true);
      await whoopApi.trainModel();
    } catch (error) {
      console.error('Training failed:', error);
    }
  };

  return (
    <Container maxWidth="md">
      <Box sx={{ my: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom align="center">
          WHOOP Data Downloader
        </Typography>

        <AttestationVerifier />

        {!downloadComplete ? (
          <LoginForm onLoginSuccess={handleLoginSuccess} />
        ) : (
          <Box sx={{ textAlign: 'center', mt: 4 }}>
            <Typography variant="h6" gutterBottom color="success.main">
              Download Complete!
            </Typography>
            
            {!trainingStarted && (
              <Button
                variant="contained"
                onClick={handleStartTraining}
                sx={{ mt: 2 }}
              >
                Start Training Model
              </Button>
            )}

            {trainingStarted && (
              <Typography variant="body1" sx={{ mt: 2 }}>
                Model training has started...
              </Typography>
            )}
          </Box>
        )}
      </Box>
    </Container>
  );
}

export default App; 