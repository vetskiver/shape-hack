#!/usr/bin/env python3

import requests
import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import time
import argparse

def get_public_key(base_url):
    """Get the public key from the TEE."""
    response = requests.get(f"{base_url}/api/pk")
    if response.status_code != 200:
        raise Exception(f"Failed to get public key: {response.text}")
    
    data = response.json()
    return data["public_key"]

def encrypt_credentials(public_key_pem, email, password):
    """Encrypt credentials using the public key."""
    # Load the public key
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
    )
    
    # Create the credentials string in the format expected by the server
    credentials = f"{email}:{password}"
    
    # Encrypt the credentials using PKCS#1 v1.5 padding
    encrypted = public_key.encrypt(
        credentials.encode(),
        padding.PKCS1v15()
    )
    
    # Return base64 encoded encrypted data
    return base64.b64encode(encrypted).decode()

def start_download(base_url, encrypted_credentials):
    """Start the download process with encrypted credentials."""
    response = requests.post(
        f"{base_url}/api/download",
        json={"encrypted_credentials": encrypted_credentials}
    )
    
    if response.status_code != 202:
        raise Exception(f"Failed to start download: {response.text}")
    
    return response.json()

def check_job_status(base_url, job_id):
    """Check the status of a download job."""
    response = requests.get(f"{base_url}/api/job/{job_id}")
    if response.status_code != 200:
        raise Exception(f"Failed to get job status: {response.text}")
    
    return response.json()

def main():
    parser = argparse.ArgumentParser(description='Interact with Whoop Data Scraper TEE')
    parser.add_argument('--url', default='http://localhost:8080', help='Base URL of the TEE API')
    parser.add_argument('--email', required=True, help='Whoop account email')
    parser.add_argument('--password', required=True, help='Whoop account password')
    args = parser.parse_args()

    try:
        print("Getting public key from TEE...")
        public_key = get_public_key(args.url)
        
        print("Encrypting credentials...")
        encrypted_credentials = encrypt_credentials(public_key, args.email, args.password)
        
        print("Starting download...")
        download_response = start_download(args.url, encrypted_credentials)
        job_id = download_response["job_id"]
        
        print(f"Download started with job ID: {job_id}")
        print("Checking job status...")
        
        # Poll for job status
        while True:
            status = check_job_status(args.url, job_id)
            print(f"Job status: {status['status']}")
            
            if status['status'] in ['Completed', 'Failed']:
                if status['message']:
                    print(f"Message: {status['message']}")
                break
            
            time.sleep(2)  # Wait 2 seconds before checking again
            
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main() 