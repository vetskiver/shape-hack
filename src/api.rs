use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use actix_cors::Cors;
use anyhow::Result;
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use uuid::Uuid;
use tokio::task;
use rsa::{RsaPublicKey, RsaPrivateKey, pkcs8::{EncodePublicKey, LineEnding}};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::cell::RefCell;
use once_cell::sync::Lazy;

use whoop_scraper::model_trainer::{train_model, Model};
use whoop_scraper::data_downloader::download_whoop_data;

// Job status type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JobStatus {
    Started,
    InProgress,
    Completed,
    Failed,
}

// Job result structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResult {
    pub job_id: String,
    pub status: JobStatus,
    pub message: Option<String>,
    pub folder_name: Option<String>,
}

// Training result structure
#[derive(Debug, Clone, Serialize)]
pub struct TrainingResult {
    pub model: Model,
    pub message: String,
}

// Request payload for download endpoint
#[derive(Debug, Deserialize)]
pub struct DownloadRequest {
    pub encrypted_credentials: String,  // Base64 encoded encrypted credentials
}

// Response for download endpoint
#[derive(Debug, Serialize)]
pub struct DownloadResponse {
    pub job_id: String,
    pub status: String,
}

// Public key response structure
#[derive(Debug, Serialize)]
pub struct PublicKeyResponse {
    pub public_key: String,
    pub timestamp: String,
}

// Attestation response structure
#[derive(Debug, Serialize)]
pub struct AttestationResponse {
    pub document: String,
    pub timestamp: String,
}

// Job tracking singleton
struct JobTracker {
    jobs: HashMap<String, JobResult>,
}

impl JobTracker {
    fn new() -> Self {
        Self {
            jobs: HashMap::new(),
        }
    }

    fn add_job(&mut self, job_id: &str) -> JobResult {
        let result = JobResult {
            job_id: job_id.to_string(),
            status: JobStatus::Started,
            message: None,
            folder_name: None,
        };
        self.jobs.insert(job_id.to_string(), result.clone());
        result
    }

    fn update_job(&mut self, job_id: &str, status: JobStatus, message: Option<String>, folder_name: Option<String>) -> Option<JobResult> {
        if let Some(job) = self.jobs.get_mut(job_id) {
            job.status = status;
            job.message = message;
            job.folder_name = folder_name;
            Some(job.clone())
        } else {
            None
        }
    }

    fn get_job(&self, job_id: &str) -> Option<JobResult> {
        self.jobs.get(job_id).cloned()
    }
}

// Get public key endpoint
async fn get_public_key() -> impl Responder {
    info!("Generating public key");
    
        match get_nitro_public_key() {
            Ok(pub_key) => {
            HttpResponse::Ok().json(PublicKeyResponse {
                    public_key: pub_key,
                    timestamp: chrono::Utc::now().to_rfc3339(),
            })
            }
            Err(e) => {
                error!("Failed to get public key: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to get public key",
                    "message": e.to_string()
            }))
        }
    }
}

static PRIVATE_KEY: Lazy<RwLock<Option<RsaPrivateKey>>> = Lazy::new(|| RwLock::new(None));

#[cfg(feature = "nsm")]
fn get_nitro_public_key() -> Result<String, String> {
    // Generate RSA key pair
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| format!("Failed to generate private key: {}", e))?;
    let public_key = RsaPublicKey::from(&private_key);
    
    // Store the private key in a static variable for later use
    {
        let mut key = PRIVATE_KEY.write().unwrap();
        *key = Some(private_key);
    }
    
    // Export public key in PEM format
    let pub_key_pem = public_key.to_public_key_pem(LineEnding::LF)
        .map_err(|e| format!("Failed to encode public key: {}", e))?;
    
    Ok(pub_key_pem)
}

#[cfg(not(feature = "nsm"))]
fn get_nitro_public_key() -> Result<String, String> {
    // For local development, generate a key pair just like in the enclave
    // This allows the same code to work in both environments
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| format!("Failed to generate private key: {}", e))?;
    let public_key = RsaPublicKey::from(&private_key);
    
    // Store the private key in a static variable for later use
    {
        let mut key = PRIVATE_KEY.write().unwrap();
        *key = Some(private_key);
    }
    
    // Export public key in PEM format
    let pub_key_pem = public_key.to_public_key_pem(LineEnding::LF)
        .map_err(|e| format!("Failed to encode public key: {}", e))?;
    
    Ok(pub_key_pem)
}

// Start a download job
async fn start_download(
    req: web::Json<DownloadRequest>,
    job_tracker: web::Data<Arc<Mutex<JobTracker>>>,
) -> impl Responder {
    let job_id = Uuid::new_v4().to_string();
    
    // Create and register the job
    {
        let mut tracker = job_tracker.lock().unwrap();
        tracker.add_job(&job_id);
    }
    
    // Decrypt credentials
    let credentials = match decrypt_credentials(&req.encrypted_credentials) {
        Ok(creds) => creds,
        Err(e) => {
            error!("Failed to decrypt credentials: {}", e);
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Failed to decrypt credentials",
                "message": e.to_string()
            }));
        }
    };
    
    // Parse credentials
    let (email, password) = match parse_credentials(&credentials) {
        Ok((e, p)) => (e, p),
        Err(e) => {
            error!("Failed to parse credentials: {}", e);
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Failed to parse credentials",
                "message": e.to_string()
            }));
        }
    };
    
    // Clone data for the task
    let job_tracker_clone = job_tracker.clone();
    let job_id_clone = job_id.clone();
    
    // Spawn a background task to run the download
    task::spawn(async move {
        // Update job status to in progress
        {
            let mut tracker = job_tracker_clone.lock().unwrap();
            tracker.update_job(&job_id_clone, JobStatus::InProgress, None, None);
        }
        
        // Run the download task
        match download_whoop_data(&email, &password).await {
            Ok(folder_name) => {
                info!("Download completed successfully for job {}", job_id_clone);
                let mut tracker = job_tracker_clone.lock().unwrap();
                tracker.update_job(
                    &job_id_clone, 
                    JobStatus::Completed, 
                    Some("Download completed".to_string()),
                    Some(folder_name)
                );
            }
            Err(e) => {
                error!("Download failed for job {}: {}", job_id_clone, e);
                let mut tracker = job_tracker_clone.lock().unwrap();
                tracker.update_job(&job_id_clone, JobStatus::Failed, Some(format!("Error: {}", e)), None);
            }
        }
    });
    
    // Return the job info to the client
    HttpResponse::Accepted().json(DownloadResponse {
        job_id,
        status: "started".to_string(),
    })
}

#[cfg(feature = "nsm")]
fn decrypt_credentials(encrypted: &str) -> Result<String, String> {
    use rsa::pkcs1v15::Pkcs1v15Encrypt;
    
    // Decode base64
    let encrypted_bytes = BASE64.decode(encrypted)
        .map_err(|e| format!("Failed to decode base64: {}", e))?;
    
    // Get the stored private key
    let key_guard = PRIVATE_KEY.read().unwrap();
    let private_key = key_guard.as_ref()
        .ok_or_else(|| "Private key not initialized".to_string())?;
    
    // Decrypt the data using PKCS#1 v1.5 padding
    let decrypted = private_key.decrypt(Pkcs1v15Encrypt, &encrypted_bytes)
        .map_err(|e| format!("Failed to decrypt: {}", e))?;
    
    // Convert decrypted bytes to string
    String::from_utf8(decrypted)
        .map_err(|e| format!("Failed to convert decrypted data to string: {}", e))
}

#[cfg(not(feature = "nsm"))]
fn decrypt_credentials(encrypted: &str) -> Result<String, String> {
    use rsa::pkcs1v15::Pkcs1v15Encrypt;
    
    // Decode base64
    let encrypted_bytes = BASE64.decode(encrypted)
        .map_err(|e| format!("Failed to decode base64: {}", e))?;
    
    // Get the stored private key
    let key_guard = PRIVATE_KEY.read().unwrap();
    let private_key = key_guard.as_ref()
        .ok_or_else(|| "Private key not initialized".to_string())?;
    
    // Decrypt the data using PKCS#1 v1.5 padding
    let decrypted = private_key.decrypt(Pkcs1v15Encrypt, &encrypted_bytes)
        .map_err(|e| format!("Failed to decrypt: {}", e))?;
    
    // Convert decrypted bytes to string
    String::from_utf8(decrypted)
        .map_err(|e| format!("Failed to convert decrypted data to string: {}", e))
}

fn parse_credentials(credentials: &str) -> Result<(String, String), String> {
    // Split credentials into email and password
    let parts: Vec<&str> = credentials.split(':').collect();
    if parts.len() != 2 {
        return Err("Invalid credentials format. Expected 'email:password'".to_string());
    }
    
    let email = parts[0].trim().to_string();
    let password = parts[1].trim().to_string();
    
    // Basic validation
    if email.is_empty() || password.is_empty() {
        return Err("Email and password cannot be empty".to_string());
    }
    
    if !email.contains('@') {
        return Err("Invalid email format".to_string());
    }
    
    Ok((email, password))
}

// Get job status
async fn get_job_status(
    path: web::Path<String>,
    job_tracker: web::Data<Arc<Mutex<JobTracker>>>,
) -> impl Responder {
    let job_id = path.into_inner();
    
    let tracker = job_tracker.lock().unwrap();
    if let Some(job) = tracker.get_job(&job_id) {
        HttpResponse::Ok().json(job)
    } else {
        HttpResponse::NotFound().json(serde_json::json!({
            "error": "Job not found"
        }))
    }
}

// Health check endpoint
async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

// Generate and return attestation document
async fn get_attestation() -> impl Responder {
    info!("Generating attestation document");
    
    #[cfg(feature = "nsm")]
    {
        // Attempt to get attestation
        match get_nitro_attestation() {
            Ok(doc_b64) => {
                // Return the attestation document
                return HttpResponse::Ok().json(AttestationResponse {
                    document: doc_b64,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });
            }
            Err(e) => {
                error!("Failed to get attestation document: {}", e);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to get attestation document",
                    "message": e.to_string()
                }));
            }
        }
    }
    
    #[cfg(not(feature = "nsm"))]
    {
        // Return an error indicating that NSM is not available
        // In production you should only run this in an enclave
        HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "NSM device not available - running outside enclave",
            "message": "This code needs to run inside a Nitro Enclave to generate real attestation documents"
        }))
    }
}

#[cfg(feature = "nsm")]
pub fn get_nitro_attestation() -> Result<String, String> {
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver;

    // 1. Initialize
    let fd = driver::nsm_init();
    if fd < 0 {
        return Err("Failed to open /dev/nsm".into());
    }

    // 2. Request attestation
    let resp = driver::nsm_process_request(
        fd,
        Request::Attestation { user_data: None, nonce: None, public_key: None },
    );

    // 3. Close the device
    driver::nsm_exit(fd);

    // 4. Handle response
    let cose = match resp {
        Response::Attestation { document } => document,
        Response::Error(code)               => return Err(format!("NSM error: {:?}", code)),
        other                               => return Err(format!("Unexpected NSM response: {:?}", other)),
    };

    // 5. Base64 encode the raw COSE document directly
    Ok(BASE64.encode(&cose))
}

// Train model endpoint
async fn train_model_endpoint() -> impl Responder {
    info!("Starting model training with all available data");
    
    match train_model("downloads") {
        Ok(model) => {
            info!("Model training completed successfully");
            HttpResponse::Ok().json(TrainingResult {
                model,
                message: "Model training completed successfully".to_string(),
            })
        }
        Err(e) => {
            error!("Model training failed: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Model training failed",
                "message": e.to_string()
            }))
        }
    }
}

// Start the API server
pub async fn start_server(port: u16) -> Result<()> {
    info!("Starting API server on port {}", port);
    
    // Create job tracker
    let job_tracker = Arc::new(Mutex::new(JobTracker::new()));
    
    // Start HTTP server
    HttpServer::new(move || {
        // Configure CORS
        let cors = Cors::default()
            .allowed_origin("http://3.145.135.218:3000")
            .allowed_methods(vec!["GET", "POST", "OPTIONS"])
            .allowed_headers(vec![
                "Content-Type",
                "Authorization",
                "Accept",
                "Origin",
                "X-Requested-With"
            ])
            .expose_headers(vec!["content-type", "content-length"])
            .max_age(3600)
            .supports_credentials();

        App::new()
            .wrap(cors)  // Add CORS middleware
            .app_data(web::Data::new(job_tracker.clone()))
            .route("/health", web::get().to(health_check))
            .route("/api/pk", web::get().to(get_public_key))
            .route("/api/download", web::post().to(start_download))
            .route("/api/job/{job_id}", web::get().to(get_job_status))
            .route("/api/train", web::post().to(train_model_endpoint))
            .route("/api/attestation", web::get().to(get_attestation))
    })
    .bind(format!("0.0.0.0:{}", port))?
    .run()
    .await?;
    
    Ok(())
} 