use anyhow::{anyhow, Result};
use std::fs;
use std::path::Path;
use walkdir::WalkDir;
use csv::ReaderBuilder;
use serde::{Deserialize, Serialize};
use log::info;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Model {
    pub coefficients: Vec<f64>,
    pub intercept: f64,
}

pub fn train_model(downloads_dir: &str) -> Result<Model> {
    info!("Starting model training with data from all users");
    
    let mut all_x_data = Vec::new();
    let mut all_y_data = Vec::new();
    
    // Walk through all user directories
    for entry in fs::read_dir(downloads_dir)? {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_dir() && path.file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with("WHOOP-user-"))
            .unwrap_or(false) 
        {
            // Look for metrics.csv in the Health folder
            let metrics_path = path.join("Health").join("metrics.csv");
            if metrics_path.exists() {
                info!("Processing metrics from: {}", metrics_path.display());
                
                // Read and parse CSV
                let file = fs::File::open(&metrics_path)?;
                let mut rdr = ReaderBuilder::new()
                    .has_headers(true)
                    .from_reader(file);
                
                // Parse records
                for result in rdr.records() {
                    let record = result?;
                    let hr: f64 = record[0].parse()?;
                    let accel_x: f64 = record[1].parse()?;
                    let accel_y: f64 = record[2].parse()?;
                    let accel_z: f64 = record[3].parse()?;
                    let skin_temp: f64 = record[4].parse()?;
                    
                    all_x_data.push(vec![skin_temp, accel_x, accel_y, accel_z]);
                    all_y_data.push(hr);
                }
            }
        }
    }
    
    let n_samples = all_x_data.len();
    if n_samples == 0 {
        return Err(anyhow!("No training data found in any user directory"));
    }
    
    info!("Total samples collected: {}", n_samples);
    
    // Normalize features
    let mut normalized_x_data = Vec::new();
    let n_features = 4;
    
    // Calculate mean and std for each feature
    let mut means = vec![0.0; n_features];
    let mut stds = vec![0.0; n_features];
    
    // Calculate means
    for sample in &all_x_data {
        for (i, &value) in sample.iter().enumerate() {
            means[i] += value;
        }
    }
    for mean in &mut means {
        *mean /= n_samples as f64;
    }
    
    // Calculate standard deviations
    for sample in &all_x_data {
        for (i, &value) in sample.iter().enumerate() {
            stds[i] += (value - means[i]).powi(2);
        }
    }
    for std in &mut stds {
        *std = (*std / n_samples as f64).sqrt();
        if *std < 1e-10 {
            *std = 1.0;
        }
    }
    
    // Normalize features
    for sample in &all_x_data {
        let mut normalized_sample = Vec::new();
        for (i, &value) in sample.iter().enumerate() {
            normalized_sample.push((value - means[i]) / stds[i]);
        }
        normalized_x_data.push(normalized_sample);
    }
    
    info!("Starting model training with {} samples and {} features", n_samples, n_features);
    
    // Initialize coefficients and intercept
    let mut coefficients = vec![0.0; n_features];
    let mut intercept = 0.0;
    
    // Gradient descent
    let learning_rate = 0.00001;
    let n_iterations = 100;
    let gradient_clip = 1.0;
    
    for iteration in 0..n_iterations {
        let mut total_error = 0.0;
        
        for i in 0..n_samples {
            let prediction = intercept + coefficients.iter()
                .zip(&normalized_x_data[i])
                .map(|(c, x)| c * x)
                .sum::<f64>();
            
            let error = prediction - all_y_data[i];
            total_error += error.abs();
            
            // Update intercept with gradient clipping
            let grad_intercept = error;
            intercept -= learning_rate * grad_intercept.clamp(-gradient_clip, gradient_clip);
            
            // Update coefficients with gradient clipping
            for j in 0..n_features {
                let grad_coef = error * normalized_x_data[i][j];
                coefficients[j] -= learning_rate * grad_coef.clamp(-gradient_clip, gradient_clip);
            }
        }
        
        if (iteration + 1) % 10 == 0 {
            info!("Completed {} iterations of gradient descent, average error: {}", 
                 iteration + 1, total_error / n_samples as f64);
        }
    }
    
    // Denormalize coefficients
    for (i, coef) in coefficients.iter_mut().enumerate() {
        *coef = *coef / stds[i];
    }
    intercept = intercept - coefficients.iter()
        .zip(&means)
        .map(|(c, m)| c * m)
        .sum::<f64>();
    
    let model = Model {
        coefficients,
        intercept,
    };
    
    info!("Model training completed successfully");
    Ok(model)
} 