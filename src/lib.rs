pub mod data_downloader;
pub mod model_trainer;

pub use data_downloader::download_whoop_data;
pub use model_trainer::{train_model, Model}; 