use anyhow::Result;
use structopt::StructOpt;
use log::info;
mod data_downloader;
mod api;

#[derive(StructOpt)]
#[structopt(name = "whoop_scraper", about = "Download Whoop data")]
enum Command {
    #[structopt(name = "download", about = "Download Whoop data")]
    Download {
        #[structopt(help = "Your Whoop account email")]
        email: String,
        #[structopt(help = "Your Whoop account password")]
        password: String,
    },
    
    #[structopt(name = "server", about = "Start API server")]
    Server {
        #[structopt(long, help = "Port to run server on", default_value = "8080")]
        port: u16,
    },

    #[structopt(name = "test-attestation", about = "Test Nitro attestation functionality")]
    TestAttestation,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();
    info!("Starting Whoop Data Downloader");

    // Parse command line arguments
    let command = Command::from_args();

    match command {
        Command::Download { email, password } => {
            info!("Starting download process");
            data_downloader::download_whoop_data(&email, &password).await?;
        },
        Command::Server { port } => {
            info!("Starting API server on port {}", port);
            api::start_server(port).await?;
        },
        Command::TestAttestation => {
            info!("Testing Nitro attestation functionality");
            #[cfg(feature = "nsm")]
            {
                match api::get_nitro_attestation() {
                    Ok(doc) => {
                        info!("Successfully got attestation document of length {}", doc.len());
                        info!("First 100 chars: {}", &doc[..std::cmp::min(100, doc.len())]);
                    },
                    Err(e) => {
                        eprintln!("Error getting attestation: {}", e);
                    }
                }
            }
            
            #[cfg(not(feature = "nsm"))]
            {
                eprintln!("Not running in an enclave. Cannot test attestation functionality.");
                eprintln!("Build with --features nsm and run in a Nitro Enclave to test attestation.");
            }
        }
    }

    Ok(())
} 