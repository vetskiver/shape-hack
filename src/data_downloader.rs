use anyhow::{anyhow, Result};
use headless_chrome::{Browser, LaunchOptionsBuilder, Tab};
use headless_chrome::protocol::cdp::Browser::{
    SetDownloadBehavior,
    SetDownloadBehaviorBehaviorOption,
};
use log::{info, debug, warn, error};
use std::{thread, time::Duration, ffi::OsStr, path::PathBuf, fs, time::Instant};
use serde_json;
use zip::ZipArchive;
use rand;

// Helper function to wait with a timeout
fn wait_with_timeout(seconds: u64) {
    thread::sleep(Duration::from_secs(seconds));
}

// For shorter waits between UI interactions
fn short_wait() {
    thread::sleep(Duration::from_millis(300));
}

// For medium waits after page navigation
fn medium_wait() {
    thread::sleep(Duration::from_millis(500));
}

// For longer UI transitions that need more time
fn long_wait() {
    thread::sleep(Duration::from_secs(5));
}

// Wait for download to complete by checking for new files
fn wait_for_download(download_dir: &str, timeout_seconds: u64) -> Result<String> {
    info!("Waiting for download to complete (timeout: {} seconds)...", timeout_seconds);
    
    let start_time = Instant::now();
    let timeout = Duration::from_secs(timeout_seconds);
    
    // Get initial file count in download directory
    let initial_files = match fs::read_dir(download_dir) {
        Ok(entries) => entries.count(),
        Err(e) => {
            error!("Failed to read download directory {}: {}", download_dir, e);
            return Err(anyhow!("Failed to read download directory"));
        }
    };
    
    info!("Initial file count in download directory: {}", initial_files);
    
    // Loop until timeout to check for new files
    while start_time.elapsed() < timeout {
        // Check every second
        thread::sleep(Duration::from_secs(1));
        
        // Get current file count
        match fs::read_dir(download_dir) {
            Ok(entries) => {
                let current_files = entries.count();
                
                // If new files appeared
                if current_files > initial_files {
                    info!("Download in progress! New files detected in {}", download_dir);
                    
                    // Look for WHOOP-export.zip
                    let file_path = fs::read_dir(download_dir)?
                        .filter_map(Result::ok)
                        .find(|entry| {
                            entry.path().file_name()
                                .and_then(|n| n.to_str())
                                .map(|name| name == "WHOOP-export.zip")
                                .unwrap_or(false)
                        })
                        .map(|entry| entry.path());
                    
                    if let Some(path) = file_path {
                        info!("Found WHOOP-export.zip file");
                        
                        // Generate random number for the folder and zip name
                        let random_number = rand::random::<u32>();
                        let folder_name = format!("WHOOP-user-{}", random_number);
                        let zip_name = format!("{}.zip", folder_name);
                        
                        // Create the subfolder
                        let subfolder_path = std::path::PathBuf::from(download_dir).join(&folder_name);
                        info!("Creating subfolder: {}", subfolder_path.display());
                        fs::create_dir_all(&subfolder_path)?;
                        
                        // Rename the zip file
                        let new_path = path.with_file_name(&zip_name);
                        info!("Renaming {} to {}", path.display(), new_path.display());
                        fs::rename(&path, &new_path)?;
                        
                        // Now process the zip file
                        info!("Opening zip file: {}", new_path.display());
                        let file = fs::File::open(&new_path)?;
                        let mut archive = ZipArchive::new(file)?;
                        
                        info!("Extracting zip contents to: {}", subfolder_path.display());
                        archive.extract(&subfolder_path)?;
                        
                        info!("Data extraction completed successfully");
                        return Ok(folder_name);
                    }
                }
            },
            Err(e) => {
                error!("Failed to read download directory {}: {}", download_dir, e);
            }
        }
        
        // Every 10 seconds, output a progress message
        if start_time.elapsed().as_secs() % 10 == 0 {
            info!("Still waiting for download... ({} seconds elapsed)", 
                 start_time.elapsed().as_secs());
        }
    }
    
    info!("Download wait timed out after {} seconds", timeout_seconds);
    Err(anyhow!("Download timeout"))
}

// Helper function to click a button using JavaScript with various strategies
async fn js_click_button(tab: &Tab, step_name: &str, button_text: &str, button_id: Option<&str>, button_class: Option<&str>) -> Result<bool> {
    info!("Attempting JavaScript click for step: {} with text: {}", step_name, button_text);
    
    let js_script = format!(
        r#"
        (function() {{
            // Strategy 1: Try by ID if provided
            {id_strategy}
            
            // Strategy 2: Try by class if provided
            {class_strategy}
            
            // Strategy 3: Try by button text content
            const buttonsByText = Array.from(document.querySelectorAll('button'))
                .filter(b => b.textContent && b.textContent.includes('{text}'));
            
            if (buttonsByText.length > 0) {{
                console.log('Found button by text: ' + '{text}');
                buttonsByText[0].click();
                return true;
            }}
            
            // Strategy 4: Try by any clickable element with matching text
            const clickableElements = Array.from(document.querySelectorAll('button, a, [role="button"], [tabindex="0"]'))
                .filter(el => el.textContent && el.textContent.includes('{text}'));
                
            if (clickableElements.length > 0) {{
                console.log('Found clickable element by text: ' + '{text}');
                clickableElements[0].click();
                return true;
            }}
            
            return false;
        }})()
        "#,
        text = button_text,
        id_strategy = if let Some(id) = button_id {
            format!(
                r#"
                const elementById = document.getElementById('{}');
                if (elementById) {{
                    console.log('Found element by ID: {}');
                    elementById.click();
                    return true;
                }}
                "#,
                id, id
            )
        } else {
            String::from("// No ID provided")
        },
        class_strategy = if let Some(class_name) = button_class {
            format!(
                r#"
                const elementsByClass = document.getElementsByClassName('{}');
                if (elementsByClass.length > 0) {{
                    console.log('Found element by class: {}');
                    elementsByClass[0].click();
                    return true;
                }}
                "#,
                class_name, class_name
            )
        } else {
            String::from("// No class provided")
        }
    );
    
    match tab.evaluate(&js_script, false) {
        Ok(result) => {
            let success = match result.value {
                Some(serde_json::Value::Bool(b)) => b,
                _ => false,
            };
            
            if success {
                info!("Successfully clicked element using JavaScript for step: {}", step_name);
                medium_wait();
                return Ok(true);
            }
        },
        Err(e) => {
            warn!("JavaScript click evaluation failed for step {}: {:?}", step_name, e);
        }
    }
    
    Ok(false)
}

async fn click_element(tab: &Tab, selectors: &[&str], step_name: &str) -> Result<bool> {
    info!("Trying to click on element in step: {}", step_name);
    
    for attempt in 1..=3 {
        info!("Attempt {} to find and click element for step: {}", attempt, step_name);
        
        // First, try to find any elements matching the selectors
        let mut found_elements = vec![];
        
        for selector in selectors {
            if let Ok(elements) = tab.find_elements(selector) {
                if !elements.is_empty() {
                    info!("Found {} elements with selector: {}", elements.len(), selector);
                    
                    for (i, _) in elements.iter().enumerate() {
                        found_elements.push((selector, i));
                    }
                }
            }
        }
        
        info!("Found {} potential elements to click", found_elements.len());
        
        // Now try to click on each found element
        for (selector, index) in found_elements {
            if let Ok(elements) = tab.find_elements(selector) {
                if index < elements.len() {
                    info!("Attempting to click element {} with selector: {}", index, selector);
                    short_wait();
                    
                    match elements[index].click() {
                        Ok(_) => {
                            info!("Successfully clicked element {} with selector: {}", index, selector);
                            return Ok(true);
                        },
                        Err(_) => {
                            // Try JavaScript click as a fallback
                            if let Ok(_) = tab.evaluate(&format!(
                                "document.querySelectorAll('{}')[{}].click()", selector, index
                            ), false) {
                                info!("Successfully clicked element using JavaScript");
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }
        
        // If we didn't click after trying all elements, wait and try again
        if attempt < 3 {
            medium_wait();
        }
    }
        
    Ok(false)
}

fn find_chrome() -> Option<PathBuf> {
    let chrome_paths = vec![
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",  // macOS path
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",    // Windows path
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
    ];

    for path in chrome_paths {
        let path_buf = PathBuf::from(path);
        if path_buf.exists() {
            return Some(path_buf);
        }
    }
    None
}

pub async fn download_whoop_data(email: &str, password: &str) -> Result<String> {
    info!("Starting Whoop data download process");
    info!("Email: {}", email);

    // Find Chrome/Chromium executable
    let chrome_path = find_chrome()
        .ok_or_else(|| anyhow!("Could not find Chrome/Chromium. Please install Chrome or Chromium browser."))?;
    
    info!("Found browser at: {:?}", chrome_path);

    // Configure browser options
    let mut args = vec![
        OsStr::new("--no-sandbox"),
        OsStr::new("--disable-setuid-sandbox"),
        OsStr::new("--disable-dev-shm-usage"),
        OsStr::new("--disable-gpu"),
        OsStr::new("--no-first-run"),
        OsStr::new("--no-zygote"),
        OsStr::new("--single-process"),
        OsStr::new("--disable-software-rasterizer"),
        OsStr::new("--disable-background-networking"),
        OsStr::new("--disable-default-apps"),
        OsStr::new("--disable-extensions"),
        OsStr::new("--disable-sync"),
        OsStr::new("--disable-translate"),
        OsStr::new("--hide-scrollbars"),
        OsStr::new("--metrics-recording-only"),
        OsStr::new("--mute-audio"),
        OsStr::new("--no-default-browser-check"),
        OsStr::new("--password-store=basic"),
        OsStr::new("--use-gl=swiftshader"),
        OsStr::new("--use-mock-keychain"),
        OsStr::new("--disable-web-security"),
        OsStr::new("--allow-running-insecure-content"),
        OsStr::new("--disable-features=IsolateOrigins,site-per-process"),
        OsStr::new("--remote-debugging-port=9222"),
        OsStr::new("--remote-debugging-address=0.0.0.0"),
        OsStr::new("--disable-crash-reporter"),
        OsStr::new("--disable-in-process-stack-traces"),
        OsStr::new("--disable-logging"),
        OsStr::new("--disable-dev-tools"),
        OsStr::new("--no-startup-window"),
    ];

    #[cfg(feature = "nsm")]
    {
        args.push(OsStr::new("--proxy-server=http://127.0.0.1:3128"));
    }

    let options = LaunchOptionsBuilder::default()
        .headless(true)
        .window_size(Some((1920, 1080)))
        .sandbox(false)
        .path(Some(chrome_path))
        .port(Some(0))
        .args(args)
        .idle_browser_timeout(Duration::from_secs(300))
        .build()
        .map_err(|e| anyhow!("Failed to build browser options: {}", e))?;
    
    // Launch browser with retry logic
    info!("Launching browser with options: {:?}", options);
    let mut browser = None;
    let mut last_error = None;
    
    for attempt in 1..=3 {
        info!("Browser launch attempt {} of {}", attempt, 3);
        match Browser::new(options.clone()) {
            Ok(b) => {
                browser = Some(b);
                break;
            }
            Err(e) => {
                error!("Failed to launch browser on attempt {}: {:?}", attempt, e);
                last_error = Some(e);
                if attempt < 3 {
                    thread::sleep(Duration::from_secs(5));
                }
            }
        }
    }
    
    let browser = browser.ok_or_else(|| {
        let err_msg = format!("Failed to launch browser after 3 attempts");
        error!("{}", err_msg);
        if let Some(e) = last_error {
            error!("Last error: {:?}", e);
        }
        anyhow!(err_msg)
    })?;
    
    // Create a new tab with retry logic
    info!("Attempting to create new tab");
    let mut tab = None;
    
    for attempt in 1..=3 {
        info!("Tab creation attempt {} of {}", attempt, 3);
        match browser.new_tab() {
            Ok(t) => {
                tab = Some(t);
                break;
            }
            Err(e) => {
                error!("Failed to create tab on attempt {}: {:?}", attempt, e);
                if attempt < 3 {
                    thread::sleep(Duration::from_secs(5));
                }
            }
        }
    }
    
    let tab = tab.ok_or_else(|| anyhow!("Failed to create new tab after 3 attempts"))?;
    
    // Configure download behavior
    let download_path = std::env::var("DOWNLOAD_DIR").unwrap_or_else(|_| {
        let project_downloads = std::path::PathBuf::from("downloads");
        if !project_downloads.exists() {
            if let Err(e) = std::fs::create_dir_all(&project_downloads) {
                error!("Failed to create downloads directory: {}", e);
            }
        }
        project_downloads.to_string_lossy().into_owned()
    });
    info!("Using download directory: {}", download_path);
    
    tab.call_method(SetDownloadBehavior {
        behavior: SetDownloadBehaviorBehaviorOption::Allow,
        download_path: Some(download_path.clone()),
        browser_context_id: None,
        events_enabled: None,
    }).map_err(|e| anyhow!("Failed to set download behavior: {}", e))?;
    
    info!("Successfully created new tab");
    
    // Step 1: Navigate to privacy policy page
    info!("Step 1: Navigating to privacy policy page");
    tab.navigate_to("https://privacy.whoop.com/policies/en-US/")
        .map_err(|e| anyhow!("Failed to navigate to privacy policy page: {}", e))?;
    
    tab.wait_until_navigated()
        .map_err(|e| anyhow!("Failed to wait for navigation: {}", e))?;
    
    // Add longer wait for page to fully load
    info!("Waiting for page to fully load...");
    long_wait();
    long_wait();
    
    // Step 2: Find and click "Take Control" button
    info!("Step 2: Looking for 'Take Control' button");
    
    let take_control_selectors = &[
        "#modal-select-subject",
        "button.kqxjSY.bjFPQb",
        ".bjFPQb",
        "button:contains('Take Control')",
        "a:contains('Take Control')",
        "button.wrappers__ButtonWrapper-sc-1w68iym-1",
        "[data-testid='take-control-button']",
        "button[aria-label*='Take Control']",
        "button",
        "a[role='button']",
        "[role='button']",
    ];
    
    let mut success = click_element(&tab, take_control_selectors, "take_control").await?;
    
    if !success {
        success = js_click_button(&tab, "take_control", "Take Control", Some("modal-select-subject"), Some("kqxjSY bjFPQb")).await?;
        
        if !success {
            return Err(anyhow!("Could not find or click 'Take Control' button"));
        }
    }
    
    medium_wait();
    
    // Step 3: Find and click "Customer with Account" button
    info!("Step 3: Looking for 'Customer with Account' button");
    
    let customer_account_selectors = &[
        "#select-dataSubject-customer",
        "button.eJneUD.dXtKPg.iDwoDh",
        "button[aria-current='true']",
        "button:contains('Customer with account')",
        "button:contains('Customer with Account')",
        "button div:contains('Customer with account')",
        "[class*='SubjectWrapper']",
        "a:contains('Customer with Account')",
        "[data-testid='customer-account-button']",
        "button[aria-label*='Customer with Account']"
    ];
    
    success = click_element(&tab, customer_account_selectors, "customer_account").await?;
    
    if !success {
        success = js_click_button(&tab, "customer_account", "Customer", Some("select-dataSubject-customer"), Some("eJneUD dXtKPg iDwoDh")).await?;
        
        if !success {
            return Err(anyhow!("Could not find or click 'Customer with Account' button"));
        }
    }
    
    medium_wait();
    
    // Step 4: Find and click "Download My Data" button
    info!("Step 4: Looking for 'Download My Data' button");
    
    let download_data_selectors = &[
        "#select-dsr-action-ACCESS",
        "button.kqxjSY.dXtKPg.eeTnHI",
        "button .ejtwIH",
        "button section[id='select-dsr-action-ACCESS']",
        "button h3:contains('Download my data')",
        ".action-button",
        "button:contains('Download my data')",
        "button:contains('Download My Data')",
        "button div:contains('Download my data')",
        "button div:contains('Download My Data')",
        ".primaryButton",
        "button[class*='download']",
        "button[class*='primary']",
        "a:contains('Download My Data')",
        "[data-testid='download-data-button']",
        "button[aria-label*='Download']"
    ];
    
    success = click_element(&tab, download_data_selectors, "download_data").await?;
    
    if !success {
        success = js_click_button(&tab, "download_data", "Download my data", Some("select-dsr-action-ACCESS"), Some("kqxjSY dXtKPg eeTnHI")).await?;
        
        if !success {
            return Err(anyhow!("Could not find or click 'Download My Data' button"));
        }
    }
    
    medium_wait();
    
    // Step 5: Fill in login credentials
    info!("Step 5: Filling in login credentials");
    long_wait();
    
    let email_selectors = vec![
        "input[type='email']", 
        "input[name='email']",
        "#email",
        "input[id*='email' i]",
        "input[placeholder*='email' i]",
        "input[class*='email' i]",
        "input",
    ];
    
    let password_selectors = vec![
        "input[type='password']", 
        "input[name='password']",
        "#password",
        "input[id*='password' i]",
        "input[placeholder*='password' i]",
        "input[class*='password' i]"
    ];
    
    // Try to fill email field
    let mut email_filled = false;
    for attempt in 1..=3 {
        info!("Attempt {} to find and fill email field", attempt);
        
        for selector in &email_selectors {
            if let Ok(element) = tab.find_element(selector) {
                info!("Found email input field with selector: {}", selector);
                medium_wait();
                
                if element.click().is_ok() {
                    medium_wait();
                    
                    if element.type_into(email).is_ok() {
                        email_filled = true;
                        info!("Successfully filled email field");
                        break;
                    }
                }
            }
        }
        
        if email_filled {
            break;
        }
        
        wait_with_timeout(2);
    }
    
    if !email_filled {
        // Try with JavaScript as last resort
        let js_script = format!(
            r#"
            (function() {{
                const emailInput = 
                    document.querySelector('input[type="email"]') || 
                    document.querySelector('input[name="email"]') || 
                    document.querySelector('#email') ||
                    Array.from(document.querySelectorAll('input')).find(i => 
                        i.id?.toLowerCase().includes('email') || 
                        i.placeholder?.toLowerCase().includes('email') ||
                        i.className?.toLowerCase().includes('email')
                    ) ||
                    document.querySelectorAll('input')[0];
                
                if (emailInput) {{
                    emailInput.focus();
                    emailInput.value = "{email}";
                    emailInput.dispatchEvent(new Event('input', {{ bubbles: true }}));
                    emailInput.dispatchEvent(new Event('change', {{ bubbles: true }}));
                    return true;
                }}
                return false;
            }})()
            "#,
            email = email
        );
        
        if let Ok(result) = tab.evaluate(&js_script, false) {
            if let Some(serde_json::Value::Bool(true)) = result.value {
                info!("Successfully filled email field with JavaScript");
                email_filled = true;
            }
        }
    }
    
    if !email_filled {
        return Err(anyhow!("Could not find or fill email field"));
    }
    
    medium_wait();
    
    // Try to fill password field
    let mut password_filled = false;
    for attempt in 1..=3 {
        info!("Attempt {} to find and fill password field", attempt);
        
        for selector in &password_selectors {
            if let Ok(element) = tab.find_element(selector) {
                info!("Found password input field with selector: {}", selector);
                medium_wait();
                
                if element.click().is_ok() {
                    medium_wait();
                    
                    if element.type_into(password).is_ok() {
                        password_filled = true;
                        info!("Successfully filled password field");
                        break;
                    }
                }
            }
        }
        
        if password_filled {
            break;
        }
        
        wait_with_timeout(2);
    }
    
    if !password_filled {
        // Try with JavaScript as last resort
        let js_script = format!(
            r#"
            (function() {{
                const passwordInput = 
                    document.querySelector('input[type="password"]') || 
                    document.querySelector('input[name="password"]') || 
                    document.querySelector('#password') ||
                    Array.from(document.querySelectorAll('input')).find(i => 
                        i.id?.toLowerCase().includes('password') || 
                        i.placeholder?.toLowerCase().includes('password') ||
                        i.className?.toLowerCase().includes('password')
                    ) ||
                    document.querySelectorAll('input[type="password"]')[0];
                
                if (passwordInput) {{
                    passwordInput.focus();
                    passwordInput.value = "{password}";
                    passwordInput.dispatchEvent(new Event('input', {{ bubbles: true }}));
                    passwordInput.dispatchEvent(new Event('change', {{ bubbles: true }}));
                    return true;
                }}
                return false;
            }})()
            "#,
            password = password
        );
        
        if let Ok(result) = tab.evaluate(&js_script, false) {
            if let Some(serde_json::Value::Bool(true)) = result.value {
                info!("Successfully filled password field with JavaScript");
                password_filled = true;
            }
        }
    }
    
    if !password_filled {
        return Err(anyhow!("Could not find or fill password field"));
    }
    
    // Click login button
    let login_button_selectors = &[
        "button[type='submit']",
        "input[type='submit']",
        "button:contains('Log In')",
        "button:contains('Sign In')",
        "button:contains('Login')",
        "button:contains('Signin')",
        "button.primaryButton",
        "button[class*='login']",
        "button[class*='submit']"
    ];
    
    if !click_element(&tab, login_button_selectors, "login").await? {
        let js_script = r#"
            (function() {
                const submitButton = 
                    document.querySelector('button[type="submit"]') || 
                    document.querySelector('input[type="submit"]') ||
                    Array.from(document.querySelectorAll('button')).find(b => 
                        b.textContent?.toLowerCase().includes('log in') || 
                        b.textContent?.toLowerCase().includes('sign in') ||
                        b.textContent?.toLowerCase().includes('login')
                    );
                
                if (submitButton) {
                    submitButton.click();
                    return true;
                }
                
                const form = document.querySelector('form');
                if (form) {
                    form.submit();
                    return true;
                }
                
                return false;
            })()
        "#;
        
        if let Ok(result) = tab.evaluate(js_script, false) {
            if let Some(serde_json::Value::Bool(true)) = result.value {
                info!("Successfully submitted login form with JavaScript");
            } else {
                return Err(anyhow!("Could not find or click login button"));
            }
        } else {
            return Err(anyhow!("Could not find or click login button"));
        }
    }
    
    medium_wait();
    
    // New Step: Click the Grant button if it appears
    info!("Looking for 'Grant' consent button");
    let grant_button_selectors = &[
        "button[data-testid='grant-consent-button']",
        "button.consent_button__g5jB7",
        "button.button-module__button-primary___hqV49",
        "button[aria-label='Grant']",
        "button[type='submit']",
        "button:contains('Grant')",
        ".button-module__button___mtcvK",
        "button.button-module__button-medium___cZpTf"
    ];
    
    click_element(&tab, grant_button_selectors, "grant_button").await?;
    medium_wait();
    
    // Step 6: Close the popup window
    info!("Step 6: Looking for Close button");
    let close_button_selectors = &[
        ".modal-close",
        "button.eVCfxG.modal-close",
        "button.wrappers__StyledButton-sc-hot31w-1",
        "button[aria-label='Close']",
        "button.btn.btn-link",
        "button:has(svg)",
        "button svg[stroke='#535f6e']",
        "button:contains('×')",
        "button:contains('✕')",
        "button:contains('Close')",
        "button[class*='close']"
    ];
    
    info!("Trying close button selectors");
    long_wait();
    
    click_element(&tab, close_button_selectors, "close_popup").await?;
    medium_wait();
    
    // Step 7: Click "Active Requests" button
    info!("Step 7: Looking for 'Active Requests' button");
    medium_wait();
    
    let active_request_selectors = &[
        "#request-history",
        "button.PGmba.eDlNAK",
        "button[aria-haspopup='true']",
        "button[aria-controls='request-history-controls']",
        "button.wrappers__StyledButton-sc-bwm5fz-0",
        "button.wrappers__StyledButton-sc-198koi9-3",
        "button:contains('Active Requests')",
        "button:contains('Active Request')",
        "button:contains('Requests')",
        "button:contains('Request')",
        "button:contains('0 Active')",
        "button:contains('1 Active')",
        "button:contains('2 Active')",
    ];
    
    info!("Trying active request selectors");
    
    if !click_element(&tab, active_request_selectors, "active_request").await? {
        warn!("Could not find or click 'Active Requests' button, but attempting to continue anyway");
    }
    
    medium_wait();
    
    // Step 8: Click "Download Archive" button
    info!("Step 8: Looking for 'Download Archive' button");
    long_wait();
    long_wait();
    
    let download_archive_selectors = &[
        "button.wrappers__StyledButton-sc-bwm5fz-0.bAMdHF.wrappers__ButtonWrapper-sc-cp086r-0.gMsvRy",
        "button:contains('Download Archive')",
        "button:contains('Download')",
        "button[class*='download']",
        "button[class*='wrappers__StyledButton']",
    ];
    
    info!("Trying download archive selectors");
    
    if !click_element(&tab, download_archive_selectors, "download_archive").await? {
        return Err(anyhow!("Could not find or click 'Download Archive' button"));
    }
    
    // Wait for download to complete with a timeout of 300 seconds (5 minutes)
    wait_for_download(&download_path, 300)
} 