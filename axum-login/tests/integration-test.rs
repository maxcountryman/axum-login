use std::{
    collections::HashMap,
    process::{Child, Command},
    time::{Duration, Instant},
};

use reqwest::Client;
use serial_test::serial;

const WEBSERVER_URL: &str = "http://localhost:3000";

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.child.kill().expect("Failed to kill example binary");
        self.child
            .wait()
            .expect("Failed to wait for example binary to exit");
    }
}

async fn start_example_binary(binary_name: &str) -> ChildGuard {
    let child = Command::new("cargo")
        .arg("run")
        .arg("-p")
        .arg(binary_name)
        .spawn()
        .expect("Failed to start example binary");

    let start_time = Instant::now();
    let mut is_server_ready = false;

    while start_time.elapsed() < Duration::from_secs(300) {
        if reqwest::get(WEBSERVER_URL).await.is_ok() {
            is_server_ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    if !is_server_ready {
        panic!("The web server did not become ready within the expected time.");
    }

    ChildGuard { child }
}

#[tokio::test]
#[serial]
async fn sqlite_example() {
    let _child_guard = start_example_binary("example-sqlite").await;

    let client = Client::builder().cookie_store(true).build().unwrap();

    // A logged out user is redirected to the login URL with a next query string.
    let res = client.get(WEBSERVER_URL).send().await.unwrap();
    assert_eq!(
        res.url().to_string(),
        format!("{}/login?next=%2F", WEBSERVER_URL)
    );

    // Log in with invalid credentials.
    let mut form = HashMap::new();
    form.insert("username", "ferris");
    form.insert("password", "bogus");
    let res = client
        .post(format!("{}/login", WEBSERVER_URL))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(res.url().to_string(), format!("{}/login", WEBSERVER_URL));

    // Log in with valid credentials.
    let mut form = HashMap::new();
    form.insert("username", "ferris");
    form.insert("password", "hunter42");
    let res = client
        .post(format!("{}/login", WEBSERVER_URL))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(res.url().to_string(), format!("{}/", WEBSERVER_URL));

    // Log out and check the cookie has been removed in response.
    let res = client
        .get(format!("{}/logout", WEBSERVER_URL))
        .send()
        .await
        .unwrap();
    assert!(res
        .cookies()
        .find(|c| c.name() == "id")
        .is_some_and(|c| c.value() == ""));
}

#[tokio::test]
#[serial]
async fn permissions_example() {
    let _child_guard = start_example_binary("example-permissions").await;

    let client = Client::builder().cookie_store(true).build().unwrap();

    // A logged out user is redirected to the login URL with a next query string.
    let res = client.get(WEBSERVER_URL).send().await.unwrap();
    assert_eq!(
        res.url().to_string(),
        format!("{}/login?next=%2F", WEBSERVER_URL)
    );

    // Log in with invalid credentials.
    let mut form = HashMap::new();
    form.insert("username", "ferris");
    form.insert("password", "bogus");
    let res = client
        .post(format!("{}/login", WEBSERVER_URL))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(res.url().to_string(), format!("{}/login", WEBSERVER_URL));

    // Log in with valid credentials.
    let mut form = HashMap::new();
    form.insert("username", "ferris");
    form.insert("password", "hunter42");
    let res = client
        .post(format!("{}/login", WEBSERVER_URL))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(res.url().to_string(), format!("{}/", WEBSERVER_URL));

    // Try to access restricted page.
    let res = client
        .get(format!("{}/restricted", WEBSERVER_URL))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.url().to_string(),
        format!("{}/login?next=%2Frestricted", WEBSERVER_URL)
    );

    // Log in with valid credentials.
    let mut form = HashMap::new();
    form.insert("username", "admin");
    form.insert("password", "hunter42");
    let res = client
        .post(format!("{}/login", WEBSERVER_URL))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(res.url().to_string(), format!("{}/", WEBSERVER_URL));

    // Now we should be able to access the restricted page.
    let res = client
        .get(format!("{}/restricted", WEBSERVER_URL))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.url().to_string(),
        format!("{}/restricted", WEBSERVER_URL)
    );

    // Log out and check the cookie has been removed in response.
    let res = client
        .get(format!("{}/logout", WEBSERVER_URL))
        .send()
        .await
        .unwrap();
    assert!(res
        .cookies()
        .find(|c| c.name() == "id")
        .is_some_and(|c| c.value() == ""));
}
