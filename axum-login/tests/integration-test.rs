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
        format!("{WEBSERVER_URL}/login?next=%2F")
    );

    // Log in with invalid credentials.
    let mut form = HashMap::new();
    form.insert("username", "ferris");
    form.insert("password", "bogus");
    let res = client
        .post(format!("{WEBSERVER_URL}/login"))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(res.url().to_string(), format!("{WEBSERVER_URL}/login"));

    // Log in with valid credentials.
    let mut form = HashMap::new();
    form.insert("username", "ferris");
    form.insert("password", "hunter42");
    let res = client
        .post(format!("{WEBSERVER_URL}/login"))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(res.url().to_string(), format!("{WEBSERVER_URL}/"));

    // Log out and check the cookie has been removed in response.
    let res = client
        .get(format!("{WEBSERVER_URL}/logout"))
        .send()
        .await
        .unwrap();
    let deleted_cookie = res.headers().get_all("set-cookie").iter().any(|val| {
        val.to_str().unwrap_or("").contains("id=")
            && val.to_str().unwrap_or("").contains("Max-Age=0")
    });

    assert!(deleted_cookie, "Expected 'id' cookie to be removed");
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
        format!("{WEBSERVER_URL}/login?next=%2F")
    );

    // Log in with invalid credentials.
    let mut form = HashMap::new();
    form.insert("username", "ferris");
    form.insert("password", "bogus");
    let res = client
        .post(format!("{WEBSERVER_URL}/login"))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(res.url().to_string(), format!("{WEBSERVER_URL}/login"));

    // Log in with valid credentials.
    let mut form = HashMap::new();
    form.insert("username", "ferris");
    form.insert("password", "hunter42");
    let res = client
        .post(format!("{WEBSERVER_URL}/login"))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(res.url().to_string(), format!("{WEBSERVER_URL}/"));

    // Try to access restricted page.
    let res = client
        .get(format!("{WEBSERVER_URL}/restricted"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.url().to_string(),
        format!("{WEBSERVER_URL}/login?next=%2Frestricted")
    );

    // Log in with valid credentials.
    let mut form = HashMap::new();
    form.insert("username", "admin");
    form.insert("password", "hunter42");
    let res = client
        .post(format!("{WEBSERVER_URL}/login"))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(res.url().to_string(), format!("{WEBSERVER_URL}/"));

    // Now we should be able to access the restricted page.
    let res = client
        .get(format!("{WEBSERVER_URL}/restricted"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.url().to_string(), format!("{WEBSERVER_URL}/restricted"));

    // Log out and check the cookie has been removed in response.
    let res = client
        .get(format!("{WEBSERVER_URL}/logout"))
        .send()
        .await
        .unwrap();

    let deleted_cookie = res.headers().get_all("set-cookie").iter().any(|val| {
        val.to_str().unwrap_or("").contains("id=")
            && val.to_str().unwrap_or("").contains("Max-Age=0")
    });

    assert!(deleted_cookie, "Expected 'id' cookie to be removed");
}
