use std::{
    collections::HashMap,
    process::{Child, Command},
    sync::Arc,
    time::{Duration, Instant},
};

use reqwest::{
    cookie::{CookieStore, Jar},
    Client, StatusCode, Url,
};
use serial_test::serial;

const WEBSERVER_URL: &str = "http://localhost:3000";

#[tokio::test]
#[serial]
async fn sqlite_example() {
    let _child_guard = start_example_binary("example-sqlite").await;

    let cookie_jar = Arc::new(Jar::default());
    let client = Client::builder()
        .cookie_provider(cookie_jar.clone())
        .build()
        .unwrap();

    // A logged out user is redirected to the login URL with a next query
    //string.
    let res = client.get(url("/")).send().await.unwrap();
    assert_eq!(*res.url(), url("/login?next=%2F"));
    assert_eq!(res.status(), StatusCode::OK);

    // Log in with invalid credentials.
    let res = login(&client, "ferris", "bogus").await;
    assert_eq!(*res.url(), url("/login"));
    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        cookie_jar.cookies(&url("/")).is_some(),
        "Expected cookies (i.e. for flash messages)"
    );

    // Log in with valid credentials.
    let res = login(&client, "ferris", "hunter42").await;
    assert_eq!(*res.url(), url("/"));
    assert_eq!(res.status(), StatusCode::OK);

    let cookies = cookie_jar
        .cookies(&url("/"))
        .expect("A cookie should be set");
    assert!(
        cookies.to_str().unwrap_or("").contains("id="),
        "Expected 'id' cookie to be set after successful login"
    );

    // Log out and check the cookie has been removed in response.
    let res = client.get(url("/logout")).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        cookie_jar.cookies(&url("/")).iter().len(),
        0,
        "Expected 'id' cookie to be removed"
    );
}

#[tokio::test]
#[serial]
async fn permissions_example() {
    let _child_guard = start_example_binary("example-permissions").await;

    let cookie_jar = Arc::new(Jar::default());
    let client = Client::builder()
        .cookie_provider(cookie_jar.clone())
        .build()
        .unwrap();

    // A logged out user is redirected to the login URL with a next query string.
    let res = client.get(url("/")).send().await.unwrap();

    assert_eq!(*res.url(), url("/login?next=%2F"));
    assert_eq!(res.status(), StatusCode::OK);

    // Log in with invalid credentials.
    let res = login(&client, "ferris", "bogus").await;

    assert_eq!(*res.url(), url("/login"));
    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        cookie_jar.cookies(&url("/")).is_none(),
        "Expected no cookies"
    );

    // Log in with valid credentials.
    let res = login(&client, "ferris", "hunter42").await;

    assert_eq!(*res.url(), url("/"));
    assert_eq!(res.status(), StatusCode::OK);

    let cookies = cookie_jar
        .cookies(&url("/"))
        .expect("A cookie should be set");
    assert!(
        cookies.to_str().unwrap_or("").contains("id="),
        "Expected 'id' cookie to be set after successful login"
    );

    // Try to access restricted page.
    let res = client.get(url("/restricted")).send().await.unwrap();
    assert_eq!(*res.url(), url("/login?next=%2Frestricted"));
    assert_eq!(res.status(), StatusCode::OK);

    // Log in with valid credentials.
    let res = login(&client, "admin", "hunter42").await;

    assert_eq!(*res.url(), url("/"));
    assert_eq!(res.status(), StatusCode::OK);

    let cookies = cookie_jar.cookies(&url("/")).unwrap();
    assert!(
        cookies.to_str().unwrap_or("").contains("id="),
        "Expected 'id' cookie to be set after login"
    );

    // Now we should be able to access the restricted page.
    let res = client.get(url("/restricted")).send().await.unwrap();
    assert_eq!(*res.url(), url("/restricted"));
    assert_eq!(res.status(), StatusCode::OK);

    // Log out and check the cookie has been removed in response.
    let res = client.get(url("/logout")).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    assert_eq!(
        cookie_jar.cookies(&url("/")).iter().len(),
        0,
        "Expected 'id' cookie to be removed"
    );
}

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

fn url(path: &str) -> Url {
    let formatted_url = if path.starts_with('/') {
        format!("{WEBSERVER_URL}{path}")
    } else {
        format!("{WEBSERVER_URL}/{path}")
    };
    formatted_url.parse().unwrap()
}

async fn login(client: &Client, username: &str, password: &str) -> reqwest::Response {
    let mut form = HashMap::new();
    form.insert("username", username);
    form.insert("password", password);
    client.post(url("/login")).form(&form).send().await.unwrap()
}
