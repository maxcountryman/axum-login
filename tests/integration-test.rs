use std::{
    collections::HashMap,
    process::{Child, Command},
    time::Duration,
};

use reqwest::Client;

const URL: &str = "http://localhost:3000";

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

fn start_example_binary() -> ChildGuard {
    let child = Command::new("cargo")
        .arg("run")
        .arg("--example")
        .arg("sqlite")
        .spawn()
        .expect("Failed to start example binary");

    std::thread::sleep(Duration::from_secs(5)); // Wait for the example binary to initialize.

    ChildGuard { child }
}

#[tokio::test]
async fn sqlite_example() {
    let _child_guard = start_example_binary();

    let client = Client::builder().cookie_store(true).build().unwrap();

    // A logged out user is redirected to the login URL with a next query string.
    let res = client.get(URL).send().await.unwrap();
    assert_eq!(res.url().to_string(), format!("{}/login?next=%2F", URL));

    // Log in with invalid credentials.
    let mut form = HashMap::new();
    form.insert("username", "ferris");
    form.insert("password", "bogus");
    let res = client
        .post(format!("{}/login", URL))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(res.url().to_string(), format!("{}/login", URL));

    // Log in with valid credentials.
    let mut form = HashMap::new();
    form.insert("username", "ferris");
    form.insert("password", "hunter42");
    let res = client
        .post(format!("{}/login", URL))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(res.url().to_string(), format!("{}/", URL));

    // Log out and check the cookie has been removed in response.
    let res = client.get(format!("{}/logout", URL)).send().await.unwrap();
    assert!(res
        .cookies()
        .find(|c| c.name() == "tower.sid")
        .is_some_and(|c| c.value() == ""));
}
