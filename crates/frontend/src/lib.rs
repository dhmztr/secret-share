//! SecretShare frontend.
//!
//! Compiled twice by cargo-leptos:
//!   1. `--features ssr`     → linked into the server binary for SSR rendering
//!   2. `--features hydrate` → compiled to WASM; loaded by the browser to take
//!                             over reactivity after the initial HTML arrives
//!
//! Security model
//! ──────────────
//! • The encryption key **never leaves the browser** – it is embedded in the
//!   URL fragment (`#<base64url-key>`) which browsers never send to the server.
//! • Content-type metadata (text vs. file + filename) is embedded inside the
//!   plaintext before encryption via `crypto::wrap_payload`, so the server
//!   stores only opaque ciphertext and learns nothing about the payload type.
//! • Password hashing (Argon2id) is performed **client-side** inside the WASM
//!   bundle; the server only ever sees and stores the PHC hash string.

use leptos::prelude::*;
use leptos_router::components::{A, Route, Router, Routes};
use leptos_router::hooks::use_params_map;
use leptos_router::path;
use serde::{Deserialize, Serialize};

// ── Embedded static assets (used by the server to serve /style.css etc.) ──

pub const STYLES: &str = include_str!("styles.css");
pub const FAVICON: &str = include_str!("favicon.svg");

// ── WASM entry-point ───────────────────────────────────────────────────────

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    leptos::mount::hydrate_body(App);
}

// ── Shared API types (serialised to/from JSON) ─────────────────────────────

/// Mirror of `crypto::Envelope` – kept here so we do not pull the full crypto
/// crate into the SSR build (it is an optional dep on the hydrate feature).
#[derive(Serialize, Deserialize, Clone, Debug)]
struct ApiEnvelope {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    /// Argon2 PHC hash produced client-side; `None` → no passphrase.
    password: Option<String>,
}

/// POST /api/secrets
#[derive(Serialize, Clone, Debug)]
struct CreateReq {
    env: ApiEnvelope,
    max_views: i32,
    /// RFC-3339 / ISO-8601 timestamp
    expires_at: String,
}

/// POST /api/secrets/:id/fetch
#[derive(Serialize, Clone, Debug)]
struct FetchReq {
    /// Plain-text password entered by the viewer; the server compares it
    /// against the Argon2 hash stored at creation time.
    password: Option<String>,
}

/// GET /api/secrets/:id/meta  →  response body
#[derive(Deserialize, Clone, Debug)]
struct MetaResp {
    password_required: bool,
    views_left: i32,
    burned: bool,
}

/// POST /api/secrets/:id/fetch  →  response body
#[derive(Deserialize, Clone, Debug)]
struct FetchResp {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

// ── Decrypted payload (lives only in the browser, never serialised) ─────────

/// What the frontend holds after successful decryption.
#[derive(Clone, Debug)]
pub enum Decrypted {
    Text(String),
    File { name: String, bytes: Vec<u8> },
}

// ── WASM-only module ────────────────────────────────────────────────────────
//
// Everything that touches the DOM, the network, or the crypto crate lives
// here behind `#[cfg(feature = "hydrate")]`.  The SSR build never compiles
// this code, so it cannot accidentally run crypto or network calls on the
// server.

#[cfg(feature = "hydrate")]
mod client {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use crypto::{ContentType, decrypt, encrypt, unwrap_payload, wrap_payload};
    use gloo_net::http::Request;
    use js_sys::Date;
    use wasm_bindgen::JsValue;
    use wasm_bindgen_futures::JsFuture;

    // ── Key encoding ────────────────────────────────────────────────────────

    pub fn encode_key(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    pub fn decode_key(s: &str) -> Result<Vec<u8>, String> {
        URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| format!("key decode error: {e}"))
    }

    // ── Time helpers ────────────────────────────────────────────────────────

    /// Return an ISO-8601 string `days` days from now, using `js_sys::Date`
    /// (the only reliable clock inside a WASM module).
    pub fn iso_in_days(days: i64) -> String {
        let now_ms = Date::now();
        let future_ms = now_ms + (days as f64) * 86_400_000.0;
        Date::new(&JsValue::from_f64(future_ms))
            .to_iso_string()
            .as_string()
            .unwrap_or_else(|| "2099-01-01T00:00:00.000Z".to_string())
    }

    // ── Browser helpers ─────────────────────────────────────────────────────

    pub fn origin() -> String {
        web_sys::window()
            .and_then(|w| w.location().origin().ok())
            .unwrap_or_else(|| "http://localhost:8080".to_string())
    }

    pub fn location_hash() -> String {
        web_sys::window()
            .and_then(|w| w.location().hash().ok())
            .unwrap_or_default()
    }

    /// Read a `File` object from the browser's File API into a `Vec<u8>`.
    pub async fn read_file_bytes(file: &web_sys::File) -> Result<(String, Vec<u8>), String> {
        let name = file.name();
        let promise = file.array_buffer();
        let buf = JsFuture::from(promise)
            .await
            .map_err(|e| format!("could not read file: {e:?}"))?;
        let arr = js_sys::Uint8Array::new(&buf);
        Ok((name, arr.to_vec()))
    }

    /// Create a temporary object URL for a `Vec<u8>` so the browser can
    /// download it as a file.
    pub fn make_blob_url(bytes: &[u8], mime: &str) -> Result<String, String> {
        use js_sys::{Array, Uint8Array};
        use web_sys::{Blob, BlobPropertyBag};

        let typed = Uint8Array::from(bytes);
        let parts = Array::new();
        parts.push(&typed);

        let mut opts = BlobPropertyBag::new();
        opts.type_(mime);

        let blob = Blob::new_with_u8_array_sequence_and_options(&parts, &opts)
            .map_err(|e| format!("blob error: {e:?}"))?;

        web_sys::Url::create_object_url_with_blob(&blob)
            .map_err(|e| format!("object-url error: {e:?}"))
    }

    // ── Network calls ────────────────────────────────────────────────────────

    /// Encrypt a payload client-side and POST it to the server.
    ///
    /// Returns the full shareable URL including the key in the fragment.
    pub async fn create_secret(
        kind: ContentType,
        data: Vec<u8>,
        max_views: i32,
        password: Option<String>,
        expiry_days: i64,
    ) -> Result<String, String> {
        // 1. Prepend content-type header so we know how to display it later.
        let payload = wrap_payload(&kind, &data);

        // 2. Encrypt (and optionally hash the password) – both happen here,
        //    inside the browser, never on the server.
        let pass_bytes = password.as_deref().map(str::as_bytes);
        let (env, key) = encrypt(&payload, pass_bytes)?;

        // 3. Build the JSON envelope that the server will store.
        let body = CreateReq {
            env: ApiEnvelope {
                nonce: env.nonce,
                ciphertext: env.ciphertext,
                password: env.password,
            },
            max_views,
            expires_at: iso_in_days(expiry_days),
        };

        let resp = Request::post("/api/secrets")
            .json(&body)
            .map_err(|e| format!("serialise error: {e}"))?
            .send()
            .await
            .map_err(|e| format!("network error: {e}"))?;

        if !resp.ok() {
            let msg = resp.text().await.unwrap_or_default();
            return Err(format!("server error {}: {msg}", resp.status()));
        }

        // Server responds with the UUID as a JSON string.
        let uuid: String = resp.json().await.map_err(|e| format!("parse error: {e}"))?;

        // 4. Embed the key in the fragment – it is never sent to the server.
        Ok(format!("{}/s/{uuid}#{}", origin(), encode_key(&key)))
    }

    /// Fetch metadata for a secret without consuming a view.
    pub async fn get_meta(id: &str) -> Result<MetaResp, String> {
        let resp = Request::get(&format!("/api/secrets/{id}/meta"))
            .send()
            .await
            .map_err(|e| format!("network error: {e}"))?;

        match resp.status() {
            404 | 410 => {
                return Err("This secret does not exist or has already expired.".to_string());
            }
            s if s >= 400 => {
                return Err(format!("server error {s}"));
            }
            _ => {}
        }

        resp.json::<MetaResp>()
            .await
            .map_err(|e| format!("parse error: {e}"))
    }

    /// Consume one view, retrieve the ciphertext, and decrypt it locally.
    ///
    /// Returns a special sentinel string on known error conditions so the
    /// caller can show the right UI state:
    ///   `"wrong_password"` – Argon2 verification failed (HTTP 401)
    ///   `"expired"`        – view limit / expiry reached  (HTTP 410)
    pub async fn fetch_and_decrypt(
        id: &str,
        key_b64: &str,
        password: Option<String>,
    ) -> Result<Decrypted, String> {
        let key = decode_key(key_b64)?;

        let resp = Request::post(&format!("/api/secrets/{id}/fetch"))
            .json(&FetchReq { password })
            .map_err(|e| format!("serialise error: {e}"))?
            .send()
            .await
            .map_err(|e| format!("network error: {e}"))?;

        match resp.status() {
            401 => return Err("wrong_password".to_string()),
            410 => return Err("expired".to_string()),
            s if s >= 400 => {
                let msg = resp.text().await.unwrap_or_default();
                return Err(format!("server error {s}: {msg}"));
            }
            _ => {}
        }

        let data: FetchResp = resp.json().await.map_err(|e| format!("parse error: {e}"))?;

        // Decrypt fully client-side – the server never sees the key.
        let plaintext = decrypt(&key, &data.nonce, &data.ciphertext)?;

        // Unwrap the content-type header we prepended before encrypting.
        let (kind, content) = unwrap_payload(&plaintext)?;

        match kind {
            ContentType::Text => {
                let text = String::from_utf8(content)
                    .map_err(|_| "decrypted content is not valid UTF-8".to_string())?;
                Ok(Decrypted::Text(text))
            }
            ContentType::File { name } => Ok(Decrypted::File {
                name,
                bytes: content,
            }),
        }
    }
}

// ── App root ────────────────────────────────────────────────────────────────

#[component]
pub fn App() -> impl IntoView {
    view! {
        <Router>
            <main>
                <div class="bg-grid" aria-hidden="true"></div>
                <header>
                    <div class="logo">
                        <A href="/">"SecretShare"</A>
                    </div>
                </header>
                <div class="container">
                    <Routes fallback=move || {
                        view! {
                            <div class="card error-card">
                                <h1>"Page not found"</h1>
                                <a href="/" class="btn-outline">"Go home"</a>
                            </div>
                        }
                    }>
                        <Route path=path!("/") view=CreatePage/>
                        <Route path=path!("/s/:id") view=ViewPage/>
                    </Routes>
                </div>
                <footer>
                    <p>
                        "Secrets are encrypted in your browser and never stored in plain text. "
                        "The decryption key exists only in the link."
                    </p>
                </footer>
            </main>
        </Router>
    }
}

// ── Create page ─────────────────────────────────────────────────────────────

const VIEW_OPTIONS: [(u32, &str); 4] = [(1, "Once"), (5, "5×"), (10, "10×"), (25, "25×")];
const EXPIRY_OPTIONS: [(i64, &str); 4] = [
    (1, "1 day"),
    (7, "7 days"),
    (30, "30 days"),
    (90, "90 days"),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum InputMode {
    Text,
    File,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CreateStep {
    Form,
    Success,
}

#[component]
fn CreatePage() -> impl IntoView {
    // ── step ────────────────────────────────────────────────────────────────
    let (step, set_step) = signal(CreateStep::Form);

    // ── form state ──────────────────────────────────────────────────────────
    let (input_mode, set_input_mode) = signal(InputMode::Text);
    let (text_value, set_text_value) = signal(String::new());
    // Display-only filename shown below the <input type="file">
    let (selected_file_name, set_selected_file_name) = signal(String::new());
    let (max_views, set_max_views) = signal(1_u32);
    let (custom_views_on, set_custom_views_on) = signal(false);
    let (custom_views_val, set_custom_views_val) = signal(10_u32);
    let (password_on, set_password_on) = signal(false);
    let (password, set_password) = signal(String::new());
    let (expiry_days, set_expiry_days) = signal(7_i64);

    // ── result / feedback ───────────────────────────────────────────────────
    let (generated_url, set_generated_url) = signal(String::new());
    let (copied, set_copied) = signal(false);
    let (error_msg, set_error_msg) = signal(String::new());
    let (loading, set_loading) = signal(false);

    // NodeRef gives us access to the <input type="file"> DOM element so we
    // can read the selected File object when the form is submitted.
    let file_input_ref = NodeRef::<leptos::html::Input>::new();

    // ── derived ─────────────────────────────────────────────────────────────
    let effective_views = Memo::new(move |_| {
        if custom_views_on.get() {
            custom_views_val.get()
        } else {
            max_views.get()
        }
    });

    let can_submit = Memo::new(move |_| {
        let has_payload = match input_mode.get() {
            InputMode::Text => !text_value.get().trim().is_empty(),
            InputMode::File => !selected_file_name.get().is_empty(),
        };
        has_payload && (!password_on.get() || !password.get().trim().is_empty()) && !loading.get()
    });

    // ── submit handler ───────────────────────────────────────────────────────
    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        set_error_msg.set(String::new());

        if !can_submit.get() {
            return;
        }

        // Capture all reactive values before the async boundary.
        let mode = input_mode.get();
        let text = text_value.get();
        let mv = effective_views.get() as i32;
        let pass = if password_on.get() && !password.get().trim().is_empty() {
            Some(password.get())
        } else {
            None
        };
        let days = expiry_days.get();
        let fref = file_input_ref.clone();

        set_loading.set(true);
leptos::task::spawn_local(async move {
            #[cfg(feature = "hydrate")]
            {
                use client::create_secret;
                use crypto::ContentType;
                use wasm_bindgen::JsCast; // 👈 1. DODANY IMPORT

                let result: Result<String, String> = match mode {
                    InputMode::Text => {
                        create_secret(ContentType::Text, text.into_bytes(), mv, pass, days).await
                    }
                    InputMode::File => {
                        // Grab the File from the <input type="file"> DOM node.
                        let maybe_file = fref
                            .get()
                            .as_deref()
                            .and_then(|el| el.dyn_ref::<web_sys::HtmlInputElement>()) // 👈 2. DODANE RZUTOWANIE
                            .and_then(|el| el.files())
                            .and_then(|list| list.get(0));

                        match maybe_file {
                            None => Err("No file selected.".to_string()),
                            Some(f) => match client::read_file_bytes(&f).await {
                                Err(e) => Err(e),
                                Ok((name, bytes)) => {
                                    create_secret(ContentType::File { name }, bytes, mv, pass, days)
                                        .await
                                }
                            },
                        }
                    }
                };

                match result {
                    Ok(url) => {
                        set_generated_url.set(url);
                        set_step.set(CreateStep::Success);
                    }
                    Err(e) => set_error_msg.set(e),
                }
            }

            // In SSR this branch is taken; the WASM has not loaded yet so
            // nothing happens – after hydration the real branch runs.
            #[cfg(not(feature = "hydrate"))]
            {
                let _ = (mode, text, mv, pass, days, fref);
                set_error_msg.set("JavaScript is required to encrypt secrets.".to_string());
            }

            set_loading.set(false);
        });
    };

    // ── reset ────────────────────────────────────────────────────────────────
    let reset = move |_| {
        set_step.set(CreateStep::Form);
        set_input_mode.set(InputMode::Text);
        set_text_value.set(String::new());
        set_selected_file_name.set(String::new());
        set_max_views.set(1);
        set_custom_views_on.set(false);
        set_custom_views_val.set(10);
        set_password_on.set(false);
        set_password.set(String::new());
        set_expiry_days.set(7);
        set_generated_url.set(String::new());
        set_copied.set(false);
        set_error_msg.set(String::new());
        set_loading.set(false);
    };

    // ── copy link ────────────────────────────────────────────────────────────
    let copy_link = move |_| {
        #[cfg(feature = "hydrate")]
        if let Some(w) = web_sys::window() {
            let _ = w.navigator().clipboard().write_text(&generated_url.get());
        }
        set_copied.set(true);
    };

    // ── view ─────────────────────────────────────────────────────────────────
    view! {
        <Show
            when=move || step.get() == CreateStep::Form
            fallback=move || view! {
                // ── Success card ───────────────────────────────────────────
                <div class="card success-card">
                    <h1>"Your secret link is ready!"</h1>
                    <p class="success-subtitle">
                        "Share this link — it self-destructs after "
                        <strong>{move || effective_views.get()}</strong>
                        {move || if effective_views.get() == 1 { " view." } else { " views." }}
                    </p>

                    <div class="link-box">
                        <input
                            type="text"
                            readonly
                            prop:value=move || generated_url.get()
                            aria-label="Generated secret link"
                        />
                        <button
                            type="button"
                            class="copy-btn"
                            class:copied=move || copied.get()
                            on:click=copy_link
                        >
                            {move || if copied.get() { "Copied!" } else { "Copy link" }}
                        </button>
                    </div>

                    <div class="meta-pills">
                        <div class="pill">
                            {move || format!(
                                "{} {} max",
                                effective_views.get(),
                                if effective_views.get() == 1 { "view" } else { "views" }
                            )}
                        </div>
                        <Show when=move || password_on.get()>
                            <div class="pill">"Password protected"</div>
                        </Show>
                        <div class="pill">
                            {move || if input_mode.get() == InputMode::Text {
                                "Text".to_string()
                            } else if selected_file_name.get().is_empty() {
                                "File".to_string()
                            } else {
                                selected_file_name.get()
                            }}
                        </div>
                    </div>

                    <button type="button" class="btn-outline" on:click=reset>
                        "Create another secret"
                    </button>
                </div>
            }
        >
            // ── Create form ────────────────────────────────────────────────
            <div class="card">
                <div class="card-header">
                    <h1>"Create a secret link"</h1>
                    <p>
                        "Encrypted in your browser before upload. "
                        "The server never sees the plaintext or the key."
                    </p>
                </div>

                <form on:submit=on_submit>

                    // ── Mode toggle ──────────────────────────────────────────
                    <div class="mode-toggle" role="tablist">
                        <button
                            role="tab" type="button" class="tab"
                            class:active=move || input_mode.get() == InputMode::Text
                            aria-selected=move || (input_mode.get() == InputMode::Text).to_string()
                            on:click=move |_| set_input_mode.set(InputMode::Text)
                        >
                            "Text"
                        </button>
                        <button
                            role="tab" type="button" class="tab"
                            class:active=move || input_mode.get() == InputMode::File
                            aria-selected=move || (input_mode.get() == InputMode::File).to_string()
                            on:click=move |_| set_input_mode.set(InputMode::File)
                        >
                            "File"
                        </button>
                    </div>

                    // ── Text / File input ────────────────────────────────────
                    <Show
                        when=move || input_mode.get() == InputMode::Text
                        fallback=move || view! {
                            <div class="field">
                                <label for="secret-file">"Choose file"</label>
                                <input
                                    id="secret-file"
                                    type="file"
                                    class="file-input"
                                    node_ref=file_input_ref
                                    on:change=move |_ev| {
                                        #[cfg(feature = "hydrate")]
                                        {
                                            use wasm_bindgen::JsCast;
                                            let name = _ev
                                                .target()
                                                .and_then(|t| {
                                                    t.dyn_into::<web_sys::HtmlInputElement>().ok()
                                                })
                                                .and_then(|el| el.files())
                                                .and_then(|list| list.get(0))
                                                .map(|f| f.name())
                                                .unwrap_or_default();
                                            set_selected_file_name.set(name);
                                        }
                                    }
                                />
                                <p class="field-hint">
                                    {move || if selected_file_name.get().is_empty() {
                                        "Any file type · max 25 MB · content type is encrypted too".to_string()
                                    } else {
                                        format!("Selected: {}", selected_file_name.get())
                                    }}
                                </p>
                            </div>
                        }
                    >
                        <div class="field">
                            <label for="secret-text">"Secret text"</label>
                            <textarea
                                id="secret-text"
                                rows="5"
                                placeholder="Type or paste your secret message…"
                                prop:value=move || text_value.get()
                                on:input=move |ev| set_text_value.set(event_target_value(&ev))
                            ></textarea>
                        </div>
                    </Show>

                    // ── Expiry ───────────────────────────────────────────────
                    <div class="field">
                        <label>"Expires after"</label>
                        <div class="views-options">
                            {EXPIRY_OPTIONS.iter().copied().map(|(d, label)| view! {
                                <button
                                    type="button"
                                    class="view-btn"
                                    class:selected=move || expiry_days.get() == d
                                    on:click=move |_| set_expiry_days.set(d)
                                >
                                    {label}
                                </button>
                            }).collect_view()}
                        </div>
                    </div>

                    // ── Max views ────────────────────────────────────────────
                    <div class="field">
                        <label>"Maximum views"</label>
                        <div class="views-options">
                            {VIEW_OPTIONS.iter().copied().map(|(opt, label)| view! {
                                <button
                                    type="button"
                                    class="view-btn"
                                    class:selected=move || {
                                        !custom_views_on.get() && max_views.get() == opt
                                    }
                                    on:click=move |_| {
                                        set_max_views.set(opt);
                                        set_custom_views_on.set(false);
                                    }
                                >
                                    {label}
                                </button>
                            }).collect_view()}
                            <button
                                type="button"
                                class="view-btn"
                                class:selected=move || custom_views_on.get()
                                on:click=move |_| set_custom_views_on.set(true)
                            >
                                "Custom"
                            </button>
                        </div>

                        <Show when=move || custom_views_on.get()>
                            <div class="custom-views">
                                <input
                                    type="number"
                                    min="1"
                                    max="1000"
                                    prop:value=move || custom_views_val.get().to_string()
                                    on:input=move |ev| {
                                        if let Ok(v) = event_target_value(&ev).parse::<u32>() {
                                            set_custom_views_val.set(v.clamp(1, 1000));
                                        }
                                    }
                                />
                                <span class="views-label">"views"</span>
                            </div>
                        </Show>

                        <p class="field-hint">
                            "Permanently destroyed after "
                            <strong>{move || effective_views.get()}</strong>
                            {move || if effective_views.get() == 1 { " view." } else { " views." }}
                        </p>
                    </div>

                    // ── Password protection ──────────────────────────────────
                    <div class="field">
                        <div class="toggle-row">
                            <div>
                                <label class="toggle-label" for="pw-toggle">
                                    "Password protection"
                                </label>
                                <p class="toggle-desc">
                                    "Hashed with Argon2id in your browser before upload"
                                </p>
                            </div>
                            <button
                                id="pw-toggle"
                                type="button"
                                class="toggle"
                                class:on=move || password_on.get()
                                aria-pressed=move || password_on.get().to_string()
                                on:click=move |_| set_password_on.update(|v| *v = !*v)
                            >
                                <span class="thumb"></span>
                            </button>
                        </div>

                        <Show when=move || password_on.get()>
                            <div class="password-field">
                                <div class="password-input-wrap">
                                    <input
                                        type="password"
                                        placeholder="Enter password…"
                                        autocomplete="new-password"
                                        prop:value=move || password.get()
                                        on:input=move |ev| set_password.set(event_target_value(&ev))
                                    />
                                </div>
                            </div>
                        </Show>
                    </div>

                    // ── Error ────────────────────────────────────────────────
                    <Show when=move || !error_msg.get().is_empty()>
                        <p class="submit-error" role="alert">
                            {move || error_msg.get()}
                        </p>
                    </Show>

                    // ── Submit ───────────────────────────────────────────────
                    <button
                        type="submit"
                        class="btn-primary"
                        disabled=move || !can_submit.get()
                    >
                        {move || if loading.get() {
                            // Argon2 in WASM can take a second; inform the user.
                            if password_on.get() {
                                "Hashing password & encrypting…"
                            } else {
                                "Encrypting…"
                            }
                        } else {
                            "Generate secret link"
                        }}
                    </button>
                </form>
            </div>
        </Show>
    }
}

// ── View page ────────────────────────────────────────────────────────────────

/// All states the viewer page can be in.
#[derive(Clone, PartialEq)]
enum ViewState {
    /// Fetching metadata from the server.
    LoadingMeta,
    /// Metadata arrived; user must enter the password before we spend a view.
    NeedsPassword,
    /// Password was submitted (or not needed); downloading + decrypting.
    Decrypting,
    /// Successfully decrypted; content is in a separate signal.
    Ready,
    /// Unrecoverable error (expired, burned, wrong key, …).
    Dead(String),
}

#[component]
fn ViewPage() -> impl IntoView {
    let params = use_params_map();
    // Reactive accessor: re-runs when the route params change.
    let id = move || params.with(|p| p.get("id").unwrap_or_default());

    let (state, set_state) = signal(ViewState::LoadingMeta);
    // Stored separately so the signal type stays `Clone + PartialEq` cheaply.
    let (decrypted, set_decrypted) = signal::<Option<Decrypted>>(None);
    let (views_left, set_views_left) = signal(0_i32);
    let (pw_input, set_pw_input) = signal(String::new());
    let (pw_error, set_pw_error) = signal(String::new());
    // Cache the key so the password-submit handler can use it.
    let (key_b64, set_key_b64) = signal(String::new());

    // ── Initialise on mount ──────────────────────────────────────────────────
    // `Effect::new` tracks every signal read inside it; here we read `id()`
    // which means the effect re-runs when navigating between different secrets.
    Effect::new(move |_: Option<()>| {
        let current_id = id();

        leptos::task::spawn_local(async move {
            #[cfg(feature = "hydrate")]
            {
                // The fragment (#…) is never sent to the server; read it here
                // in the browser.
                let hash = client::location_hash();
                let key = hash.trim_start_matches('#').to_string();

                if key.is_empty() {
                    set_state.set(ViewState::Dead(
                        "No decryption key found in the URL. \
                         Make sure you copied the complete link \
                         including everything after the # symbol."
                            .to_string(),
                    ));
                    return;
                }

                set_key_b64.set(key.clone());

                match client::get_meta(&current_id).await {
                    Err(e) => set_state.set(ViewState::Dead(e)),

                    Ok(meta) if meta.burned => set_state.set(ViewState::Dead(
                        "This secret has been permanently destroyed.".to_string(),
                    )),

                    Ok(meta) if meta.views_left <= 0 => set_state.set(ViewState::Dead(
                        "This secret has reached its view limit.".to_string(),
                    )),

                    Ok(meta) => {
                        set_views_left.set(meta.views_left);

                        if meta.password_required {
                            // Show the password form; do NOT spend a view yet.
                            set_state.set(ViewState::NeedsPassword);
                        } else {
                            // No password – fetch and decrypt immediately.
                            set_state.set(ViewState::Decrypting);
                            match client::fetch_and_decrypt(&current_id, &key, None).await {
                                Ok(payload) => {
                                    set_decrypted.set(Some(payload));
                                    set_state.set(ViewState::Ready);
                                }
                                Err(e) => set_state.set(ViewState::Dead(e)),
                            }
                        }
                    }
                }
            }
            // SSR: stay in LoadingMeta; the WASM takes over after hydration.
        });
    });

    // ── Password submit ──────────────────────────────────────────────────────
    let on_pw_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        set_pw_error.set(String::new());

        let pw = pw_input.get();
        if pw.trim().is_empty() {
            set_pw_error.set("Please enter the password.".to_string());
            return;
        }

        let current_id = id();
        let key = key_b64.get();

        set_state.set(ViewState::Decrypting);

        leptos::task::spawn_local(async move {
            #[cfg(feature = "hydrate")]
            match client::fetch_and_decrypt(&current_id, &key, Some(pw)).await {
                Ok(payload) => {
                    set_decrypted.set(Some(payload));
                    set_state.set(ViewState::Ready);
                }
                Err(e) if e == "wrong_password" => {
                    // Return to the password form with an error.
                    set_state.set(ViewState::NeedsPassword);
                    set_pw_error.set("Incorrect password. Please try again.".to_string());
                }
                Err(e) if e == "expired" => {
                    set_state.set(ViewState::Dead(
                        "This secret has expired or reached its view limit.".to_string(),
                    ));
                }
                Err(e) => set_state.set(ViewState::Dead(e)),
            }

            #[cfg(not(feature = "hydrate"))]
            {
                let _ = (current_id, key);
            }
        });
    };

    // ── View ─────────────────────────────────────────────────────────────────
    view! {
        <div class="card">
            {move || match state.get() {

                // ── Loading metadata ─────────────────────────────────────────
                ViewState::LoadingMeta => view! {
                    <div class="secret-loading">
                        <div class="spinner"></div>
                        <p>"Fetching secret metadata…"</p>
                    </div>
                }.into_any(),

                // ── Password gate ────────────────────────────────────────────
                ViewState::NeedsPassword => view! {
                    <div>
                        <div class="card-header">
                            <h1>"Password required"</h1>
                            <p>
                                "This secret is password-protected. "
                                {move || {
                                    let vl = views_left.get();
                                    if vl > 0 {
                                        format!(
                                            "{vl} view{} remaining.",
                                            if vl == 1 { "" } else { "s" }
                                        )
                                    } else {
                                        String::new()
                                    }
                                }}
                            </p>
                        </div>

                        <form on:submit=on_pw_submit>
                            <div class="field">
                                <label for="view-pw">"Password"</label>
                                <input
                                    id="view-pw"
                                    type="password"
                                    placeholder="Enter password…"
                                    autocomplete="current-password"
                                    prop:value=move || pw_input.get()
                                    on:input=move |ev| set_pw_input.set(event_target_value(&ev))
                                />
                            </div>

                            <Show when=move || !pw_error.get().is_empty()>
                                <p class="submit-error" role="alert">
                                    {move || pw_error.get()}
                                </p>
                            </Show>

                            <button type="submit" class="btn-primary">
                                "Decrypt secret"
                            </button>
                        </form>
                    </div>
                }.into_any(),

                // ── Decrypting ───────────────────────────────────────────────
                ViewState::Decrypting => view! {
                    <div class="secret-loading">
                        <div class="spinner"></div>
                        <p>"Decrypting…"</p>
                    </div>
                }.into_any(),

                // ── Ready ────────────────────────────────────────────────────
                ViewState::Ready => {
                    match decrypted.get() {
                        Some(Decrypted::Text(text)) => view! {
                            <div>
                                <div class="card-header">
                                    <h1>"Secret revealed"</h1>
                                    <p class="success-subtitle">
                                        "This view has been counted. "
                                        "Copy the content before closing this tab."
                                    </p>
                                </div>
                                <div class="field">
                                    <label>"Content"</label>
                                    <textarea
                                        rows="10"
                                        readonly
                                        prop:value=text
                                    ></textarea>
                                </div>
                            </div>
                        }.into_any(),

                        Some(Decrypted::File { name, bytes }) => {
                            // Build a temporary object URL so the browser can
                            // download the file without re-contacting the server.
                            #[cfg(feature = "hydrate")]
                            let dl_url = client::make_blob_url(
                                &bytes,
                                "application/octet-stream",
                            )
                            .unwrap_or_default();

                            #[cfg(not(feature = "hydrate"))]
                            let dl_url = String::new();

                            let file_size = bytes.len();
                            let display_name = name.clone();

                            view! {
                                <div>
                                    <div class="card-header">
                                        <h1>"Secret file revealed"</h1>
                                        <p class="success-subtitle">
                                            "This view has been counted. "
                                            "Download the file before closing this tab."
                                        </p>
                                    </div>
                                    <div class="file-download">
                                        <div class="file-icon">"📁"</div>
                                        <div class="file-info">
                                            <strong>{display_name.clone()}</strong>
                                            <span class="field-hint">
                                                {format_file_size(file_size)}
                                            </span>
                                        </div>
                                        <a
                                            href=dl_url
                                            download=name
                                            class="btn-primary file-dl-btn"
                                        >
                                            "Download"
                                        </a>
                                    </div>
                                </div>
                            }.into_any()
                        }

                        // Should never happen (Ready always has Some), but
                        // handle gracefully anyway.
                        None => view! {
                            <div class="secret-loading">
                                <p>"Content unavailable."</p>
                            </div>
                        }.into_any(),
                    }
                }

                // ── Dead (expired / burned / error) ──────────────────────────
                ViewState::Dead(msg) => view! {
                    <div class="error-card">
                        <h1>"Secret unavailable"</h1>
                        <p class="submit-error">{msg}</p>
                        <a href="/" class="btn-outline" style="display:inline-block;margin-top:1rem;">
                            "Create a new secret"
                        </a>
                    </div>
                }.into_any(),
            }}
        </div>
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn format_file_size(bytes: usize) -> String {
    if bytes < 1_024 {
        format!("{bytes} B")
    } else if bytes < 1_024 * 1_024 {
        format!("{:.1} KB", bytes as f64 / 1_024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1_024.0 * 1_024.0))
    }
}
