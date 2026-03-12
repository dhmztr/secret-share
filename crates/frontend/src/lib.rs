use leptos::prelude::*;

pub const STYLES: &str = include_str!("styles.css");
pub const FAVICON: &str = include_str!("favicon.svg");

const VIEW_OPTIONS: [u32; 4] = [1, 5, 10, 25];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Text,
    File,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Create,
    Success,
}

#[component]
pub fn App() -> impl IntoView {
    let (mode, set_mode) = signal(Mode::Text);
    let (step, set_step) = signal(Step::Create);

    let (text_value, set_text_value) = signal(String::new());
    let (selected_file, set_selected_file) = signal(String::new());
    let (max_views, set_max_views) = signal(1_u32);
    let (custom_views_enabled, set_custom_views_enabled) = signal(false);
    let (custom_views_value, set_custom_views_value) = signal(10_u32);
    let (password_enabled, set_password_enabled) = signal(false);
    let (password, set_password) = signal(String::new());

    let (generated_link, set_generated_link) = signal(String::new());
    let (copied, set_copied) = signal(false);
    let (submit_error, set_submit_error) = signal(String::new());

    let effective_max_views = Memo::new(move |_| {
        if custom_views_enabled.get() {
            custom_views_value.get()
        } else {
            max_views.get()
        }
    });

    let can_submit = Memo::new(move |_| {
        let has_payload = match mode.get() {
            Mode::Text => !text_value.get().trim().is_empty(),
            Mode::File => !selected_file.get().trim().is_empty(),
        };

        has_payload && (!password_enabled.get() || !password.get().trim().is_empty())
    });

    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        set_submit_error.set(String::new());

        if mode.get() == Mode::Text && text_value.get().trim().is_empty() {
            set_submit_error.set("Please enter some text before generating a link.".to_string());
            return;
        }

        if mode.get() == Mode::File && selected_file.get().trim().is_empty() {
            set_submit_error.set("Please select a file before generating a link.".to_string());
            return;
        }

        if password_enabled.get() && password.get().trim().is_empty() {
            set_submit_error
                .set("Please enter a password or disable password protection.".to_string());
            return;
        }

        if custom_views_enabled.get() && !(1..=1000).contains(&custom_views_value.get()) {
            set_submit_error
                .set("Custom view count must be a whole number between 1 and 1000.".to_string());
            return;
        }

        let id = uuid::Uuid::new_v4().simple().to_string();
        let short = &id[..12];
        let origin = current_origin();
        set_generated_link.set(format!("{origin}/s/{short}"));
        set_step.set(Step::Success);
    };

    let reset = move |_| {
        set_mode.set(Mode::Text);
        set_step.set(Step::Create);
        set_text_value.set(String::new());
        set_selected_file.set(String::new());
        set_max_views.set(1);
        set_custom_views_enabled.set(false);
        set_custom_views_value.set(10);
        set_password_enabled.set(false);
        set_password.set(String::new());
        set_generated_link.set(String::new());
        set_copied.set(false);
        set_submit_error.set(String::new());
    };

    let copy_link = move |_| {
        #[cfg(target_arch = "wasm32")]
        {
            if let Some(window) = web_sys::window() {
                let navigator = window.navigator();
                let _ = navigator.clipboard().write_text(&generated_link.get());
            }
        }

        set_copied.set(true);
    };

    view! {
        <main>
            <div class="bg-grid" aria-hidden="true"></div>

            <header>
                <div class="logo">
                    <span>"SecretShare"</span>
                </div>
            </header>

            <div class="container">
                <Show
                    when=move || step.get() == Step::Create
                    fallback=move || {
                        view! {
                            <div class="card success-card">
                                <h1>"Your secret link is ready!"</h1>
                                <p class="success-subtitle">
                                    "Share this link. It will self-destruct after "
                                    <strong>{move || effective_max_views.get()}</strong>
                                    {move || if effective_max_views.get() == 1 { " view." } else { " views." }}
                                </p>

                                <div class="link-box">
                                    <input type="text" readonly prop:value=move || generated_link.get() aria-label="Generated link"/>
                                    <button type="button" class="copy-btn" class:copied=move || copied.get() on:click=copy_link>
                                        {move || if copied.get() { "Copied!" } else { "Copy link" }}
                                    </button>
                                </div>

                                <div class="meta-pills">
                                    <div class="pill">
                                        {move || format!("{} {} max", effective_max_views.get(), if effective_max_views.get() == 1 { "view" } else { "views" })}
                                    </div>
                                    <Show when=move || password_enabled.get() && !password.get().is_empty()>
                                        <div class="pill">"Password protected"</div>
                                    </Show>
                                    <div class="pill">
                                        {move || if mode.get() == Mode::Text { "Text".to_string() } else if selected_file.get().is_empty() { "File".to_string() } else { selected_file.get() }}
                                    </div>
                                </div>

                                <button type="button" class="btn-outline" on:click=reset>
                                    "Create another secret"
                                </button>
                            </div>
                        }
                    }
                >
                    <div class="card">
                        <div class="card-header">
                            <h1>"Create a secret link"</h1>
                            <p>"Share text or a file securely. The link self-destructs after the set number of views."</p>
                        </div>

                        <form on:submit=on_submit>
                            <div class="mode-toggle" role="tablist">
                                <button
                                    role="tab"
                                    type="button"
                                    class="tab"
                                    class:active=move || mode.get() == Mode::Text
                                    aria-selected=move || mode.get() == Mode::Text
                                    on:click=move |_| set_mode.set(Mode::Text)
                                >
                                    "Text"
                                </button>
                                <button
                                    role="tab"
                                    type="button"
                                    class="tab"
                                    class:active=move || mode.get() == Mode::File
                                    aria-selected=move || mode.get() == Mode::File
                                    on:click=move |_| set_mode.set(Mode::File)
                                >
                                    "File"
                                </button>
                            </div>

                            <Show
                                when=move || mode.get() == Mode::Text
                                fallback=move || {
                                    view! {
                                        <div class="field">
                                            <label for="secret-file">"File"</label>
                                            <input
                                                id="secret-file"
                                                type="text"
                                                placeholder="Paste a filename to simulate file selection"
                                                prop:value=move || selected_file.get()
                                                on:input=move |ev| set_selected_file.set(event_target_value(&ev))
                                            />
                                            <p class="field-hint">"Any file type · Max 25 MB"</p>
                                        </div>
                                    }
                                }
                            >
                                <div class="field">
                                    <label for="secret-text">"Secret text"</label>
                                    <textarea
                                        id="secret-text"
                                        rows="5"
                                        placeholder="Enter your secret message here…"
                                        prop:value=move || text_value.get()
                                        on:input=move |ev| set_text_value.set(event_target_value(&ev))
                                    ></textarea>
                                </div>
                            </Show>

                            <div class="field">
                                <label>"Maximum views"</label>
                                <div class="views-options">
                                    {VIEW_OPTIONS
                                        .iter()
                                        .copied()
                                        .map(|opt| {
                                            view! {
                                                <button
                                                    type="button"
                                                    class="view-btn"
                                                    class:selected=move || !custom_views_enabled.get() && max_views.get() == opt
                                                    on:click=move |_| {
                                                        set_max_views.set(opt);
                                                        set_custom_views_enabled.set(false);
                                                    }
                                                >
                                                    {if opt == 1 { "Once".to_string() } else { format!("{opt}×") }}
                                                </button>
                                            }
                                        })
                                        .collect_view()}
                                    <button
                                        type="button"
                                        class="view-btn"
                                        class:selected=move || custom_views_enabled.get()
                                        on:click=move |_| set_custom_views_enabled.set(true)
                                    >
                                        "Custom"
                                    </button>
                                </div>

                                <Show when=move || custom_views_enabled.get()>
                                    <div class="custom-views">
                                        <input
                                            type="number"
                                            min="1"
                                            max="1000"
                                            prop:value=move || custom_views_value.get().to_string()
                                            on:input=move |ev| {
                                                set_custom_views_value.set(event_target_value(&ev).parse::<u32>().unwrap_or(1));
                                            }
                                        />
                                        <span class="views-label">"views"</span>
                                    </div>
                                </Show>

                                <p class="field-hint">
                                    "The link will be permanently destroyed after "
                                    <strong>{move || effective_max_views.get()}</strong>
                                    {move || if effective_max_views.get() == 1 { " view." } else { " views." }}
                                </p>
                            </div>

                            <div class="field">
                                <div class="toggle-row">
                                    <div>
                                        <label class="toggle-label" for="password-toggle">"Password protection"</label>
                                        <p class="toggle-desc">"Require a password to view the secret"</p>
                                    </div>
                                    <button
                                        id="password-toggle"
                                        type="button"
                                        class="toggle"
                                        class:on=move || password_enabled.get()
                                        on:click=move |_| set_password_enabled.update(|current| *current = !*current)
                                    >
                                        <span class="thumb"></span>
                                    </button>
                                </div>

                                <Show when=move || password_enabled.get()>
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

                            <Show when=move || !submit_error.get().is_empty()>
                                <p class="submit-error" role="alert">{move || submit_error.get()}</p>
                            </Show>

                            <button type="submit" class="btn-primary" disabled=move || !can_submit.get()>
                                "Generate secret link"
                            </button>
                        </form>
                    </div>
                </Show>
            </div>

            <footer>
                <p>"Your secrets are encrypted and never stored in plain text."</p>
            </footer>
        </main>
    }
}

#[cfg(target_arch = "wasm32")]
fn current_origin() -> String {
    web_sys::window()
        .and_then(|window| window.location().origin().ok())
        .unwrap_or_default()
}

#[cfg(not(target_arch = "wasm32"))]
fn current_origin() -> String {
    "http://localhost:8080".to_string()
}

#[cfg(test)]
mod tests {
    use super::current_origin;

    #[test]
    fn has_server_origin_fallback() {
        assert_eq!(current_origin(), "http://localhost:8080");
    }
}
