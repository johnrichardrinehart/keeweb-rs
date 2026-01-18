//! Auto-lock component with countdown modal

use leptos::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;

use crate::state::{AppState, AppView};

/// Inactivity timeout before showing warning (milliseconds)
const WARNING_TIMEOUT_MS: u32 = 20_000; // 20 seconds

/// Countdown duration after warning (milliseconds)
#[allow(dead_code)]
const COUNTDOWN_DURATION_MS: u32 = 10_000; // 10 seconds

/// Auto-lock component - tracks inactivity and shows countdown modal
#[component]
pub fn AutoLock() -> impl IntoView {
    let state = expect_context::<AppState>();

    // Countdown state
    let show_warning = create_rw_signal(false);
    let countdown_seconds = create_rw_signal(10i32);

    // Timer handles stored in signals for cleanup
    let inactivity_timer: StoredValue<Option<i32>> = store_value(None);
    let countdown_timer: StoredValue<Option<i32>> = store_value(None);

    // Reset inactivity timer - called on user activity
    let reset_timer = move || {
        // Only track activity when database is open
        if state.current_view.get_untracked() != AppView::Database {
            return;
        }

        // Clear existing timers
        if let Some(timer_id) = inactivity_timer.get_value() {
            clear_timeout(timer_id);
        }
        if let Some(timer_id) = countdown_timer.get_value() {
            clear_interval(timer_id);
        }

        // Hide warning if shown
        show_warning.set(false);
        countdown_seconds.set(10);

        // Set new inactivity timer
        let timer_id = set_timeout(
            move || {
                // Show warning modal and start countdown
                if state.current_view.get_untracked() == AppView::Database {
                    show_warning.set(true);
                    countdown_seconds.set(10);

                    // Start countdown interval
                    let interval_id = set_interval(
                        move || {
                            let current = countdown_seconds.get_untracked();
                            if current <= 1 {
                                // Time's up - lock the database
                                if let Some(timer_id) = countdown_timer.get_value() {
                                    clear_interval(timer_id);
                                }
                                show_warning.set(false);
                                state.close_database();
                            } else {
                                countdown_seconds.set(current - 1);
                            }
                        },
                        1000, // 1 second intervals
                    );
                    countdown_timer.set_value(Some(interval_id));
                }
            },
            WARNING_TIMEOUT_MS,
        );
        inactivity_timer.set_value(Some(timer_id));
    };

    // Keep alive - user clicked to stay
    let keep_alive = move |_| {
        reset_timer();
    };

    // Set up activity listeners when component mounts
    create_effect(move |_| {
        // Only set up listeners when database is open
        if state.current_view.get() != AppView::Database {
            // Clear timers when not in database view
            if let Some(timer_id) = inactivity_timer.get_value() {
                clear_timeout(timer_id);
                inactivity_timer.set_value(None);
            }
            if let Some(timer_id) = countdown_timer.get_value() {
                clear_interval(timer_id);
                countdown_timer.set_value(None);
            }
            show_warning.set(false);
            return;
        }

        // Start initial timer
        reset_timer();
    });

    // Set up global event listeners for activity tracking
    create_effect(move |_| {
        let window = web_sys::window().expect("no window");
        let document = window.document().expect("no document");

        // Create event handler closures
        let reset_timer_clone = reset_timer;
        let on_activity: Closure<dyn Fn()> = Closure::new(move || {
            reset_timer_clone();
        });

        // Add listeners for various activity events
        let _ = document
            .add_event_listener_with_callback("mousemove", on_activity.as_ref().unchecked_ref());
        let _ = document
            .add_event_listener_with_callback("mousedown", on_activity.as_ref().unchecked_ref());
        let _ = document
            .add_event_listener_with_callback("keydown", on_activity.as_ref().unchecked_ref());
        let _ = document
            .add_event_listener_with_callback("touchstart", on_activity.as_ref().unchecked_ref());
        let _ = document
            .add_event_listener_with_callback("scroll", on_activity.as_ref().unchecked_ref());

        // Forget the closure to keep it alive
        on_activity.forget();
    });

    // Cleanup on unmount
    on_cleanup(move || {
        if let Some(timer_id) = inactivity_timer.get_value() {
            clear_timeout(timer_id);
        }
        if let Some(timer_id) = countdown_timer.get_value() {
            clear_interval(timer_id);
        }
    });

    view! {
        <Show when=move || show_warning.get()>
            <div class="auto-lock-overlay">
                <div class="auto-lock-modal">
                    <div class="auto-lock-icon">
                        <svg viewBox="0 0 24 24" width="48" height="48">
                            <path fill="currentColor" d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>
                        </svg>
                    </div>
                    <h2 class="auto-lock-title">"Locking soon..."</h2>
                    <p class="auto-lock-message">
                        "The database will lock due to inactivity in"
                    </p>
                    <div class="auto-lock-countdown">
                        {move || countdown_seconds.get()}
                    </div>
                    <p class="auto-lock-unit">"seconds"</p>
                    <button
                        class="btn btn-primary auto-lock-button"
                        on:click=keep_alive
                    >
                        "Stay Unlocked"
                    </button>
                </div>
            </div>
        </Show>
    }
}

// JS timer helpers
fn set_timeout<F>(callback: F, delay_ms: u32) -> i32
where
    F: FnOnce() + 'static,
{
    let window = web_sys::window().expect("no window");
    let closure = Closure::once(callback);
    let timer_id = window
        .set_timeout_with_callback_and_timeout_and_arguments_0(
            closure.as_ref().unchecked_ref(),
            delay_ms as i32,
        )
        .expect("set_timeout failed");
    closure.forget();
    timer_id
}

fn set_interval<F>(callback: F, interval_ms: u32) -> i32
where
    F: Fn() + 'static,
{
    let window = web_sys::window().expect("no window");
    let closure: Closure<dyn Fn()> = Closure::new(callback);
    let timer_id = window
        .set_interval_with_callback_and_timeout_and_arguments_0(
            closure.as_ref().unchecked_ref(),
            interval_ms as i32,
        )
        .expect("set_interval failed");
    closure.forget();
    timer_id
}

fn clear_timeout(timer_id: i32) {
    if let Some(window) = web_sys::window() {
        window.clear_timeout_with_handle(timer_id);
    }
}

fn clear_interval(timer_id: i32) {
    if let Some(window) = web_sys::window() {
        window.clear_interval_with_handle(timer_id);
    }
}
