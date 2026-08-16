// SPDX-License-Identifier: MIT OR Apache-2.0

//! Choosing between the loopback and device flows for `ironauth login` (issue #120).
//!
//! # This is a security default, not a convenience one
//!
//! It is tempting to read the choice as "device flow for headless, loopback for desktop",
//! which is true but is the wrong reason. #120 states the actual reason: the loopback
//! pattern (RFC 8252 section 7.3) "avoids cross-device phishing exposure entirely when the
//! login happens on the same machine".
//!
//! The device flow's whole shape, a code you read off one screen and type into another, is
//! the shape of the attack: a user who is willing to type a code into a browser can be
//! persuaded to type an ATTACKER's code. `draft-ietf-oauth-cross-device-security` exists
//! because of it, and the server-side mitigations M3 shipped reduce that exposure without
//! removing it.
//!
//! So loopback is preferred WHENEVER it can work, and the device flow is the fallback for
//! machines that cannot open a browser. Getting this backwards, or defaulting to device
//! flow because it always works, trades a phishing class for convenience the user did not
//! ask for.
//!
//! The signals are taken as data rather than read from the process here, so every rule
//! below is a table entry rather than something that only reproduces on the right host.

/// Which flow `ironauth login` should drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginFlow {
    /// RFC 8252 loopback redirect with PKCE. Preferred: no cross-device exposure.
    Loopback,
    /// RFC 8628 device flow. The fallback for machines that cannot open a browser.
    Device,
}

/// What the caller explicitly asked for, if anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowPreference {
    /// No flag: detect.
    Detect,
    /// `--loopback`.
    ForceLoopback,
    /// `--device`.
    ForceDevice,
}

/// What `login` should actually do, once the registration and the bind are known.
///
/// `choose_flow` answers from the ENVIRONMENT, and the environment cannot know whether a
/// listener will bind or whether a loopback redirect was ever registered. Both of those are
/// discovered later, and both change the answer. Keeping that second decision here, as a
/// value, is what makes criterion 3's fallback half testable: it used to live inline in the
/// `login` command's async block, where nothing could reach it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginRoute {
    /// Drive the loopback flow.
    Loopback,
    /// Drive the device flow because that is what was CHOSEN, not fallen back to. Distinct
    /// from [`LoginRoute::DeviceFallback`] on purpose: the two are identical in what they
    /// run and opposite in what they mean, and collapsing them would print a fallback
    /// explanation to a user who asked for the device flow outright.
    Device,
    /// Drive the device flow instead, for this reason.
    DeviceFallback(FallbackReason),
    /// Refuse: the registration cannot support a loopback login at all.
    ///
    /// NOT a fallback. A registration a loopback login cannot use is a CONFIGURATION
    /// problem, and downgrading it silently would hide it behind a flow that happens to
    /// work, leaving it undiagnosable.
    Misconfigured,
}

/// Why a chosen loopback login became a device login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackReason {
    /// No loopback redirect was registered, so there is nothing to redirect to.
    NoRedirectRegistered,
    /// A listener could not be bound: IPv6 disabled against a `[::1]` registration, or a
    /// sandbox that forbids listening.
    ListenerWouldNotBind,
}

impl FallbackReason {
    /// What the user is told. A fallback that happened silently would leave them wondering
    /// why they are typing a code on a machine that has a browser.
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Self::NoRedirectRegistered => {
                "no --redirect registered for a loopback login; using the device flow instead"
            }
            Self::ListenerWouldNotBind => {
                "could not bind a loopback listener; using the device flow instead"
            }
        }
    }
}

/// Decide the route, given the environment's choice and what was then discovered.
///
/// `bound_ok` is whether a listener bound. It is only consulted when a redirect exists,
/// because binding is not attempted without one.
#[must_use]
pub fn route(
    flow: LoginFlow,
    registered_redirect: bool,
    registration_supports_loopback: bool,
    bound_ok: bool,
) -> LoginRoute {
    if flow == LoginFlow::Device {
        // Already the device flow. Nothing discovered later can change that, and a missing
        // redirect is not a fallback here: loopback was never wanted.
        return LoginRoute::Device;
    }
    if !registered_redirect {
        return LoginRoute::DeviceFallback(FallbackReason::NoRedirectRegistered);
    }
    if !bound_ok {
        return LoginRoute::DeviceFallback(FallbackReason::ListenerWouldNotBind);
    }
    if !registration_supports_loopback {
        return LoginRoute::Misconfigured;
    }
    LoginRoute::Loopback
}

/// The environment signals the decision reads.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostSignals {
    /// An SSH session: `SSH_CONNECTION` or `SSH_TTY` is set.
    pub over_ssh: bool,
    /// A display server is reachable: `DISPLAY` or `WAYLAND_DISPLAY` is set. Meaningful
    /// only where a display server is how a browser gets opened, which is why
    /// `browser_implicit` exists alongside it.
    pub has_display: bool,
    /// The platform opens a browser without a display variable (macOS, Windows).
    pub browser_implicit: bool,
}

/// Why the flow was chosen, so the CLI can say so rather than appearing to guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowReason {
    /// The caller passed a flag.
    Requested,
    /// A browser can be opened here.
    BrowserAvailable,
    /// An SSH session: the browser that would open is on the wrong machine.
    SshSession,
    /// No display server and no implicit browser.
    NoDisplay,
}

/// Choose the flow.
///
/// An explicit flag always wins, INCLUDING when it selects the device flow on a machine
/// that could have used loopback. That is a downgrade, and it is the caller's to make: a
/// developer testing the device flow, or one whose browser is genuinely unusable, should
/// not be overridden by a heuristic. What the CLI must not do is make that choice FOR them
/// silently, which is why the reason is returned rather than only the flow.
#[must_use]
pub fn choose_flow(signals: HostSignals, preference: FlowPreference) -> (LoginFlow, FlowReason) {
    match preference {
        FlowPreference::ForceLoopback => (LoginFlow::Loopback, FlowReason::Requested),
        FlowPreference::ForceDevice => (LoginFlow::Device, FlowReason::Requested),
        FlowPreference::Detect => {
            // SSH first, and it OUTRANKS a display. An SSH session that forwarded X11 has a
            // display, but the browser it opens is on the machine the user is sitting at
            // only by accident of configuration; treating that as "a local browser" is the
            // assumption that turns loopback's same-machine guarantee into a guess.
            if signals.over_ssh {
                return (LoginFlow::Device, FlowReason::SshSession);
            }
            if signals.has_display || signals.browser_implicit {
                return (LoginFlow::Loopback, FlowReason::BrowserAvailable);
            }
            (LoginFlow::Device, FlowReason::NoDisplay)
        }
    }
}

/// Read the signals from the process environment.
///
/// Separated from [`choose_flow`] so the rules are testable as a table. This function is
/// the only part that cannot be, and it is deliberately trivial for that reason.
#[must_use]
pub fn signals_from_env() -> HostSignals {
    let set = |name: &str| std::env::var_os(name).is_some_and(|value| !value.is_empty());
    HostSignals {
        over_ssh: set("SSH_CONNECTION") || set("SSH_TTY"),
        has_display: set("DISPLAY") || set("WAYLAND_DISPLAY"),
        // macOS and Windows open a browser without a display variable. Naming them
        // positively rather than treating "not Linux" as implicit keeps a new target
        // (a BSD, a container image) defaulting to the SAFE fallback rather than
        // assuming a browser it may not have.
        browser_implicit: cfg!(any(target_os = "macos", target_os = "windows")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desktop() -> HostSignals {
        HostSignals {
            over_ssh: false,
            has_display: true,
            browser_implicit: false,
        }
    }

    fn headless() -> HostSignals {
        HostSignals::default()
    }

    /// Criterion 3's second half: "falls back cleanly to device flow when the listener
    /// cannot bind". `choose_flow` answers from the environment, which cannot know that, so
    /// this is the decision that actually implements the criterion -- and it lived inline in
    /// the login command's async block, where no test could reach it.
    #[test]
    fn a_listener_that_will_not_bind_falls_back_to_the_device_flow() {
        assert_eq!(
            route(LoginFlow::Loopback, true, true, false),
            LoginRoute::DeviceFallback(FallbackReason::ListenerWouldNotBind),
        );
    }

    /// The happy path, asserted alongside it. Without this the test above passes for a
    /// `route` that returned the fallback unconditionally, which would mean the loopback
    /// flow never ran at all.
    #[test]
    fn a_loopback_login_that_binds_stays_a_loopback_login() {
        assert_eq!(route(LoginFlow::Loopback, true, true, true), LoginRoute::Loopback);
    }

    #[test]
    fn no_registered_redirect_falls_back_to_the_device_flow() {
        assert_eq!(
            route(LoginFlow::Loopback, false, true, true),
            LoginRoute::DeviceFallback(FallbackReason::NoRedirectRegistered),
        );
    }

    /// A registration a loopback login cannot use is NOT a fallback. Downgrading silently
    /// would hide a configuration error behind a flow that happens to work.
    #[test]
    fn a_registration_that_cannot_do_loopback_is_refused_not_downgraded() {
        assert_eq!(route(LoginFlow::Loopback, true, false, true), LoginRoute::Misconfigured);
    }

    /// A device login that was CHOSEN is not a fallback, whatever else is true of the host.
    /// Reporting it as one would tell a user who passed `--device` that something went
    /// wrong.
    #[test]
    fn a_chosen_device_login_is_never_reported_as_a_fallback() {
        for redirect in [true, false] {
            for bound in [true, false] {
                assert_eq!(
                    route(LoginFlow::Device, redirect, true, bound),
                    LoginRoute::Device,
                    "redirect={redirect} bound={bound}"
                );
            }
        }
    }

    /// Each fallback explains ITSELF. A user on a machine with a browser, suddenly typing a
    /// code, needs to know which of the two reasons applied.
    #[test]
    fn the_two_fallbacks_do_not_share_an_explanation() {
        let no_redirect = FallbackReason::NoRedirectRegistered.message();
        let no_bind = FallbackReason::ListenerWouldNotBind.message();
        assert_ne!(no_redirect, no_bind);
        assert!(no_redirect.contains("--redirect"), "{no_redirect}");
        assert!(no_bind.contains("bind"), "{no_bind}");
    }

    #[test]
    fn a_desktop_with_a_display_prefers_loopback() {
        // Preferred because it has NO cross-device exposure, not because it is nicer.
        assert_eq!(
            choose_flow(desktop(), FlowPreference::Detect),
            (LoginFlow::Loopback, FlowReason::BrowserAvailable)
        );
    }

    #[test]
    fn a_headless_box_falls_back_to_the_device_flow() {
        assert_eq!(
            choose_flow(headless(), FlowPreference::Detect),
            (LoginFlow::Device, FlowReason::NoDisplay)
        );
    }

    #[test]
    fn ssh_outranks_a_forwarded_display() {
        // The case that makes this more than a two-line rule. An SSH session with X11
        // forwarding HAS a display, so a naive check picks loopback and opens a browser on
        // whichever machine the display points at. Loopback's guarantee is that the login
        // happens on the SAME machine, and over SSH that is exactly what is not known.
        let forwarded = HostSignals {
            over_ssh: true,
            has_display: true,
            browser_implicit: false,
        };
        assert_eq!(
            choose_flow(forwarded, FlowPreference::Detect),
            (LoginFlow::Device, FlowReason::SshSession)
        );
    }

    #[test]
    fn ssh_outranks_an_implicit_browser_too() {
        // Same rule on macOS, where there is no DISPLAY to check: sshing INTO a Mac still
        // means the browser is on the wrong machine.
        let ssh_to_mac = HostSignals {
            over_ssh: true,
            has_display: false,
            browser_implicit: true,
        };
        assert_eq!(
            choose_flow(ssh_to_mac, FlowPreference::Detect).0,
            LoginFlow::Device
        );
    }

    #[test]
    fn a_platform_that_opens_a_browser_without_a_display_still_gets_loopback() {
        let mac = HostSignals {
            over_ssh: false,
            has_display: false,
            browser_implicit: true,
        };
        assert_eq!(
            choose_flow(mac, FlowPreference::Detect),
            (LoginFlow::Loopback, FlowReason::BrowserAvailable)
        );
    }

    #[test]
    fn an_explicit_flag_wins_in_both_directions() {
        // Including the DOWNGRADE. Forcing the device flow on a desktop accepts
        // cross-device exposure, and that is the caller's call to make: a developer testing
        // the device flow should not be overridden by a heuristic.
        assert_eq!(
            choose_flow(desktop(), FlowPreference::ForceDevice),
            (LoginFlow::Device, FlowReason::Requested)
        );
        // And forcing loopback on a headless box is allowed even though it will fail to
        // open a browser: a wrong flag should produce a clear failure, not a silent
        // substitution the user never asked for.
        assert_eq!(
            choose_flow(headless(), FlowPreference::ForceLoopback),
            (LoginFlow::Loopback, FlowReason::Requested)
        );
    }

    #[test]
    fn every_detected_choice_carries_a_reason_that_is_not_requested() {
        // The CLI prints the reason, so a user can see WHY it picked a flow rather than
        // watching it appear to guess. A detected choice reporting `Requested` would be a
        // lie in the one place a confused user looks.
        for signals in [desktop(), headless()] {
            let (_, reason) = choose_flow(signals, FlowPreference::Detect);
            assert_ne!(reason, FlowReason::Requested, "{signals:?}");
        }
    }
}
