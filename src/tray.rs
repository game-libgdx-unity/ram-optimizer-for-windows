//! System-tray icon for the dashboard window. While the app runs it sits in the
//! tray; closing the window hides it to the tray (the app keeps running), and
//! the tray's "Quit" actually exits. Either way the OS-scheduled optimizer is
//! untouched — it runs in the background independent of this app.
//!
//! Real implementation on Windows/macOS; a no-op on Linux (where a tray needs
//! GTK, which we don't pull in — the app there just runs without a tray).

/// What the user picked from the tray menu.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    /// Show + focus the window.
    Open,
    /// Run one optimization pass now.
    RunNow,
    /// Exit the app for real.
    Quit,
}

#[cfg(not(target_os = "linux"))]
pub use imp::{poll_action, Tray, TrayIds};

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::TrayAction;
    use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem};
    use tray_icon::{
        Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent,
    };

    pub struct Tray {
        _tray: TrayIcon,
        open: MenuId,
        run: MenuId,
        quit: MenuId,
    }

    /// The menu-item ids, cloned out so a background thread can classify tray
    /// clicks without holding the (main-thread-only) `Tray`/`TrayIcon`.
    #[derive(Clone)]
    pub struct TrayIds {
        open: MenuId,
        run: MenuId,
        quit: MenuId,
    }

    /// Drain one pending tray interaction and classify it. Safe to call from any
    /// thread — the `*_EVENT` channels are global, fed by the main thread's message
    /// pump (which keeps running even while the window is hidden). A plain
    /// LEFT-CLICK on the icon opens the window directly (the menu is on right-click,
    /// see `with_menu_on_left_click(false)`); menu items map to their actions.
    pub fn poll_action(ids: &TrayIds) -> Option<TrayAction> {
        if let Ok(TrayIconEvent::Click {
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            ..
        }) = TrayIconEvent::receiver().try_recv()
        {
            return Some(TrayAction::Open);
        }
        let ev = MenuEvent::receiver().try_recv().ok()?;
        if ev.id == ids.open {
            Some(TrayAction::Open)
        } else if ev.id == ids.run {
            Some(TrayAction::RunNow)
        } else if ev.id == ids.quit {
            Some(TrayAction::Quit)
        } else {
            None
        }
    }

    /// A simple 32×32 round dot in the accent colour — no external asset needed.
    fn icon() -> Icon {
        const N: usize = 32;
        let mut rgba = vec![0u8; N * N * 4];
        let c = (N as f32 - 1.0) / 2.0;
        for y in 0..N {
            for x in 0..N {
                let dx = x as f32 - c;
                let dy = y as f32 - c;
                let d = (dx * dx + dy * dy).sqrt();
                let i = (y * N + x) * 4;
                if d <= c {
                    rgba[i] = 0x4a;
                    rgba[i + 1] = 0xa3;
                    rgba[i + 2] = 0xff;
                    rgba[i + 3] = 0xff;
                }
            }
        }
        Icon::from_rgba(rgba, N as u32, N as u32).expect("tray icon")
    }

    impl Tray {
        pub fn new() -> Option<Self> {
            let menu = Menu::new();
            let open = MenuItem::new("Open RAM Optimizer", true, None);
            let run = MenuItem::new("Run optimization now", true, None);
            let sep = tray_icon::menu::PredefinedMenuItem::separator();
            let quit = MenuItem::new("Quit", true, None);
            menu.append_items(&[&open, &run, &sep, &quit]).ok()?;
            let tray = TrayIconBuilder::new()
                .with_tooltip("RAM Optimizer — left-click to open · right-click for menu")
                .with_menu(Box::new(menu))
                // Left-click opens the window directly; the menu shows on right-click.
                .with_menu_on_left_click(false)
                .with_icon(icon())
                .build()
                .ok()?;
            Some(Tray {
                _tray: tray,
                open: open.id().clone(),
                run: run.id().clone(),
                quit: quit.id().clone(),
            })
        }

        /// Clone the menu-item ids for the background tray-event thread.
        pub fn ids(&self) -> TrayIds {
            TrayIds {
                open: self.open.clone(),
                run: self.run.clone(),
                quit: self.quit.clone(),
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use stub::{poll_action, Tray, TrayIds};

#[cfg(target_os = "linux")]
mod stub {
    use super::TrayAction;
    pub struct Tray;
    #[derive(Clone)]
    pub struct TrayIds;
    impl Tray {
        pub fn new() -> Option<Self> {
            None
        }
        pub fn ids(&self) -> TrayIds {
            TrayIds
        }
    }
    pub fn poll_action(_ids: &TrayIds) -> Option<TrayAction> {
        None
    }
}
