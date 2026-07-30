use crate::model::{ClientSnapshot, LocalServiceState, LocalTunnelState};

pub(crate) const ICON_SIZE: usize = 32;
const ICON_RADIUS: i32 = 14;

#[derive(Debug)]
pub(crate) enum TrayInput {
    Snapshot(ClientSnapshot),
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TrayState {
    Gray,
    Red,
    Yellow,
    Green,
}

impl TrayState {
    pub(crate) fn from_input(input: TrayInput) -> Self {
        match input {
            TrayInput::Unavailable => Self::Gray,
            TrayInput::Snapshot(snapshot) if snapshot.service == LocalServiceState::Failed => {
                Self::Red
            }
            TrayInput::Snapshot(snapshot)
                if snapshot.tunnel == LocalTunnelState::Connected && snapshot.live_carriers > 0 =>
            {
                Self::Green
            }
            TrayInput::Snapshot(_) => Self::Yellow,
        }
    }

    pub(crate) const fn tooltip(self) -> &'static str {
        match self {
            Self::Gray => "rqbit tunnel: unavailable",
            Self::Red => "rqbit tunnel: service failed",
            Self::Yellow => "rqbit tunnel: reconnecting",
            Self::Green => "rqbit tunnel: connected",
        }
    }
}

pub(crate) const fn color_for(state: TrayState) -> [u8; 4] {
    match state {
        TrayState::Gray => [128, 128, 128, 255],
        TrayState::Red => [220, 53, 69, 255],
        TrayState::Yellow => [255, 193, 7, 255],
        TrayState::Green => [25, 135, 84, 255],
    }
}

pub(crate) fn rgba_circle(state: TrayState) -> Vec<u8> {
    let color = color_for(state);
    let mut rgba = vec![0; ICON_SIZE * ICON_SIZE * 4];
    let center = (ICON_SIZE / 2) as i32;

    for y in 0..ICON_SIZE {
        for x in 0..ICON_SIZE {
            let dx = x as i32 - center;
            let dy = y as i32 - center;
            if dx * dx + dy * dy <= ICON_RADIUS * ICON_RADIUS {
                let offset = (y * ICON_SIZE + x) * 4;
                rgba[offset..offset + 4].copy_from_slice(&color);
            }
        }
    }

    rgba
}

#[cfg(test)]
mod tests {
    use crate::model::{ClientSnapshot, LocalServiceState, LocalTunnelState};

    use super::{ICON_SIZE, TrayInput, TrayState, color_for, rgba_circle};

    fn snapshot(
        service: LocalServiceState,
        tunnel: LocalTunnelState,
        live_carriers: usize,
    ) -> ClientSnapshot {
        ClientSnapshot {
            service,
            tunnel,
            socks_listen: Some("127.0.0.1:1080".parse().expect("test socket address")),
            configured_carriers: 2,
            live_carriers,
            version: "9.9.9-secret-version".to_owned(),
            error: Some("private service error".to_owned()),
        }
    }

    #[test]
    fn tray_state_is_green_only_with_a_connected_carrier() {
        assert_eq!(
            TrayState::from_input(TrayInput::Snapshot(snapshot(
                LocalServiceState::Running,
                LocalTunnelState::Connected,
                1,
            ))),
            TrayState::Green
        );
        assert_eq!(
            TrayState::from_input(TrayInput::Snapshot(snapshot(
                LocalServiceState::Running,
                LocalTunnelState::Connected,
                0,
            ))),
            TrayState::Yellow
        );
        assert_eq!(
            TrayState::from_input(TrayInput::Snapshot(snapshot(
                LocalServiceState::Running,
                LocalTunnelState::Reconnecting,
                1,
            ))),
            TrayState::Yellow
        );
    }

    #[test]
    fn unavailable_input_is_gray() {
        assert_eq!(
            TrayState::from_input(TrayInput::Unavailable),
            TrayState::Gray
        );
    }

    #[test]
    fn failed_client_snapshot_is_red() {
        assert_eq!(
            TrayState::from_input(TrayInput::Snapshot(snapshot(
                LocalServiceState::Failed,
                LocalTunnelState::Connected,
                1,
            ))),
            TrayState::Red
        );
    }

    #[test]
    fn state_colors_and_circle_icon_are_exact_and_in_memory() {
        assert_eq!(color_for(TrayState::Gray), [128, 128, 128, 255]);
        assert_eq!(color_for(TrayState::Red), [220, 53, 69, 255]);
        assert_eq!(color_for(TrayState::Yellow), [255, 193, 7, 255]);
        assert_eq!(color_for(TrayState::Green), [25, 135, 84, 255]);

        let icon = rgba_circle(TrayState::Green);
        assert_eq!(icon.len(), ICON_SIZE * ICON_SIZE * 4);
        let center = ((ICON_SIZE / 2) * ICON_SIZE + (ICON_SIZE / 2)) * 4;
        assert_eq!(&icon[center..center + 4], &[25, 135, 84, 255]);
        assert_eq!(&icon[..4], &[0, 0, 0, 0]);
    }

    #[test]
    fn tooltip_is_redacted_to_the_state_only() {
        let tooltip = TrayState::Green.tooltip();

        assert_eq!(tooltip, "rqbit tunnel: connected");
        assert!(!tooltip.contains("secret"));
        assert!(!tooltip.contains("127.0.0.1"));
    }
}
