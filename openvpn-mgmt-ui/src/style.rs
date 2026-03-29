//! Gruvbox-themed style helpers.
//!
//! small functions derive colours from the active [`iced::Theme`] palette
//! so the UI stays consistent regardless of the concrete theme variant.

use iced::widget::{container, text};
use iced::{Border, Color, Theme};
use iced_aw::style::{Status, tab_bar};

// -------------------------------------------------------------------
// Tab bar
// -------------------------------------------------------------------

pub(crate) fn tab_style(theme: &Theme, status: Status) -> tab_bar::Style {
    let palette = theme.extended_palette();
    let background = palette.background.base.color;
    let foreground = palette.background.base.text;

    let base = tab_bar::Style {
        background: None,
        border_color: None,
        border_width: 0.0,
        tab_label_background: Color::TRANSPARENT.into(),
        tab_label_border_color: Color::TRANSPARENT,
        tab_label_border_width: 0.0,
        icon_color: foreground,
        icon_background: None,
        icon_border_radius: 0.0.into(),
        tab_border_radius: 0.0.into(),
        text_color: mix(foreground, background, 0.4),
    };

    match status {
        Status::Active => tab_bar::Style {
            tab_label_background: mix(background, foreground, 0.08).into(),
            text_color: foreground,
            ..base
        },
        Status::Hovered => tab_bar::Style {
            tab_label_background: mix(background, foreground, 0.06).into(),
            text_color: mix(foreground, background, 0.15),
            ..base
        },
        _ => base,
    }
}

// -------------------------------------------------------------------
// Text styles
// -------------------------------------------------------------------

pub(crate) fn text_label(theme: &Theme) -> text::Style {
    let (foreground, background) = foreground_background(theme);
    text::Style {
        color: Some(mix(foreground, background, 0.4)),
    }
}

pub(crate) fn text_muted(theme: &Theme) -> text::Style {
    let (foreground, background) = foreground_background(theme);
    text::Style {
        color: Some(mix(foreground, background, 0.5)),
    }
}

pub(crate) fn text_warning(theme: &Theme) -> text::Style {
    let palette = theme.extended_palette();
    let danger = palette.danger.base.color;
    let success = palette.success.base.color;
    text::Style {
        color: Some(Color {
            r: danger.r * 0.67 + success.r * 0.33,
            g: danger.g * 0.33 + success.g * 0.67,
            b: (danger.b + success.b) * 0.25,
            a: 1.0,
        }),
    }
}

// -------------------------------------------------------------------
// Container styles
// -------------------------------------------------------------------

/// Tooltip popup container — weak background with a thin border.
pub(crate) fn tooltip_box() -> <Theme as container::Catalog>::Class<'static> {
    Box::new(|theme: &Theme| {
        let palette = theme.extended_palette();
        container::Style {
            background: Some(palette.background.weak.color.into()),
            border: Border {
                color: palette.background.strong.color,
                width: 1.0,
                radius: 4.0.into(),
            },
            ..Default::default()
        }
    })
}

/// Status dot — small colored circle.
pub(crate) fn status_dot(color: Color) -> <Theme as container::Catalog>::Class<'static> {
    Box::new(move |_theme: &Theme| container::Style {
        background: Some(color.into()),
        border: Border {
            radius: 4.0.into(),
            ..Default::default()
        },
        ..Default::default()
    })
}

/// Selected row — subtle highlighted background.
pub(crate) fn row_selected() -> <Theme as container::Catalog>::Class<'static> {
    Box::new(|theme: &Theme| {
        let palette = theme.extended_palette();
        container::Style {
            background: Some(
                mix(
                    palette.background.base.color,
                    palette.primary.base.color,
                    0.15,
                )
                .into(),
            ),
            border: Border {
                radius: 2.0.into(),
                ..Default::default()
            },
            ..Default::default()
        }
    })
}

/// Flash row — brighter highlight for copy feedback.
pub(crate) fn row_flash() -> <Theme as container::Catalog>::Class<'static> {
    Box::new(|theme: &Theme| {
        let palette = theme.extended_palette();
        container::Style {
            background: Some(
                mix(
                    palette.background.base.color,
                    palette.primary.base.color,
                    0.35,
                )
                .into(),
            ),
            border: Border {
                radius: 2.0.into(),
                ..Default::default()
            },
            ..Default::default()
        }
    })
}

/// Status card container — subtle raised surface.
pub(crate) fn card() -> <Theme as container::Catalog>::Class<'static> {
    Box::new(|theme: &Theme| {
        let palette = theme.extended_palette();
        container::Style {
            background: Some(
                mix(
                    palette.background.base.color,
                    palette.background.base.text,
                    0.04,
                )
                .into(),
            ),
            border: Border {
                color: mix(
                    palette.background.base.color,
                    palette.background.base.text,
                    0.10,
                ),
                width: 1.0,
                radius: 6.0.into(),
            },
            ..Default::default()
        }
    })
}

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------

pub(crate) fn foreground_background(theme: &Theme) -> (Color, Color) {
    let palette = theme.extended_palette();
    (palette.background.base.text, palette.background.base.color)
}

/// Linearly interpolate between two colours. `ratio = 0.0` → `start`, `ratio = 1.0` → `end`.
pub(crate) fn mix(start: Color, end: Color, ratio: f32) -> Color {
    Color {
        r: start.r + (end.r - start.r) * ratio,
        g: start.g + (end.g - start.g) * ratio,
        b: start.b + (end.b - start.b) * ratio,
        a: 1.0,
    }
}
