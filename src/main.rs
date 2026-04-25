mod wallet;
mod password_checker;
mod gui;

use anyhow::Result;

fn main() -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 600.0])
            .with_min_inner_size([600.0, 400.0])
            .with_title("BTC Recovery - Rust Edition"),
        ..Default::default()
    };

    eframe::run_native(
        "BTC Recovery",
        options,
        Box::new(|cc| Box::new(gui::RecoveryApp::new(cc))),
    )
    .map_err(|e| anyhow::anyhow!("Failed to run GUI: {}", e))
}
