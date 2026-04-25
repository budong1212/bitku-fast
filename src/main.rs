#![windows_subsystem = "windows"]

mod gui;
mod password_checker;
mod wallet;

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
        Box::new(|cc| {
            // 加载 Windows 自带中文字体（微软雅黑），解决中文乱码
            let mut fonts = egui::FontDefinitions::default();

            // 尝试加载微软雅黑，失败则尝试宋体
            let font_paths = [
                "C:\\Windows\\Fonts\\msyh.ttc",   // 微软雅黑 (Win7+)
                "C:\\Windows\\Fonts\\msyh.ttf",   // 微软雅黑旧版本
                "C:\\Windows\\Fonts\\simsun.ttc", // 宋体备用
            ];

            let mut loaded = false;
            for path in &font_paths {
                if let Ok(data) = std::fs::read(path) {
                    fonts.font_data.insert(
                        "chinese_font".to_owned(),
                        egui::FontData::from_owned(data),
                    );
                    // 将中文字体插入到首位，确保中文字符优先使用它
                    fonts
                        .families
                        .entry(egui::FontFamily::Proportional)
                        .or_default()
                        .insert(0, "chinese_font".to_owned());
                    fonts
                        .families
                        .entry(egui::FontFamily::Monospace)
                        .or_default()
                        .push("chinese_font".to_owned());
                    loaded = true;
                    break;
                }
            }

            if !loaded {
                // 如果找不到字体文件，输出警告（不崩溃）
                eprintln!("[warn] 未找到 Windows 中文字体，界面可能显示乱码");
            }

            cc.egui_ctx.set_fonts(fonts);

            Box::new(gui::RecoveryApp::new(cc))
        }),
    )
    .map_err(|e| anyhow::anyhow!("Failed to run GUI: {}", e))
}
