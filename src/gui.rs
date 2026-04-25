// GUI 模块 - 从原仓库直接迁移，功能不变
// 原始文件见 https://github.com/budong1212/bitku/blob/main/gui.rs
use crate::password_checker::{CheckResult, PasswordChecker};
use crate::wallet::BitcoinCoreWallet;
use eframe::egui;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

/// 应用状态
#[derive(Debug, Clone, PartialEq)]
enum AppState {
    Idle,
    Running,
    Finished,
    Error(String),
}

/// 共享的运行状态
struct RunState {
    result: Option<CheckResult>,
    log: Vec<String>,
}

/// 主应用结构体
pub struct RecoveryApp {
    // 钱包文件路径
    wallet_path: Option<PathBuf>,
    wallet_info: Option<String>,
    wallet: Option<BitcoinCoreWallet>,

    // 字典文件路径
    dict_path: Option<PathBuf>,

    // 单个密码测试
    test_password: String,
    test_result: Option<bool>,

    // 运行状态
    state: AppState,
    run_state: Arc<Mutex<RunState>>,

    // 进度显示
    progress_count: u64,
    progress_speed: f64,
}

impl RecoveryApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            wallet_path: None,
            wallet_info: None,
            wallet: None,
            dict_path: None,
            test_password: String::new(),
            test_result: None,
            state: AppState::Idle,
            run_state: Arc::new(Mutex::new(RunState {
                result: None,
                log: Vec::new(),
            })),
            progress_count: 0,
            progress_speed: 0.0,
        }
    }
}

impl eframe::App for RecoveryApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("BTC Recovery - 高性能 CPU 优化版");
            ui.separator();

            // --- 钱包加载区 ---
            ui.group(|ui| {
                ui.label("📂 钱包文件");
                ui.horizontal(|ui| {
                    let path_text = self
                        .wallet_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "未选择".to_string());
                    ui.label(&path_text);
                    if ui.button("选择钱包文件…").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("wallet", &["dat", "sqlite", "db"])
                            .pick_file()
                        {
                            match BitcoinCoreWallet::load_from_file(&path) {
                                Ok(w) => {
                                    self.wallet_info = Some(w.difficulty_info());
                                    self.wallet = Some(w);
                                    self.wallet_path = Some(path);
                                }
                                Err(e) => {
                                    self.wallet_info =
                                        Some(format!("加载失败: {}", e));
                                }
                            }
                        }
                    }
                });
                if let Some(info) = &self.wallet_info {
                    ui.label(format!("ℹ️  {}", info));
                }
            });

            ui.add_space(8.0);

            // --- 单密码测试区 ---
            ui.group(|ui| {
                ui.label("🔑 测试单个密码");
                ui.horizontal(|ui| {
                    ui.text_edit_singleline(&mut self.test_password);
                    let btn = ui.add_enabled(
                        self.wallet.is_some() && !self.test_password.is_empty(),
                        egui::Button::new("测试"),
                    );
                    if btn.clicked() {
                        if let Some(w) = &self.wallet {
                            let checker = PasswordChecker::new(w.clone());
                            self.test_result =
                                Some(checker.check_password(&self.test_password));
                        }
                    }
                });
                if let Some(ok) = self.test_result {
                    if ok {
                        ui.colored_label(egui::Color32::GREEN, "✅ 密码正确！");
                    } else {
                        ui.colored_label(egui::Color32::RED, "❌ 密码错误");
                    }
                }
            });

            ui.add_space(8.0);

            // --- 字典攻击区 ---
            ui.group(|ui| {
                ui.label("📖 字典攻击");
                ui.horizontal(|ui| {
                    let dict_text = self
                        .dict_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "未选择".to_string());
                    ui.label(&dict_text);
                    if ui.button("选择字典文件…").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("txt", &["txt"])
                            .pick_file()
                        {
                            self.dict_path = Some(path);
                        }
                    }
                });

                let can_start = self.wallet.is_some()
                    && self.dict_path.is_some()
                    && self.state != AppState::Running;

                if ui
                    .add_enabled(can_start, egui::Button::new("🚀 开始恢复"))
                    .clicked()
                {
                    self.start_recovery(ctx.clone());
                }

                // 进度显示
                if self.state == AppState::Running {
                    ui.separator();
                    ui.label(format!(
                        "已检查: {}  速度: {:.0} pwd/s",
                        self.progress_count, self.progress_speed
                    ));
                    ctx.request_repaint();
                }

                // 结果
                {
                    let rs = self.run_state.lock().unwrap();
                    if let Some(ref r) = rs.result {
                        ui.separator();
                        match &r.password {
                            Some(pw) => {
                                ui.colored_label(
                                    egui::Color32::GREEN,
                                    format!("🎉 找到密码: {}", pw),
                                );
                            }
                            None => {
                                ui.colored_label(
                                    egui::Color32::YELLOW,
                                    "未找到密码，字典已穷举",
                                );
                            }
                        }
                        ui.label(format!(
                            "总耗时: {:.2}s  平均速度: {:.0} pwd/s",
                            r.elapsed_secs, r.speed
                        ));
                    }

                    // 日志
                    if !rs.log.is_empty() {
                        ui.separator();
                        egui::ScrollArea::vertical()
                            .max_height(120.0)
                            .show(ui, |ui| {
                                for line in rs.log.iter().rev().take(50) {
                                    ui.label(line);
                                }
                            });
                    }
                }

                if let AppState::Error(ref msg) = self.state.clone() {
                    ui.colored_label(egui::Color32::RED, format!("错误: {}", msg));
                }
            });
        });
    }
}

impl RecoveryApp {
    fn start_recovery(&mut self, ctx: egui::Context) {
        let wallet = match self.wallet.clone() {
            Some(w) => w,
            None => return,
        };
        let dict_path = match self.dict_path.clone() {
            Some(p) => p,
            None => return,
        };

        self.state = AppState::Running;
        self.progress_count = 0;
        self.progress_speed = 0.0;

        // 清空上次结果
        {
            let mut rs = self.run_state.lock().unwrap();
            rs.result = None;
            rs.log.clear();
        }

        let run_state = self.run_state.clone();
        let progress_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let progress_speed = Arc::new(std::sync::Mutex::new(0.0f64));
        let pc_clone = progress_count.clone();
        let ps_clone = progress_speed.clone();

        thread::spawn(move || {
            // 读取字典
            let content = match std::fs::read_to_string(&dict_path) {
                Ok(c) => c,
                Err(e) => {
                    let mut rs = run_state.lock().unwrap();
                    rs.log
                        .push(format!("读取字典失败: {}", e));
                    return;
                }
            };
            let passwords: Vec<String> =
                content.lines().map(|l| l.to_string()).collect();

            let checker = PasswordChecker::new(wallet);
            let result = checker.check_passwords_parallel(&passwords, move |count, speed| {
                pc_clone.store(count, std::sync::atomic::Ordering::Relaxed);
                *ps_clone.lock().unwrap() = speed;
                ctx.request_repaint();
            });

            let mut rs = run_state.lock().unwrap();
            rs.result = Some(result);
        });
    }
}
