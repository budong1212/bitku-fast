use crate::password_checker::{CheckResult, PasswordChecker};
use crate::wallet::BitcoinCoreWallet;
use crossbeam::channel;
use eframe::egui;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

const BATCH_SIZE: usize = 2_000;

#[derive(Debug, Clone, PartialEq)]
enum AppState {
    Idle,
    Running,
    Finished,
    Cancelled,
    Error(String),
}

struct RunState {
    result: Option<CheckResult>,
    log: Vec<String>,
    total_count: Option<u64>,
}

struct TaskHandle {
    cancel_flag: Arc<AtomicBool>,
    progress_count: Arc<AtomicU64>,
    progress_speed: Arc<Mutex<f64>>,
}

pub struct RecoveryApp {
    wallet_path: Option<PathBuf>,
    wallet_info: Option<String>,
    wallet: Option<BitcoinCoreWallet>,

    dict_path: Option<PathBuf>,

    test_password: String,
    test_result: Option<bool>,

    state: AppState,
    run_state: Arc<Mutex<RunState>>,
    task: Option<TaskHandle>,

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
                total_count: None,
            })),
            task: None,
            progress_count: 0,
            progress_speed: 0.0,
        }
    }

    fn poll_task_completion(&mut self) {
        if self.state != AppState::Running {
            return;
        }
        let rs = self.run_state.lock().unwrap();
        if rs.result.is_some() {
            drop(rs);
            let cancelled = self
                .task
                .as_ref()
                .map(|t| t.cancel_flag.load(Ordering::Relaxed))
                .unwrap_or(false);
            self.state = if cancelled {
                AppState::Cancelled
            } else {
                AppState::Finished
            };
            self.task = None;
        } else if let Some(ref t) = self.task {
            self.progress_count = t.progress_count.load(Ordering::Relaxed);
            self.progress_speed = *t.progress_speed.lock().unwrap();
        }
    }

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

        {
            let mut rs = self.run_state.lock().unwrap();
            rs.result = None;
            rs.log.clear();
            rs.total_count = None;
        }

        let cancel_flag = Arc::new(AtomicBool::new(false));
        let progress_count = Arc::new(AtomicU64::new(0));
        let progress_speed = Arc::new(Mutex::new(0.0f64));

        let handle = TaskHandle {
            cancel_flag: cancel_flag.clone(),
            progress_count: progress_count.clone(),
            progress_speed: progress_speed.clone(),
        };
        self.task = Some(handle);

        let run_state = self.run_state.clone();
        let pc_clone = progress_count.clone();
        let ps_clone = progress_speed.clone();
        let cancel_clone = cancel_flag.clone();
        let run_state2 = run_state.clone();
        let dict_path2 = dict_path.clone();

        // ── IO 线程：流式读取字典，按批发送 ──────────────────────────────────
        let (tx, rx) = channel::bounded::<Vec<String>>(16);

        thread::spawn(move || {
            if let Ok(f) = std::fs::File::open(&dict_path2) {
                let total = BufReader::new(f).lines().count() as u64;
                run_state2.lock().unwrap().total_count = Some(total);
            }

            let file = match std::fs::File::open(&dict_path) {
                Ok(f) => f,
                Err(e) => {
                    run_state.lock().unwrap().log.push(format!("读取字典失败: {}", e));
                    return;
                }
            };

            let reader = BufReader::new(file);
            let mut batch = Vec::with_capacity(BATCH_SIZE);

            for line in reader.lines() {
                if cancel_clone.load(Ordering::Relaxed) {
                    break;
                }
                if let Ok(l) = line {
                    batch.push(l);
                    if batch.len() >= BATCH_SIZE {
                        if tx
                            .send(std::mem::replace(&mut batch, Vec::with_capacity(BATCH_SIZE)))
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
            if !batch.is_empty() {
                let _ = tx.send(batch);
            }
        });

        // ── 计算线程：从 channel 消费并行验证 ────────────────────────────────
        let run_state3 = self.run_state.clone();
        // 修复 E0382: 提前 clone 两份 ctx，各自独立所有权
        let ctx_callback = ctx.clone();  // 给进度回调闭包
        let ctx_finish = ctx;            // 给线程结束时的 repaint
        thread::spawn(move || {
            let checker = PasswordChecker {
                wallet,
                checked_count: pc_clone,
                found: Arc::new(AtomicBool::new(false)),
                cancelled: cancel_flag,
                start_time: std::time::Instant::now(),
            };

            let result = checker.check_passwords_from_channel(rx, move |_count, speed| {
                *ps_clone.lock().unwrap() = speed;
                ctx_callback.request_repaint();
            });

            run_state3.lock().unwrap().result = Some(result);
            ctx_finish.request_repaint();
        });
    }
}

impl eframe::App for RecoveryApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_task_completion();

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("BTC Recovery - 高性能 CPU 优化版");
            ui.separator();

            // ── 钱包加载区 ────────────────────────────────────────────────────
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
                                    self.wallet_info = Some(format!("加载失败: {}", e));
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

            // ── 单密码测试区 ──────────────────────────────────────────────────
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
                            self.test_result = Some(checker.check_password(&self.test_password));
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

            // ── 字典攻击区 ────────────────────────────────────────────────────
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

                ui.horizontal(|ui| {
                    let can_start = self.wallet.is_some()
                        && self.dict_path.is_some()
                        && self.state != AppState::Running;

                    if ui
                        .add_enabled(can_start, egui::Button::new("🚀 开始恢复"))
                        .clicked()
                    {
                        self.start_recovery(ctx.clone());
                    }

                    if self.state == AppState::Running {
                        if ui
                            .add(
                                egui::Button::new("⏹ 停止")
                                    .fill(egui::Color32::from_rgb(180, 50, 50)),
                            )
                            .clicked()
                        {
                            if let Some(ref t) = self.task {
                                t.cancel_flag.store(true, Ordering::Relaxed);
                            }
                        }
                    }
                });

                // 进度显示 + ETA
                if self.state == AppState::Running {
                    ui.separator();
                    let total_opt = self.run_state.lock().unwrap().total_count;

                    let speed = self.progress_speed;
                    let count = self.progress_count;

                    let eta_str = match total_opt {
                        Some(total) if speed > 0.0 && total > count => {
                            let remaining = (total - count) as f64 / speed;
                            if remaining < 60.0 {
                                format!("  ETA: {:.0}s", remaining)
                            } else {
                                format!("  ETA: {:.1}min", remaining / 60.0)
                            }
                        }
                        _ => String::new(),
                    };

                    ui.label(format!(
                        "已检查: {}  速度: {:.0} pwd/s{}",
                        count, speed, eta_str
                    ));
                    ctx.request_repaint();
                }

                // 结果展示
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
                                if ui.button("📋 复制密码").clicked() {
                                    ui.output_mut(|o| o.copied_text = pw.clone());
                                }
                            }
                            None => {
                                let label = if r.cancelled {
                                    "🟡 任务已取消"
                                } else {
                                    "未找到密码，字典已穷举"
                                };
                                ui.colored_label(egui::Color32::YELLOW, label);
                            }
                        }
                        ui.label(format!(
                            "总耗时: {:.2}s  共检查: {}  平均速度: {:.0} pwd/s",
                            r.elapsed_secs, r.checked_count, r.speed
                        ));
                    }

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

                if self.state == AppState::Cancelled {
                    ui.colored_label(egui::Color32::YELLOW, "🟡 任务已停止");
                }
            });
        });
    }
}
