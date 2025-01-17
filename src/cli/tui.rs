use std::{
    fs,
    io::{stdout, Stdout},
    path::{Path, PathBuf},
    time::Instant,
};

use ratatui::{
    prelude::{
        Alignment, Color, Constraint, CrosstermBackend, Direction, Layout, Line, Rect, Span, Style,
    },
    style::Stylize,
    widgets::{Block, Paragraph, Wrap},
    Frame, Terminal,
};

use rosa::{
    config::{Config, RosaPhase},
    criterion::Criterion,
    error::RosaError,
    fuzzer::FuzzerStatus,
    oracle::{comp_min_max::CompMinMax, Oracle},
};
use rosa::{error, fail};

pub struct RosaTui {
    monitor_dir: PathBuf,
    terminal: Option<Terminal<CrosstermBackend<Stdout>>>,
    stats: RosaTuiStats,
}

struct RosaTuiStats {
    start_time: Option<Instant>,
    phase: RosaPhase,
    last_backdoor_time: Option<Instant>,
    last_new_trace_time: Option<Instant>,
    unique_backdoors: u64,
    total_backdoors: u64,
    total_traces: u64,
    edge_coverage: f64,
    syscall_coverage: f64,
    new_traces: u64,
    oracle: Box<dyn Oracle>,
    oracle_criterion: Criterion,
    clusters: Option<u64>,
    seed_traces: Option<u64>,
    formation_criterion: Criterion,
    selection_criterion: Criterion,
    edge_tolerance: u64,
    syscall_tolerance: u64,
    config_file_path: String,
    output_dir_path: String,
    alive_fuzzers: u64,
    total_fuzzers: u64,
    crash_warning: bool,
}

impl RosaTuiStats {
    pub fn new(config_path: &Path, output_dir_path: &Path) -> Self {
        Self {
            phase: RosaPhase::Starting,
            start_time: None,
            last_backdoor_time: None,
            last_new_trace_time: None,
            unique_backdoors: 0,
            total_backdoors: 0,
            total_traces: 0,
            edge_coverage: 0.0,
            syscall_coverage: 0.0,
            new_traces: 0,
            oracle: Box::new(CompMinMax),
            oracle_criterion: Criterion::EdgesAndSyscalls,
            clusters: None,
            seed_traces: None,
            formation_criterion: Criterion::EdgesAndSyscalls,
            selection_criterion: Criterion::EdgesAndSyscalls,
            edge_tolerance: 0,
            syscall_tolerance: 0,
            config_file_path: config_path.display().to_string(),
            output_dir_path: output_dir_path.join("").display().to_string(),
            alive_fuzzers: 0,
            total_fuzzers: 0,
            crash_warning: false,
        }
    }

    pub fn load_config(&mut self, monitor_dir: &Path) -> Result<(), RosaError> {
        let config = Config::load(&monitor_dir.join("config").with_extension("toml"))?;

        self.oracle = config.oracle;
        self.oracle_criterion = config.oracle_criterion;
        self.formation_criterion = config.cluster_formation_criterion;
        self.selection_criterion = config.cluster_selection_criterion;
        self.edge_tolerance = config.cluster_formation_edge_tolerance;
        self.syscall_tolerance = config.cluster_formation_syscall_tolerance;

        self.total_fuzzers = config.fuzzers.len() as u64;

        Ok(())
    }

    pub fn update(&mut self, monitor_dir: &Path) -> Result<(), RosaError> {
        let config = Config::load(&monitor_dir.join("config").with_extension("toml"))?;

        // Get the current phase.
        self.phase = config.get_current_phase()?;

        // Check for new traces.
        let current_traces = fs::read_dir(config.traces_dir())
            .map_or_else(
                |err| {
                    fail!(
                        "could not read traces directory '{}': {}.",
                        config.traces_dir().display(),
                        err
                    )
                },
                |res| {
                    Ok(res
                        // Ignore files/dirs we cannot read.
                        .filter_map(|item| item.ok())
                        .map(|item| item.path())
                        // Only keep files that have no extension
                        .filter(|path| path.is_file() && path.extension().is_none()))
                },
            )?
            .collect::<Vec<PathBuf>>()
            .len() as u64;
        let new_traces = current_traces - self.total_traces;
        if new_traces > 0 {
            self.last_new_trace_time = Some(Instant::now());
        }
        self.new_traces = new_traces;
        self.total_traces += new_traces;

        // Update coverage.
        // If not possible (e.g. the other process is writing in the file), it's fine, we'll keep
        // the same coverage for now.
        (self.edge_coverage, self.syscall_coverage) = config
            .get_current_coverage()
            .unwrap_or((self.edge_coverage, self.syscall_coverage));

        if self.clusters.is_none() && self.phase == RosaPhase::DetectingBackdoors {
            // Check for clusters.
            let cluster_files: Vec<PathBuf> = fs::read_dir(config.clusters_dir())
                .map_or_else(
                    |err| {
                        fail!(
                            "could not read clusters directory '{}': {}.",
                            config.clusters_dir().display(),
                            err
                        )
                    },
                    |res| {
                        Ok(res
                            // Ignore files/dirs we cannot read.
                            .filter_map(|item| item.ok())
                            .map(|item| item.path())
                            // Only keep files that end in `.txt`.
                            .filter(|path| {
                                path.is_file()
                                    && path.extension().is_some_and(|extension| extension == "txt")
                                    && path.file_name().is_some_and(|name| name != "README.txt")
                            }))
                    },
                )?
                .collect();
            self.clusters = Some(cluster_files.len() as u64);
            self.seed_traces = Some(cluster_files.iter().try_fold(0, |acc, file| {
                let cluster_file_content = fs::read_to_string(file).map_err(|err| {
                    error!("could not read cluster file '{}': {}.", file.display(), err)
                })?;
                let traces: Vec<&str> = cluster_file_content
                    .split('\n')
                    // Filter empty lines (newlines).
                    .filter(|line| !line.is_empty())
                    .collect();

                Ok(acc + (traces.len() as u64))
            })?);
        }

        // Check for new backdoors.
        let unique_backdoor_dirs: Vec<PathBuf> = fs::read_dir(config.backdoors_dir())
            .map_or_else(
                |err| {
                    fail!(
                        "could not read backdoors directory '{}': {}.",
                        config.backdoors_dir().display(),
                        err
                    )
                },
                |res| {
                    Ok(res
                        // Ignore files/dirs we cannot read.
                        .filter_map(|item| item.ok())
                        .map(|item| item.path())
                        // Only keep directories (corresponding to unique backdoors).
                        .filter(|path| path.is_dir()))
                },
            )?
            .collect();

        let new_total_backdoors: Vec<u64> = unique_backdoor_dirs
            .iter()
            .map(|backdoor_dir| {
                fs::read_dir(backdoor_dir).map_or_else(
                    |err| {
                        fail!(
                            "could not read backdoor directory '{}': {}.",
                            backdoor_dir.display(),
                            err
                        )
                    },
                    |res| {
                        Ok(res
                            // Ignore files/dirs we cannot read.
                            .filter_map(|item| item.ok())
                            .map(|item| item.path())
                            // Only keep files that have no extension
                            .filter(|path| path.is_file() && path.extension().is_none())
                            .collect::<Vec<PathBuf>>()
                            .len() as u64)
                    },
                )
            })
            .collect::<Result<Vec<u64>, RosaError>>()?;
        let new_total_backdoors = new_total_backdoors.iter().sum();

        if new_total_backdoors > self.total_backdoors {
            self.last_backdoor_time = Some(Instant::now());
        }
        self.total_backdoors = new_total_backdoors;
        self.unique_backdoors = unique_backdoor_dirs.len() as u64;

        // Check for crashes.
        if !self.crash_warning {
            let found_crashes: Vec<bool> = config
                .fuzzers
                .iter()
                .map(|fuzzer_config| fuzzer_config.backend.found_crashes())
                .collect::<Result<Vec<bool>, RosaError>>()?;
            self.crash_warning = found_crashes.iter().any(|found_crashes| *found_crashes);
        }

        // Check for how many fuzzers are alive.
        self.alive_fuzzers = config
            .fuzzers
            .iter()
            .filter_map(|fuzzer_config| match fuzzer_config.backend.status() {
                FuzzerStatus::Running => Some(1),
                _ => None,
            })
            .count() as u64;

        Ok(())
    }

    pub fn run_time(&self) -> String {
        self.start_time
            .map(|time| {
                let seconds = time.elapsed().as_secs();

                format!(
                    "{:02.}:{:02.}:{:02.}",
                    (seconds / 60) / 60,
                    (seconds / 60) % 60,
                    seconds % 60
                )
            })
            .unwrap_or("(not started yet)".to_string())
    }

    pub fn time_since_last_backdoor(&self) -> String {
        self.last_backdoor_time
            .map(|time| {
                let seconds = time.elapsed().as_secs();

                format!(
                    "{:02.}:{:02.}:{:02.}",
                    (seconds / 60) / 60,
                    (seconds / 60) % 60,
                    seconds % 60
                )
            })
            .unwrap_or("(none seen yet)".to_string())
    }

    pub fn time_since_last_new_trace(&self) -> String {
        self.last_new_trace_time
            .map(|time| {
                let seconds = time.elapsed().as_secs();

                format!(
                    "{:02.}:{:02.}:{:02.}",
                    (seconds / 60) / 60,
                    (seconds / 60) % 60,
                    seconds % 60
                )
            })
            .unwrap_or("(none seen yet)".to_string())
    }
}

impl RosaTui {
    const MIN_WIDTH: u16 = 90;
    const MIN_HEIGHT: u16 = 21;

    pub fn new(config_path: &Path, monitor_dir: &Path) -> Self {
        RosaTui {
            monitor_dir: monitor_dir.to_path_buf(),
            terminal: None,
            stats: RosaTuiStats::new(config_path, monitor_dir),
        }
    }

    pub fn start(&mut self) -> Result<(), RosaError> {
        match &self.terminal {
            Some(_) => fail!("TUI: could not start TUI, because it's already running."),
            None => Ok(()),
        }?;

        self.terminal = Some(
            Terminal::new(CrosstermBackend::new(stdout()))
                .map_err(|err| error!("TUI: could not create new terminal: {}.", err))?,
        );
        self.terminal
            .as_mut()
            .unwrap()
            .clear()
            .map_err(|err| error!("TUI: could not clear terminal: {}.", err))?;

        self.stats.start_time = Some(Instant::now());
        self.stats.load_config(&self.monitor_dir)?;

        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), RosaError> {
        self.terminal
            .as_mut()
            .ok_or(error!("TUI: could not stop TUI, because it's not running."))?;
        // Clear terminal before stopping, to avoid writing on top of existing output.
        self.terminal
            .as_mut()
            .unwrap()
            .clear()
            .map_err(|err| error!("TUI: could not clear terminal: {}.", err))?;
        self.terminal = None;

        Ok(())
    }

    pub fn render(&mut self) -> Result<(), RosaError> {
        let terminal = self.terminal.as_mut().ok_or(error!(
            "TUI: could not render TUI, because it's not running."
        ))?;

        self.stats.update(&self.monitor_dir)?;

        terminal
            .draw(|frame| Self::ui(&self.stats, frame))
            .map_err(|err| error!("TUI: could not render: {}.", err))?;

        Ok(())
    }

    fn ui(stats: &RosaTuiStats, frame: &mut Frame) {
        // Check that the TUI fits first, and emit a warning if it doesn't.
        if frame.size().width < Self::MIN_WIDTH || frame.size().height < Self::MIN_HEIGHT {
            frame.render_widget(
                Paragraph::new(format!(
                    "The terminal is too small to render the TUI; please resize to at least \
                        {}x{} or run with `--no-tui`.",
                    Self::MIN_WIDTH,
                    Self::MIN_HEIGHT
                ))
                .bold()
                .wrap(Wrap { trim: true }),
                frame.size(),
            );

            return;
        }

        // Create the area occupied by the TUI.
        let main_area = Rect::new(
            (frame.size().width / 2) - (Self::MIN_WIDTH / 2),
            (frame.size().height / 2) - (Self::MIN_HEIGHT / 2),
            Self::MIN_WIDTH,
            Self::MIN_HEIGHT,
        );
        // We'll split the main area in 2, one for the title and the rest for the stats.
        let main_layout = Layout::new(
            Direction::Vertical,
            [Constraint::Length(1), Constraint::Min(0)],
        )
        .split(main_area);

        // The header/title is the name of the tool and the current phase.
        let header = Layout::new(
            Direction::Horizontal,
            [Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)],
        )
        .split(main_layout[0]);
        let title = Paragraph::new(vec![Line::from(vec![" rosa backdoor detector".into()])])
            .style(Style::reset().fg(Color::Rgb(255, 135, 135)).bold());
        let phase = Paragraph::new(vec![Line::from(vec![format!(
            "[{}]",
            stats.phase.to_string().replace('-', " ")
        )
        .into()])])
        .alignment(Alignment::Right)
        .style(Style::reset().fg(Color::Rgb(167, 171, 221)).bold());

        // The rest of it gets split into 3 rows:
        // - First row: time stats & results
        // - Second row: oracle & clustering info
        // - Third row: configuration info
        let stats_rows = Layout::new(
            Direction::Vertical,
            [
                Constraint::Length(5),
                Constraint::Length(8),
                Constraint::Min(5),
            ],
        )
        .split(main_layout[1]);
        let first_row = Layout::new(
            Direction::Horizontal,
            [Constraint::Min(0), Constraint::Min(0)],
        )
        .split(stats_rows[0]);
        let second_row = Layout::new(
            Direction::Horizontal,
            [Constraint::Min(0), Constraint::Min(0)],
        )
        .split(stats_rows[1]);

        // Give everything a uniform style, for labels and for block titles.
        let block_title_style = Style::reset().bold().italic().fg(Color::Rgb(229, 220, 137));
        let label_style = Style::reset().bold().dim();
        let warning_style = Style::reset().bold().fg(Color::Rgb(255, 111, 0));

        // Create the different blocks.
        let time_stats_block = Block::bordered()
            .dim()
            .title(Span::styled(" time stats ", block_title_style));
        let results_block = Block::bordered()
            .dim()
            .title(Span::styled(" results ", block_title_style));
        let oracle_block = Block::bordered()
            .dim()
            .title(Span::styled(" oracle ", block_title_style));
        let clustering_block = Block::bordered()
            .dim()
            .title(Span::styled(" clustering ", block_title_style));
        let config_block = Block::bordered()
            .dim()
            .title(Span::styled(" configuration ", block_title_style));

        // Create the time stats.
        let time_stats = Paragraph::new(vec![
            Line::from(vec![
                Span::styled("       run time: ", label_style),
                stats.run_time().into(),
            ]),
            Line::from(vec![
                Span::styled(" last new trace: ", label_style),
                stats.time_since_last_new_trace().into(),
            ]),
            Line::from(vec![
                Span::styled("  last backdoor: ", label_style),
                stats.time_since_last_backdoor().into(),
            ]),
        ])
        .style(Style::reset())
        .block(time_stats_block);

        // Create a special style for when backdoors are hit.
        let backdoors_line_style = match stats.total_backdoors {
            0 => Style::new(),
            _ => Style::reset().bold().red(),
        };
        // Create the results.
        let results = Paragraph::new(vec![
            Line::from(vec![
                Span::styled("    backdoors: ", label_style.patch(backdoors_line_style)),
                Span::styled(stats.unique_backdoors.to_string(), backdoors_line_style),
                Span::styled(" (", backdoors_line_style),
                Span::styled(stats.total_backdoors.to_string(), backdoors_line_style),
                Span::styled(" total)", backdoors_line_style),
            ]),
            Line::from(vec![
                Span::styled(" total traces: ", label_style),
                stats.total_traces.to_string().into(),
            ]),
            Line::from(vec![
                Span::styled("     coverage: ", label_style),
                format!("{:.2}%", stats.edge_coverage * 100.0).into(),
                " / ".to_string().into(),
                format!("{:.2}%", stats.syscall_coverage * 100.0).into(),
            ]),
        ])
        .style(Style::reset())
        .block(results_block);

        // Create the oracle info.
        let oracle = Paragraph::new(vec![
            Line::from(vec![
                Span::styled(" now processing: ", label_style),
                format!("{} traces", stats.new_traces).into(),
            ]),
            Line::from(vec![
                Span::styled("         oracle: ", label_style),
                stats.oracle.name().into(),
            ]),
            Line::from(vec![
                Span::styled("      criterion: ", label_style),
                stats.oracle_criterion.to_string().into(),
            ]),
        ])
        .style(Style::reset())
        .block(oracle_block);

        // Create the clustering info.
        let clustering = Paragraph::new(vec![
            Line::from(vec![
                Span::styled("            clusters: ", label_style),
                stats
                    .clusters
                    .map(|clusters| clusters.to_string())
                    .unwrap_or("-".to_string())
                    .into(),
            ]),
            Line::from(vec![
                Span::styled("         seed traces: ", label_style),
                stats
                    .seed_traces
                    .map(|seed_traces| seed_traces.to_string())
                    .unwrap_or("-".to_string())
                    .into(),
            ]),
            Line::from(vec![
                Span::styled(" formation criterion: ", label_style),
                stats.formation_criterion.to_string().into(),
            ]),
            Line::from(vec![
                Span::styled(" selection criterion: ", label_style),
                stats.selection_criterion.to_string().into(),
            ]),
            Line::from(vec![
                Span::styled("      edge tolerance: ", label_style),
                stats.edge_tolerance.to_string().into(),
            ]),
            Line::from(vec![
                Span::styled("   syscall tolerance: ", label_style),
                stats.syscall_tolerance.to_string().into(),
            ]),
        ])
        .style(Style::reset())
        .block(clustering_block);

        // Truncate the configuration options if needed, to make sure they fit on the TUI.
        let mut config_file = stats.config_file_path.clone();
        let mut output_dir = stats.output_dir_path.clone();
        let fuzzers = format!("{}/{}", stats.alive_fuzzers, stats.total_fuzzers);
        let fuzzers_style = if stats.alive_fuzzers < stats.total_fuzzers {
            warning_style
        } else {
            Style::reset()
        };
        // -3 for the borders and left padding.
        let max_text_width = (frame.size().width - 14) as usize;
        if config_file.len() > max_text_width {
            config_file.truncate(max_text_width - 3);
            config_file += "...";
        }
        if output_dir.len() > max_text_width {
            output_dir.truncate(max_text_width - 3);
            output_dir += "...";
        }

        // Create the configuration info.
        let mut config_lines = vec![
            Line::from(vec![
                Span::styled("          config: ", label_style),
                config_file.into(),
            ]),
            Line::from(vec![
                Span::styled("          output: ", label_style),
                output_dir.into(),
            ]),
            Line::from(vec![
                Span::styled(" fuzzers running: ", label_style),
                Span::styled(fuzzers, fuzzers_style),
            ]),
            Line::from(vec![]),
        ];

        // If there's a crash warning, add it to the configuration info.
        if stats.crash_warning {
            config_lines.push(
                Line::from(vec![
                    " WARNING: a fuzzer has detected crashes. This is probably hindering \
                    backdoor detection!"
                        .into(),
                ])
                .style(warning_style),
            )
        }

        // Wrap up everything in the configuration block.
        let config = Paragraph::new(config_lines)
            .style(Style::reset())
            .block(config_block);

        // Render the header and all the blocks.
        frame.render_widget(title, header[0]);
        frame.render_widget(phase, header[1]);
        frame.render_widget(time_stats, first_row[0]);
        frame.render_widget(results, first_row[1]);
        frame.render_widget(oracle, second_row[0]);
        frame.render_widget(clustering, second_row[1]);
        frame.render_widget(config, stats_rows[2]);
    }
}
