use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Tabs},
    Frame, Terminal,
};
use serde::Deserialize;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Connection info from daemon
#[derive(Debug, Clone, Deserialize)]
struct ConnectionInfo {
    subdomain: String,
    reverse_port: u16,
    local_port: u16,
    connected_at: String,
}

/// Client info from clients.d
#[derive(Debug, Clone)]
struct ClientInfo {
    key_id: String,
    name: Option<String>,
    filename: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Tab {
    Dashboard,
    Clients,
    Help,
}

impl Tab {
    fn titles() -> Vec<&'static str> {
        vec!["Dashboard", "Clients", "Help"]
    }

    fn index(self) -> usize {
        match self {
            Tab::Dashboard => 0,
            Tab::Clients => 1,
            Tab::Help => 2,
        }
    }

    fn from_index(i: usize) -> Self {
        match i {
            0 => Tab::Dashboard,
            1 => Tab::Clients,
            _ => Tab::Help,
        }
    }
}

struct App {
    socket_path: std::path::PathBuf,
    clients_dir: std::path::PathBuf,
    current_tab: Tab,
    connections: Vec<ConnectionInfo>,
    clients: Vec<ClientInfo>,
    connection_state: TableState,
    client_state: TableState,
    status_text: String,
    last_error: Option<String>,
    should_quit: bool,
}

impl App {
    fn new(socket_path: &Path, clients_dir: &Path) -> Self {
        let mut app = Self {
            socket_path: socket_path.to_path_buf(),
            clients_dir: clients_dir.to_path_buf(),
            current_tab: Tab::Dashboard,
            connections: Vec::new(),
            clients: Vec::new(),
            connection_state: TableState::default(),
            client_state: TableState::default(),
            status_text: String::new(),
            last_error: None,
            should_quit: false,
        };
        app.refresh();
        app
    }

    fn refresh(&mut self) {
        self.refresh_connections();
        self.refresh_clients();
        self.last_error = None;
    }

    fn refresh_connections(&mut self) {
        match Self::fetch_connections(&self.socket_path) {
            Ok((status, conns)) => {
                self.status_text = status;
                self.connections = conns;
            }
            Err(e) => {
                self.last_error = Some(format!("Failed to fetch connections: {}", e));
                self.connections = Vec::new();
                self.status_text = "Daemon not running".to_string();
            }
        }
    }

    fn refresh_clients(&mut self) {
        match Self::load_clients(&self.clients_dir) {
            Ok(clients) => self.clients = clients,
            Err(e) => {
                self.last_error = Some(format!("Failed to load clients: {}", e));
                self.clients = Vec::new();
            }
        }
    }

    fn fetch_connections(socket_path: &Path) -> io::Result<(String, Vec<ConnectionInfo>)> {
        // First get status
        let status = Self::socket_request(socket_path, b"status\n")?;

        // Then get connections as JSON
        let conns_json = Self::socket_request(socket_path, b"connections\n")?;
        let connections: Vec<ConnectionInfo> = if conns_json.contains("No active connections") {
            Vec::new()
        } else {
            serde_json::from_str(&conns_json).unwrap_or_default()
        };

        Ok((status, connections))
    }

    fn socket_request(socket_path: &Path, cmd: &[u8]) -> io::Result<String> {
        let mut stream = UnixStream::connect(socket_path)?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.write_all(cmd)?;
        let mut buf = String::new();
        stream.read_to_string(&mut buf)?;
        Ok(buf)
    }

    fn load_clients(clients_dir: &Path) -> io::Result<Vec<ClientInfo>> {
        let mut clients = Vec::new();

        if let Ok(entries) = fs::read_dir(clients_dir) {
            for entry in entries.flatten() {
                if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    if let Ok(text) = fs::read_to_string(entry.path()) {
                        let mut key_id = None;
                        let mut name = None;

                        for line in text.lines() {
                            let l = line.trim();
                            if l.starts_with("# name:") {
                                name = Some(l.strip_prefix("# name:").unwrap().trim().to_string());
                            } else if l.starts_with("ssh-ed25519") {
                                if let Ok(id) = Self::compute_fingerprint(l) {
                                    key_id = Some(id);
                                }
                            }
                        }

                        if let Some(id) = key_id {
                            clients.push(ClientInfo {
                                key_id: id,
                                name,
                                filename: entry.file_name().to_string_lossy().to_string(),
                            });
                        }
                    }
                }
            }
        }

        Ok(clients)
    }

    fn compute_fingerprint(line: &str) -> Result<String, String> {
        use base64::Engine;
        use sha2::{Digest, Sha256};

        let mut parts = line.split_whitespace();
        let kind = parts.next().ok_or("missing kind")?;
        if kind != "ssh-ed25519" {
            return Err("only ssh-ed25519 supported".into());
        }
        let b64 = parts.next().ok_or("missing key")?;
        let blob = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| format!("b64: {}", e))?;
        let fp = base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(&blob));
        Ok(format!("SHA256:{}", fp))
    }

    fn next_tab(&mut self) {
        let i = (self.current_tab.index() + 1) % 3;
        self.current_tab = Tab::from_index(i);
    }

    fn prev_tab(&mut self) {
        let i = if self.current_tab.index() == 0 {
            2
        } else {
            self.current_tab.index() - 1
        };
        self.current_tab = Tab::from_index(i);
    }

    fn next_row(&mut self) {
        match self.current_tab {
            Tab::Dashboard => {
                if self.connections.is_empty() {
                    return;
                }
                let i = match self.connection_state.selected() {
                    Some(i) => (i + 1) % self.connections.len(),
                    None => 0,
                };
                self.connection_state.select(Some(i));
            }
            Tab::Clients => {
                if self.clients.is_empty() {
                    return;
                }
                let i = match self.client_state.selected() {
                    Some(i) => (i + 1) % self.clients.len(),
                    None => 0,
                };
                self.client_state.select(Some(i));
            }
            Tab::Help => {}
        }
    }

    fn prev_row(&mut self) {
        match self.current_tab {
            Tab::Dashboard => {
                if self.connections.is_empty() {
                    return;
                }
                let i = match self.connection_state.selected() {
                    Some(i) => {
                        if i == 0 {
                            self.connections.len() - 1
                        } else {
                            i - 1
                        }
                    }
                    None => 0,
                };
                self.connection_state.select(Some(i));
            }
            Tab::Clients => {
                if self.clients.is_empty() {
                    return;
                }
                let i = match self.client_state.selected() {
                    Some(i) => {
                        if i == 0 {
                            self.clients.len() - 1
                        } else {
                            i - 1
                        }
                    }
                    None => 0,
                };
                self.client_state.select(Some(i));
            }
            Tab::Help => {}
        }
    }
}

pub fn run(socket_path: &Path, clients_dir: &Path) -> io::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state
    let mut app = App::new(socket_path, clients_dir);

    // Main loop
    let result = run_app(&mut terminal, &mut app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> io::Result<()> {
    loop {
        terminal.draw(|f| ui(f, app))?;

        // Poll for events with timeout for auto-refresh
        if event::poll(Duration::from_secs(5))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
                        KeyCode::Tab | KeyCode::Right => app.next_tab(),
                        KeyCode::BackTab | KeyCode::Left => app.prev_tab(),
                        KeyCode::Down | KeyCode::Char('j') => app.next_row(),
                        KeyCode::Up | KeyCode::Char('k') => app.prev_row(),
                        KeyCode::Char('r') => app.refresh(),
                        KeyCode::Char('1') => app.current_tab = Tab::Dashboard,
                        KeyCode::Char('2') => app.current_tab = Tab::Clients,
                        KeyCode::Char('3' | '?') => app.current_tab = Tab::Help,
                        _ => {}
                    }
                }
            }
        } else {
            // Auto-refresh on timeout
            app.refresh();
        }

        if app.should_quit {
            return Ok(());
        }
    }
}

fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Tabs
            Constraint::Min(0),    // Content
            Constraint::Length(3), // Status bar
        ])
        .split(f.area());

    // Tabs
    let titles: Vec<Line> = Tab::titles()
        .iter()
        .map(|t| Line::from(Span::styled(*t, Style::default().fg(Color::White))))
        .collect();
    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" kickflip ")
                .title_style(Style::default().fg(Color::Cyan).bold()),
        )
        .select(app.current_tab.index())
        .style(Style::default().fg(Color::DarkGray))
        .highlight_style(Style::default().fg(Color::Yellow).bold());
    f.render_widget(tabs, chunks[0]);

    // Content based on tab
    match app.current_tab {
        Tab::Dashboard => render_dashboard(f, app, chunks[1]),
        Tab::Clients => render_clients(f, app, chunks[1]),
        Tab::Help => render_help(f, chunks[1]),
    }

    // Status bar
    let status_style = if app.last_error.is_some() {
        Style::default().fg(Color::Red)
    } else {
        Style::default().fg(Color::Green)
    };
    let default_status = format!(
        "Connections: {} | Clients: {} | Press 'r' to refresh, 'q' to quit",
        app.connections.len(),
        app.clients.len()
    );
    let status_text = app.last_error.as_ref().unwrap_or(&default_status);
    let status = Paragraph::new(status_text.as_str())
        .style(status_style)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(status, chunks[2]);
}

fn render_dashboard(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Min(0)])
        .split(area);

    // Status panel
    let status_lines: Vec<Line> = app
        .status_text
        .lines()
        .take(4)
        .map(|l| Line::from(l.to_string()))
        .collect();
    let status_para = Paragraph::new(status_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Server Status ")
            .title_style(Style::default().fg(Color::Cyan)),
    );
    f.render_widget(status_para, chunks[0]);

    // Connections table
    let header_cells = ["Subdomain", "Port", "Local Port", "Connected At"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).bold()));
    let header = Row::new(header_cells).height(1);

    let rows: Vec<Row> = app
        .connections
        .iter()
        .map(|c| {
            Row::new([
                Cell::from(c.subdomain.clone()),
                Cell::from(c.reverse_port.to_string()),
                Cell::from(c.local_port.to_string()),
                Cell::from(format_time(&c.connected_at)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(30),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
            Constraint::Percentage(40),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Active Connections ")
            .title_style(Style::default().fg(Color::Cyan)),
    )
    .row_highlight_style(Style::default().bg(Color::DarkGray))
    .highlight_symbol("▶ ");

    f.render_stateful_widget(table, chunks[1], &mut app.connection_state.clone());

    // Show empty state
    if app.connections.is_empty() {
        let empty = Paragraph::new("No active connections")
            .style(Style::default().fg(Color::DarkGray))
            .centered();
        let inner = centered_rect(50, 20, chunks[1]);
        f.render_widget(empty, inner);
    }
}

fn render_clients(f: &mut Frame, app: &App, area: Rect) {
    let header_cells = ["Name", "Key ID", "File"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).bold()));
    let header = Row::new(header_cells).height(1);

    let rows: Vec<Row> = app
        .clients
        .iter()
        .map(|c| {
            Row::new([
                Cell::from(c.name.clone().unwrap_or_else(|| "-".to_string())),
                Cell::from(truncate_key_id(&c.key_id)),
                Cell::from(c.filename.clone()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(25),
            Constraint::Percentage(45),
            Constraint::Percentage(30),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Registered Clients ")
            .title_style(Style::default().fg(Color::Cyan)),
    )
    .row_highlight_style(Style::default().bg(Color::DarkGray))
    .highlight_symbol("▶ ");

    f.render_stateful_widget(table, area, &mut app.client_state.clone());

    // Show empty state
    if app.clients.is_empty() {
        let empty = Paragraph::new(
            "No clients registered\n\nUse: kickflip-server add-client --pubkey \"...\"",
        )
        .style(Style::default().fg(Color::DarkGray))
        .centered();
        let inner = centered_rect(60, 20, area);
        f.render_widget(Clear, inner);
        f.render_widget(empty, inner);
    }
}

fn render_help(f: &mut Frame, area: Rect) {
    let help_text = vec![
        Line::from(vec![Span::styled(
            "Keyboard Shortcuts",
            Style::default().bold().fg(Color::Cyan),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Tab / → / ←  ", Style::default().fg(Color::Yellow)),
            Span::raw("Switch between tabs"),
        ]),
        Line::from(vec![
            Span::styled("1 / 2 / 3    ", Style::default().fg(Color::Yellow)),
            Span::raw("Jump to Dashboard / Clients / Help"),
        ]),
        Line::from(vec![
            Span::styled("↑ / ↓ / j / k", Style::default().fg(Color::Yellow)),
            Span::raw("Navigate rows"),
        ]),
        Line::from(vec![
            Span::styled("r            ", Style::default().fg(Color::Yellow)),
            Span::raw("Refresh data"),
        ]),
        Line::from(vec![
            Span::styled("q / Esc      ", Style::default().fg(Color::Yellow)),
            Span::raw("Quit"),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Auto-refresh",
            Style::default().bold().fg(Color::Cyan),
        )]),
        Line::from("Data refreshes automatically every 5 seconds."),
        Line::from(""),
        Line::from(vec![Span::styled(
            "CLI Commands",
            Style::default().bold().fg(Color::Cyan),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "kickflip-server add-client --pubkey \"...\"",
            Style::default().fg(Color::Green),
        )]),
        Line::from("  Add a new client"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "kickflip-server remove-client --key-id \"SHA256:...\"",
            Style::default().fg(Color::Green),
        )]),
        Line::from("  Remove a client"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "kickflip-server status",
            Style::default().fg(Color::Green),
        )]),
        Line::from("  Show daemon status"),
    ];

    let help = Paragraph::new(help_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Help ")
            .title_style(Style::default().fg(Color::Cyan)),
    );
    f.render_widget(help, area);
}

fn format_time(rfc3339: &str) -> String {
    // Parse and format nicely, or return as-is on failure
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|_| rfc3339.to_string())
}

fn truncate_key_id(key_id: &str) -> String {
    if key_id.len() > 30 {
        format!("{}...", &key_id[..30])
    } else {
        key_id.to_string()
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
