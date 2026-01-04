use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Terminal,
};
use std::io;
use tokio::sync::mpsc;
use chrono::{DateTime, Utc};

use crate::error::Result;
use crate::state::MessageEntry;

/// Terminal UI manager
pub struct TerminalUI {
    input: String,
    messages: Vec<DisplayMessage>,
    status: String,
    scroll_offset: usize,
}

/// Display message for UI
#[derive(Debug, Clone)]
pub struct DisplayMessage {
    pub peer_id: String,
    pub content: String,
    pub timestamp: DateTime<Utc>,
    pub is_sent: bool,
}

/// UI events
#[derive(Debug, Clone)]
pub enum UIEvent {
    /// User wants to send a message
    SendMessage(String),

    /// User wants to quit
    Quit,

    /// User wants to add a peer
    AddPeer(String),

    /// User wants to scroll up
    ScrollUp,

    /// User wants to scroll down
    ScrollDown,
}

impl TerminalUI {
    /// Create new terminal UI
    pub fn new() -> Self {
        Self {
            input: String::new(),
            messages: Vec::new(),
            status: "Ready".to_string(),
            scroll_offset: 0,
        }
    }

    /// Add message to display
    pub fn add_message(&mut self, message: DisplayMessage) {
        self.messages.push(message);
        // Auto-scroll to bottom when new message arrives
        self.scroll_offset = 0;
    }

    /// Update status
    pub fn set_status(&mut self, status: String) {
        self.status = status;
    }

    /// Run the terminal UI
    pub async fn run(
        mut self,
        mut event_rx: mpsc::UnboundedReceiver<DisplayMessage>,
    ) -> Result<mpsc::UnboundedReceiver<UIEvent>> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Create UI event channel
        let (ui_event_tx, ui_event_rx) = mpsc::unbounded_channel();

        // Main UI loop
        tokio::spawn(async move {
            loop {
                // Check for incoming messages
                while let Ok(message) = event_rx.try_recv() {
                    self.add_message(message);
                }

                // Draw UI
                if let Err(e) = terminal.draw(|f| {
                    self.render(f);
                }) {
                    eprintln!("Failed to draw UI: {}", e);
                    break;
                }

                // Handle input
                if event::poll(std::time::Duration::from_millis(100)).unwrap_or(false) {
                    if let Ok(Event::Key(key)) = event::read() {
                        match self.handle_key_event(key.code, key.modifiers) {
                            Some(UIEvent::Quit) => {
                                let _ = ui_event_tx.send(UIEvent::Quit);
                                break;
                            }
                            Some(event) => {
                                let _ = ui_event_tx.send(event);
                            }
                            None => {}
                        }
                    }
                }
            }

            // Cleanup terminal
            let _ = disable_raw_mode();
            let _ = execute!(
                terminal.backend_mut(),
                LeaveAlternateScreen,
                DisableMouseCapture
            );
            let _ = terminal.show_cursor();
        });

        Ok(ui_event_rx)
    }

    /// Render the UI
    fn render(&mut self, f: &mut ratatui::Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(3),     // Messages area
                Constraint::Length(3),  // Input area
                Constraint::Length(3),  // Status bar
            ])
            .split(f.area());

        self.render_messages(f, chunks[0]);
        self.render_input(f, chunks[1]);
        self.render_status(f, chunks[2]);
    }

    /// Render messages area
    fn render_messages(&self, f: &mut ratatui::Frame, area: Rect) {
        let messages: Vec<ListItem> = self
            .messages
            .iter()
            .rev()
            .skip(self.scroll_offset)
            .take(area.height as usize - 2) // Account for border
            .rev()
            .map(|msg| {
                let time_str = msg.timestamp.format("%H:%M:%S").to_string();
                let prefix = if msg.is_sent { "→" } else { "←" };
                let color = if msg.is_sent { Color::Green } else { Color::Cyan };

                let content = format!(
                    "[{}] {} {}: {}",
                    time_str,
                    prefix,
                    &msg.peer_id[..8.min(msg.peer_id.len())],
                    msg.content
                );

                ListItem::new(Line::from(Span::styled(content, Style::default().fg(color))))
            })
            .collect();

        let messages_widget = List::new(messages).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Messages ")
                .style(Style::default().fg(Color::White)),
        );

        f.render_widget(messages_widget, area);
    }

    /// Render input area
    fn render_input(&self, f: &mut ratatui::Frame, area: Rect) {
        let input_widget = Paragraph::new(self.input.as_str())
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Input (Enter: Send | Ctrl+C: Quit | Ctrl+A: Add Peer) ")
                    .style(Style::default().fg(Color::Yellow)),
            )
            .wrap(Wrap { trim: false });

        f.render_widget(input_widget, area);
    }

    /// Render status bar
    fn render_status(&self, f: &mut ratatui::Frame, area: Rect) {
        let status_widget = Paragraph::new(self.status.as_str())
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Status ")
                    .style(Style::default().fg(Color::Magenta)),
            );

        f.render_widget(status_widget, area);
    }

    /// Handle keyboard events
    fn handle_key_event(&mut self, code: KeyCode, modifiers: KeyModifiers) -> Option<UIEvent> {
        match (code, modifiers) {
            // Quit
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                return Some(UIEvent::Quit);
            }

            // Send message
            (KeyCode::Enter, _) => {
                if !self.input.is_empty() {
                    let message = self.input.clone();
                    self.input.clear();
                    return Some(UIEvent::SendMessage(message));
                }
            }

            // Add peer
            (KeyCode::Char('a'), KeyModifiers::CONTROL) => {
                if !self.input.is_empty() {
                    let peer_info = self.input.clone();
                    self.input.clear();
                    return Some(UIEvent::AddPeer(peer_info));
                }
            }

            // Scroll up
            (KeyCode::PageUp, _) => {
                self.scroll_offset = self.scroll_offset.saturating_add(5).min(self.messages.len());
                return Some(UIEvent::ScrollUp);
            }

            // Scroll down
            (KeyCode::PageDown, _) => {
                self.scroll_offset = self.scroll_offset.saturating_sub(5);
                return Some(UIEvent::ScrollDown);
            }

            // Backspace
            (KeyCode::Backspace, _) => {
                self.input.pop();
            }

            // Character input
            (KeyCode::Char(c), _) => {
                self.input.push(c);
            }

            _ => {}
        }

        None
    }
}

impl From<MessageEntry> for DisplayMessage {
    fn from(entry: MessageEntry) -> Self {
        DisplayMessage {
            peer_id: entry.peer_id.as_str().to_string(),
            content: entry.content,
            timestamp: entry.timestamp,
            is_sent: matches!(entry.direction, crate::state::MessageDirection::Sent),
        }
    }
}
