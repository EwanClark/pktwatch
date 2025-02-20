use clap::{App, Arg};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use pcap::{Capture, Device};
use ratatui::{
    prelude::*,
    style::{Color, Modifier, Style},
    widgets::*,
};
use std::{
    io::{self, Write},
    time::{Duration, Instant},
};

struct AppState {
    packets: Vec<String>,
    start_time: Instant,
    total_packets: usize,
    packets_per_second: f64,
    last_update: Instant,
    devices: Vec<Device>,
    selected_device: Option<usize>,
    selection_made: bool,
}

impl AppState {
    fn new() -> Self {
        let devices = Device::list().unwrap_or_else(|e| {
            eprintln!("Error listing devices: {}", e);
            std::process::exit(1);
        });

        Self {
            packets: Vec::new(),
            start_time: Instant::now(),
            total_packets: 0,
            packets_per_second: 0.0,
            last_update: Instant::now(),
            devices,
            selected_device: Some(0),
            selection_made: false,
        }
    }

    fn update_stats(&mut self) {
        self.total_packets += 1;
        let elapsed = self.last_update.elapsed().as_secs_f64();
        if elapsed >= 1.0 {
            self.packets_per_second =
                self.total_packets as f64 / self.start_time.elapsed().as_secs_f64();
            self.last_update = Instant::now();
        }
    }

    fn select_next_device(&mut self) {
        if let Some(current) = self.selected_device {
            self.selected_device = Some((current + 1) % self.devices.len());
        }
    }

    fn select_previous_device(&mut self) {
        if let Some(current) = self.selected_device {
            self.selected_device = Some((current + self.devices.len() - 1) % self.devices.len());
        }
    }

    fn confirm_selection(&mut self) {
        self.selection_made = true;
    }

    fn get_selected_device(&self) -> Option<Device> {
        self.selected_device.map(|idx| self.devices[idx].clone())
    }
}

fn setup_capture(device: Device, promisc: bool) -> Result<Capture<pcap::Active>, String> {
    println!("Promiscuous mode: {}", promisc);

    Capture::from_device(device)
        .map_err(|e| format!("Failed to open device: {}", e))?
        .promisc(promisc)
        .immediate_mode(true)
        .snaplen(65535)
        .open()
        .map_err(|e| format!("Failed to start capture on device: {}", e))
}

fn parse_arguments() -> (bool, bool) {
    let matches = App::new("Packet Capture")
        .version("1.0")
        .author("Ewan Clark <ewancclark@outlook.com>")
        .about("Capture packets from network devices")
        .arg(
            Arg::with_name("promisc")
                .short("p")
                .long("promisc")
                .help("Captures all packets on the network")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("version")
                .short("v")
                .long("version")
                .help("Show version information")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("gui")
                .short("g")
                .long("gui")
                .help("Shows a graphical interface in the terminal")
                .takes_value(false),
        )
        .get_matches();

    (matches.is_present("promisc"), matches.is_present("gui"))
}

fn draw_device_selection(frame: &mut Frame, app_state: &AppState) {
    let area = centered_rect(60, 60, frame.area());

    let devices: Vec<ListItem> = app_state
        .devices
        .iter()
        .enumerate()
        .map(|(i, device)| {
            let style = if Some(i) == app_state.selected_device {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            ListItem::new(format!("{}: {}", i + 1, device.name)).style(style)
        })
        .collect();

    let devices_list = List::new(devices)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" Select Network Interface ")
                .title_alignment(Alignment::Center),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

    let instructions = Paragraph::new("↑↓: Navigate | Enter: Select | q: Quit")
        .style(Style::default().fg(Color::Yellow))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::TOP));

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(3)])
        .split(area);

    frame.render_widget(Clear, area);
    frame.render_widget(devices_list, layout[0]);
    frame.render_widget(instructions, layout[1]);
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

fn setup_tui() -> io::Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend)
}

fn update_tui(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app_state: &AppState,
) -> io::Result<()> {
    terminal.draw(|frame| {
        if !app_state.selection_made {
            draw_device_selection(frame, app_state);
            return;
        }

        let size = frame.area();

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(1),
                Constraint::Length(3),
                Constraint::Length(1),
            ])
            .split(size);

        let header = Paragraph::new("Packet Sniffer")
            .style(Style::default().fg(Color::Cyan))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan))
                    .title(" Network Monitor ")
                    .title_alignment(Alignment::Center),
            );
        frame.render_widget(header, chunks[0]);

        let packets = app_state.packets.iter().cloned().collect::<Vec<_>>();
        let packets_list = Paragraph::new(packets.join("\n"))
            .style(Style::default().fg(Color::White))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Blue))
                    .title(" Captured Packets ")
                    .title_alignment(Alignment::Left),
            );
        frame.render_widget(packets_list, chunks[1]);

        let stats = format!(
            "Total Packets: {} | Packets/sec: {:.2} | Running Time: {:?}",
            app_state.total_packets,
            app_state.packets_per_second,
            app_state.start_time.elapsed().as_secs()
        );
        let stats_widget = Paragraph::new(stats)
            .style(Style::default().fg(Color::Green))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Green))
                    .title(" Statistics ")
                    .title_alignment(Alignment::Left),
            );
        frame.render_widget(stats_widget, chunks[2]);

        let footer = Paragraph::new("Press 'q' or Ctrl+C to quit")
            .style(Style::default().fg(Color::Yellow))
            .alignment(Alignment::Center);
        frame.render_widget(footer, chunks[3]);
    })?;

    Ok(())
}

fn cleanup_tui(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

fn select_device() -> Device {
    let devices = Device::list().unwrap_or_else(|e| {
        eprintln!("Error listing devices: {}", e);
        std::process::exit(1);
    });

    println!("Available devices:");
    for (i, device) in devices.iter().enumerate() {
        println!("{}. {}", i + 1, device.name);
    }

    let mut input = String::new();
    print!("Select a device to capture: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut input).unwrap();

    let input: usize = input.trim().parse().unwrap_or_else(|_| {
        println!("Invalid input! Please enter a valid number.");
        std::process::exit(1);
    });

    devices.get(input - 1).cloned().unwrap_or_else(|| {
        eprintln!("Invalid device selection!");
        std::process::exit(1);
    })
}

fn main() -> io::Result<()> {
    let args = parse_arguments();
    let promisc = args.0;
    let enablegui = args.1;

    let mut app_state = AppState::new();

    if !enablegui {
        let device = select_device();
        match setup_capture(device, promisc) {
            Ok(mut capture) => {
                println!("Sniffing on device... Press Ctrl+C to stop.");
                while let Ok(packet) = capture.next_packet() {
                    println!("Captured {} bytes", packet.header.len);
                }
            }
            Err(e) => eprintln!("Error: {}", e),
        }
        return Ok(());
    }

    let mut terminal = setup_tui()?;

    'outer: loop {
        update_tui(&mut terminal, &app_state)?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Up if !app_state.selection_made => app_state.select_previous_device(),
                    KeyCode::Down if !app_state.selection_made => app_state.select_next_device(),
                    KeyCode::Enter if !app_state.selection_made => {
                        app_state.confirm_selection();

                        if let Some(device) = app_state.get_selected_device() {
                            match setup_capture(device, promisc) {
                                Ok(capture) => {
                                    let mut capture = capture.setnonblock().unwrap();

                                    app_state.start_time = Instant::now();

                                    'capture: loop {
                                        if event::poll(Duration::from_millis(1))? {
                                            if let Event::Key(key) = event::read()? {
                                                match key.code {
                                                    KeyCode::Char('q') => break 'outer,
                                                    KeyCode::Char('c')
                                                        if key
                                                            .modifiers
                                                            .contains(KeyModifiers::CONTROL) =>
                                                    {
                                                        break 'outer
                                                    }
                                                    _ => {}
                                                }
                                            }
                                        }

                                        match capture.next_packet() {
                                            Ok(packet) => {
                                                let packet_info = format!(
                                                    "[{}] Captured {} bytes",
                                                    app_state.total_packets + 1,
                                                    packet.header.len
                                                );
                                                app_state.packets.insert(0, packet_info);
                                                app_state.update_stats();

                                                if app_state.packets.len() > 100 {
                                                    app_state.packets.pop();
                                                }

                                                update_tui(&mut terminal, &app_state)?;
                                            }
                                            Err(pcap::Error::TimeoutExpired) => {
                                                update_tui(&mut terminal, &app_state)?;
                                            }
                                            Err(e) => {
                                                eprintln!("Error capturing packet: {}", e);
                                                break 'capture;
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Error: {}", e);
                                    break;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    cleanup_tui(&mut terminal)?;
    Ok(())
}
