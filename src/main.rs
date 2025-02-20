use clap::{App, Arg};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use pcap::{Capture, Device};
use pnet::packet::{
    ethernet::EthernetPacket, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, ipv6::Ipv6Packet, tcp::TcpPacket, udp::UdpPacket, Packet
};
use ratatui::{
    prelude::*,
    style::{Color, Modifier, Style},
    widgets::*,
};
use std::{
    fs,
    io::{self, Read, Write},
    path::Path,
    time::{Duration, Instant},
};

struct AppState {
    packets: Vec<String>,
    starttime: Instant,
    totalpackets: usize,
    packetspersecond: f64,
    lastupdate: Instant,
    devices: Vec<Device>,
    selecteddevice: Option<usize>,
    selectionmade: bool,
    iscapturing: bool,
}

impl AppState {
    fn new() -> Self {
        let devices = Device::list().unwrap_or_else(|e| {
            eprintln!("Error listing devices: {}", e);
            std::process::exit(1);
        });

        Self {
            packets: Vec::new(),
            starttime: Instant::now(),
            totalpackets: 0,
            packetspersecond: 0.0,
            lastupdate: Instant::now(),
            devices,
            selecteddevice: Some(0),
            selectionmade: false,
            iscapturing: false,
        }
    }

    fn updatestats(&mut self) {
        self.totalpackets += 1;
        let elapsed = self.lastupdate.elapsed().as_secs_f64();
        if elapsed >= 1.0 {
            self.packetspersecond =
                self.totalpackets as f64 / self.starttime.elapsed().as_secs_f64();
            self.lastupdate = Instant::now();
        }
    }

    fn selectnextdevice(&mut self) {
        if let Some(current) = self.selecteddevice {
            self.selecteddevice = Some((current + 1) % self.devices.len());
        }
    }

    fn selectpreviousdevice(&mut self) {
        if let Some(current) = self.selecteddevice {
            self.selecteddevice = Some((current + self.devices.len() - 1) % self.devices.len());
        }
    }

    fn confirmselection(&mut self) {
        self.selectionmade = true;
    }

    fn getselecteddevice(&self) -> Option<Device> {
        self.selecteddevice.map(|idx| self.devices[idx].clone())
    }
}

fn setupcapture(device: Device, promisc: bool) -> Result<Capture<pcap::Active>, String> {
    Capture::from_device(device)
        .map_err(|e| format!("Failed to open device: {}", e))?
        .promisc(promisc)
        .immediate_mode(true)
        .snaplen(65535)
        .open()
        .map_err(|e| format!("Failed to start capture on device: {}", e))
}

fn parsearguments() -> (bool, bool, String, bool) {
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
        .arg(
            Arg::with_name("export")
                .short("e")
                .long("export")
                .help("Export captured packets to a file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("clear")
                .short("c")
                .long("clear")
                .help("Clears the file before exporting")
                .takes_value(false),
        )
        .get_matches();

    (
        matches.is_present("promisc"),
        matches.is_present("gui"),
        matches.value_of("export").unwrap_or("").to_string(),
        matches.is_present("clear"),
    )
}

fn drawdeviceselection(frame: &mut Frame, appstate: &AppState) {
    let area = centeredrect(60, 60, frame.area());

    let devices: Vec<ListItem> = appstate
        .devices
        .iter()
        .enumerate()
        .map(|(i, device)| {
            let style = if Some(i) == appstate.selecteddevice {
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

    let deviceslist = List::new(devices)
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
    frame.render_widget(deviceslist, layout[0]);
    frame.render_widget(instructions, layout[1]);
}

fn centeredrect(percentx: u16, percenty: u16, r: Rect) -> Rect {
    let popuplayout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percenty) / 2),
            Constraint::Percentage(percenty),
            Constraint::Percentage((100 - percenty) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percentx) / 2),
            Constraint::Percentage(percentx),
            Constraint::Percentage((100 - percentx) / 2),
        ])
        .split(popuplayout[1])[1]
}

fn setuptui() -> io::Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend)
}

fn parsepacket(packetdata: &[u8], packetnumber: usize) -> String {
    if let Some(ethernet) = EthernetPacket::new(packetdata) {
        match ethernet.get_ethertype() {
            pnet::packet::ethernet::EtherTypes::Ipv4 => {
                if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                    match ipv4.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => {
                            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                return format!(
                                    "[{}] IPv4 TCP | SRC: {}:{} | DST: {}:{} | FLAGS: {:?} | LEN: {}",
                                    packetnumber,
                                    ipv4.get_source(),
                                    tcp.get_source(),
                                    ipv4.get_destination(),
                                    tcp.get_destination(),
                                    tcp.get_flags(),
                                    packetdata.len()
                                );
                            }
                        }
                        IpNextHeaderProtocols::Udp => {
                            if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                return format!(
                                    "[{}] IPv4 UDP | SRC: {}:{} | DST: {}:{} | LEN: {}",
                                    packetnumber,
                                    ipv4.get_source(),
                                    udp.get_source(),
                                    ipv4.get_destination(),
                                    udp.get_destination(),
                                    packetdata.len()
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
            pnet::packet::ethernet::EtherTypes::Ipv6 => {
                if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
                    match ipv6.get_next_header() {
                        IpNextHeaderProtocols::Tcp => {
                            if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                                return format!(
                                    "[{}] IPv6 TCP | SRC: {}:{} | DST: {}:{} | FLAGS: {:?} | LEN: {}",
                                    packetnumber,
                                    ipv6.get_source(),
                                    tcp.get_source(),
                                    ipv6.get_destination(),
                                    tcp.get_destination(),
                                    tcp.get_flags(),
                                    packetdata.len()
                                );
                            }
                        }
                        IpNextHeaderProtocols::Udp => {
                            if let Some(udp) = UdpPacket::new(ipv6.payload()) {
                                return format!(
                                    "[{}] IPv6 UDP | SRC: {}:{} | DST: {}:{} | LEN: {}",
                                    packetnumber,
                                    ipv6.get_source(),
                                    udp.get_source(),
                                    ipv6.get_destination(),
                                    udp.get_destination(),
                                    packetdata.len()
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    format!("[{}] Unknown Packet | LEN: {}", packetnumber, packetdata.len())
}

fn updatetui(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    appstate: &AppState,
) -> io::Result<()> {
    terminal.draw(|frame| {
        if !appstate.selectionmade {
            drawdeviceselection(frame, appstate);
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

        let packets = appstate.packets.iter().cloned().collect::<Vec<_>>();
        let packetslist = Paragraph::new(packets.join("\n"))
            .style(Style::default().fg(Color::White))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Blue))
                    .title(" Captured Packets ")
                    .title_alignment(Alignment::Left),
            );
        frame.render_widget(packetslist, chunks[1]);

        let stats = format!(
            "Total Packets: {} | Packets/sec: {:.2} | Running Time: {:?}",
            appstate.totalpackets,
            appstate.packetspersecond,
            appstate.starttime.elapsed().as_secs()
        );
        let statswidget = Paragraph::new(stats)
            .style(Style::default().fg(Color::Green))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Green))
                    .title(" Statistics ")
                    .title_alignment(Alignment::Left),
            );
        frame.render_widget(statswidget, chunks[2]);
        let footertext = if appstate.iscapturing {
            "Press 's' to stop capturing | 'q' or Ctrl+C to quit"
        } else {
            "Press 's' to start capturing | 'q' or Ctrl+C to quit"
        };
        let footer = Paragraph::new(footertext)
            .style(Style::default().fg(Color::Yellow))
            .alignment(Alignment::Center);
        frame.render_widget(footer, chunks[3]);
    })?;

    Ok(())
}

fn cleanuptui(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

fn selectdevice() -> Device {
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
        eprintln!("Invalid input! Please enter a valid number.");
        std::process::exit(1);
    });

    devices.get(input - 1).cloned().unwrap_or_else(|| {
        eprintln!("Invalid device selection!");
        std::process::exit(1);
    })
}

fn checkandprepareexportlocation(exportlocation: &str, clearfile: bool) -> io::Result<String> {
    let path = Path::new(exportlocation);

    // Check if the parent directory exists
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            eprintln!("Error: The parent directory does not exist: {:?}", parent);
            std::process::exit(1);
        }
    } else {
        eprintln!("Error: The export location has no parent directory.");
        std::process::exit(1);
    }

    // If the path is a directory, treat it as invalid (we expect a file path)
    if path.is_dir() {
        eprintln!("Error: The export location is a directory. Please specify a file path.");
        std::process::exit(1);
    }

    // If the file doesn't exist, create it
    if !path.exists() {
        fs::File::create(&path)?;
    }

    // Ensure the file is writable
    let file = fs::OpenOptions::new().write(true).open(path);
    if file.is_err() {
        eprintln!("Error: The specified file is not writable.");
        std::process::exit(1);
    }

    // Clear the file if `clearfile` is true
    if clearfile {
        fs::write(&path, "")?; // Overwrite the file with an empty string
    }

    // Return the file path as a String
    Ok(path.to_string_lossy().into_owned())
}

fn exportdata(exportlocation: &str, data: &str) -> io::Result<()> {
    // Read the existing file content (if the file exists)
    let mut existingcontent = String::new();
    if Path::new(exportlocation).exists() {
        let mut file = fs::File::open(exportlocation)?;
        file.read_to_string(&mut existingcontent)?;
    }

    // Open the file for writing (this will truncate the file)
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(exportlocation)?;

    // Write the new data followed by the existing content
    writeln!(file, "{}", data)?;
    write!(file, "{}", existingcontent)?;

    Ok(())
}

fn main() -> io::Result<()> {
    let args = parsearguments();
    let promisc = args.0;
    let enablegui = args.1;
    let mut exportlocation = args.2;
    let clearfile = args.3;

    if exportlocation != "" {
        match checkandprepareexportlocation(&exportlocation, clearfile) {
            Ok(path) => {
                exportlocation = path.clone();
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        if clearfile {
            eprintln!("Error: The --clear flag requires the --export flag to be set.");
            std::process::exit(1);
        }
    }

    let mut appstate = AppState::new();

    if !enablegui {
        let device = selectdevice();
        match setupcapture(device, promisc) {
            Ok(mut capture) => {
                println!("Sniffing on device... Press Ctrl+C to stop.");
                while let Ok(packet) = capture.next_packet() {
                    let packetinfo = parsepacket(&packet.data, appstate.totalpackets);
                    appstate.packets.insert(0, packetinfo.clone());
                    appstate.updatestats();

                    if appstate.packets.len() > 100 {
                        appstate.packets.pop();
                    }

                    println!("{}", packetinfo);
                    exportdata(&exportlocation, &packetinfo)?;
                }
            }
            Err(e) => eprintln!("Error: {}", e),
        }
        return Ok(());
    }

    let mut terminal = setuptui()?;

    'outer: loop {
        updatetui(&mut terminal, &appstate)?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Up if !appstate.selectionmade => appstate.selectpreviousdevice(),
                    KeyCode::Down if !appstate.selectionmade => appstate.selectnextdevice(),
                    KeyCode::Enter if !appstate.selectionmade => {
                        appstate.confirmselection();

                        if let Some(device) = appstate.getselecteddevice() {
                            match setupcapture(device, promisc) {
                                Ok(capture) => {
                                    let mut capture = capture.setnonblock().unwrap();

                                    appstate.starttime = Instant::now();
                                    appstate.iscapturing = true; // Start capturing

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
                                                    KeyCode::Char('s') => {
                                                        appstate.iscapturing =
                                                            !appstate.iscapturing;
                                                        updatetui(&mut terminal, &appstate)?;
                                                    }
                                                    _ => {}
                                                }
                                            }
                                        }

                                        if appstate.iscapturing {
                                            match capture.next_packet() {
                                                Ok(packet) => {
                                                    let packetinfo = parsepacket(&packet.data, appstate.totalpackets);
                                                    appstate
                                                        .packets
                                                        .insert(0, packetinfo.clone());
                                                    exportdata(
                                                        &exportlocation,
                                                        &packetinfo.clone(),
                                                    )?;
                                                    appstate.updatestats();

                                                    if appstate.packets.len() > 100 {
                                                        appstate.packets.pop();
                                                    }

                                                    updatetui(&mut terminal, &appstate)?;
                                                }
                                                Err(pcap::Error::TimeoutExpired) => {
                                                    updatetui(&mut terminal, &appstate)?;
                                                }
                                                Err(e) => {
                                                    eprintln!("Error capturing packet: {}", e);
                                                    break 'capture;
                                                }
                                            }
                                        } else {
                                            updatetui(&mut terminal, &appstate)?;
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

    cleanuptui(&mut terminal)?;
    Ok(())
}