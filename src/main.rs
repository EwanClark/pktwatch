use clap::{App, Arg};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use pcap::{Capture, Device};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    Packet,
};
use ratatui::{
    prelude::*,
    style::{Color, Modifier, Style},
    widgets::*,
};
use std::{
    fs,
    io::{self, Write},
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
    filters: Vec<Filter>,
}

#[derive(Clone)]
enum FilterType {
    Include,
    Exclude,
}

#[derive(Clone)]
struct Filter {
    pattern: String,
    filter_type: FilterType,
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
            filters: Vec::new(),
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

    fn should_display_packet(&self, packet_info: &str) -> bool {
        if self.filters.is_empty() {
            return true; // No filters, display all packets
        }
    
        let packet_info_lower = packet_info.to_lowercase();
    
        // Check exclude filters first
        for filter in &self.filters {
            if let FilterType::Exclude = filter.filter_type {
                if packet_info_lower.contains(&filter.pattern.to_lowercase()) {
                    return false; // Exclude if it matches any exclude filter
                }
            }
        }
    
        // If there are no include filters, display the packet
        let has_include_filters = self.filters.iter().any(|f| matches!(f.filter_type, FilterType::Include));
        if !has_include_filters {
            return true;
        }
    
        // Check include filters
        for filter in &self.filters {
            if let FilterType::Include = filter.filter_type {
                if packet_info_lower.contains(&filter.pattern.to_lowercase()) {
                    return true; // Include if it matches any include filter
                }
            }
        }
    
        false // If no include filters match, exclude the packet
    }
}

// Modify the setupcapture function to always show errors
fn setupcapture(device: Device, promisc: bool, verbose: bool) -> Result<Capture<pcap::Active>, String> {
    if verbose {
        println!("Setting up capture on device: {}", device.name);
        println!("Promiscuous mode: {}", promisc);
    }

    let device_name = device.name.clone();
    let capture = Capture::from_device(device)
        .map_err(|e| format!("Failed to open device '{}': {}", device_name, e))?
        .promisc(promisc)
        .immediate_mode(true)
        .snaplen(65535)
        .open()
        .map_err(|e| format!("Failed to start capture on device '{}': {}", device_name, e))?;
    Ok(capture)
}

fn selectdevice(devices: &[Device]) -> Device {
    println!("Available devices:");
    for (i, device) in devices.iter().enumerate() {
        println!("{}. {}", i + 1, device.name);
    }

    let mut input = String::new();
    print!("Select a device to capture (1-{}): ", devices.len());
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut input).unwrap();

    let input: usize = input.trim().parse().unwrap_or_else(|_| {
        eprintln!("Invalid input! Please enter a valid number.");
        std::process::exit(1);
    });

    if input < 1 || input > devices.len() {
        eprintln!("Invalid device selection!");
        std::process::exit(1);
    }

    devices[input - 1].clone()
}

fn parsearguments() -> (bool, bool, String, bool, bool, bool, String) {
    let matches = App::new("Packet Capture")
        .version(env!("CARGO_PKG_VERSION"))
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
        .arg(
            Arg::with_name("verbose")
            .short("v")
            .long("verbose")
            .help("Enable verbose output")
            .takes_value(false),
        )
        .arg(
            Arg::with_name("version")
                .short("V")
                .long("version")
                .help("Show version information")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("filter")
                .short("f")
                .long("filter")
                .help(
                    "Filter packets using patterns (semicolon-separated). \
                     Include with pattern, exclude with !pattern.\n\
                     Example: -f \"TCP;!192.168.1.1;!UDP\"\n\
                     This shows all TCP packets except those containing UDP or 192.168.1.1\n\
                     Filters are applied in order: includes first, then excludes."
                )
                .takes_value(true),
        )
        .get_matches();

    (
        matches.is_present("promisc"),
        matches.is_present("gui"),
        matches.value_of("export").unwrap_or("").to_string(),
        matches.is_present("clear"),
        matches.is_present("verbose"),
        matches.is_present("version"),
        matches.value_of("filter").unwrap_or("").to_string(),
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

fn parsepacket(packetdata: &[u8], packetnumber: usize, verbose: bool) -> String {
    if let Some(ethernet) = EthernetPacket::new(packetdata) {
        if verbose {
            println!(
                "[Packet {}] Ethernet | SRC: {:02X?} | DST: {:02X?} | Type: {:?}",
                packetnumber,
                ethernet.get_source(),
                ethernet.get_destination(),
                ethernet.get_ethertype()
            );
        }

        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => {
                if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                    if verbose {
                        println!(
                            "[Packet {}] IPv4 | SRC: {} | DST: {} | Protocol: {:?} | \
                             TTL: {} | LEN: {}",
                            packetnumber,
                            ipv4.get_source(),
                            ipv4.get_destination(),
                            ipv4.get_next_level_protocol(),
                            ipv4.get_ttl(),
                            ipv4.get_total_length()
                        );
                    }

                    match ipv4.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => {
                            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                if verbose {
                                    println!(
                                        "[Packet {}] TCP | SRC Port: {} | DST Port: {} | Flags: {:?} | SEQ: {} | ACK: {} | Window: {}",
                                        packetnumber,
                                        tcp.get_source(),
                                        tcp.get_destination(),
                                        tcp.get_flags(),
                                        tcp.get_sequence(),
                                        tcp.get_acknowledgement(),
                                        tcp.get_window()
                                    );
                                }

                                return format!(
                                    "[{}] IPv4 TCP | SRC: {}:{} | DST: {}:{} | \
                                     FLAGS: {:?} | LEN: {}",
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
                                if verbose {
                                    println!(
                                        "[Packet {}] UDP | SRC Port: {} | DST Port: {} | LEN: {}",
                                        packetnumber,
                                        udp.get_source(),
                                        udp.get_destination(),
                                        udp.get_length()
                                    );
                                }

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
            EtherTypes::Ipv6 => {
                if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
                    if verbose {
                        println!(
                            "[Packet {}] IPv6 | SRC: {} | DST: {} | Protocol: {:?} | Hop Limit: {} | LEN: {}",
                            packetnumber,
                            ipv6.get_source(),
                            ipv6.get_destination(),
                            ipv6.get_next_header(),
                            ipv6.get_hop_limit(),
                            ipv6.get_payload_length()
                        );
                    }

                    match ipv6.get_next_header() {
                        IpNextHeaderProtocols::Tcp => {
                            if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                                if verbose {
                                    println!(
                                        "[Packet {}] TCP | SRC Port: {} | DST Port: {} | Flags: {:?} | SEQ: {} | ACK: {} | Window: {}",
                                        packetnumber,
                                        tcp.get_source(),
                                        tcp.get_destination(),
                                        tcp.get_flags(),
                                        tcp.get_sequence(),
                                        tcp.get_acknowledgement(),
                                        tcp.get_window()
                                    );
                                }

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
                                if verbose {
                                    println!(
                                        "[Packet {}] UDP | SRC Port: {} | DST Port: {} | LEN: {}",
                                        packetnumber,
                                        udp.get_source(),
                                        udp.get_destination(),
                                        udp.get_length()
                                    );
                                }

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

// Modify the checkandprepareexportlocation function to always show errors
fn checkandprepareexportlocation(exportlocation: &str, clearfile: bool, verbose: bool) -> io::Result<String> {
    let path = Path::new(exportlocation);

    if verbose {
        println!("Checking export location: {}", exportlocation);
    }

    if let Some(parent) = path.parent() {
        if !parent.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Parent directory does not exist: {:?}", parent)
            ));
        }
    }

    if path.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Export location is a directory, please specify a file path"
        ));
    }

    if !path.exists() {
        if verbose {
            println!("Creating file: {:?}", path);
        }
        fs::File::create(&path)?;
    }

    fs::OpenOptions::new().write(true).open(path).map_err(|e| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("File is not writable: {}", e)
        )
    })?;

    if clearfile {
        if verbose {
            println!("Clearing file: {:?}", path);
        }
        fs::write(&path, "")?;
    }

    if verbose {
        println!("Export location prepared: {:?}", path);
    }

    Ok(path.to_string_lossy().into_owned())
}

fn exportdata(exportlocation: &str, data: &str) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(exportlocation)?;

    writeln!(file, "{}", data)?;
    Ok(())
}

fn parse_filters(filter_str: &str) -> Vec<Filter> {
    if filter_str.is_empty() {
        return Vec::new();
    }

    filter_str
        .split(';')
        .filter(|s| !s.trim().is_empty())
        .map(|pattern| {
            let pattern = pattern.trim();
            if pattern.starts_with('!') {
                Filter {
                    pattern: pattern[1..].to_string(),
                    filter_type: FilterType::Exclude,
                }
            } else {
                Filter {
                    pattern: pattern.to_string(),
                    filter_type: FilterType::Include,
                }
            }
        })
        .collect()
}

fn main() -> io::Result<()> {
    let args = parsearguments();
    let promisc = args.0;
    let enablegui = args.1;
    let mut exportlocation = args.2;
    let clearfile = args.3;
    let verbose = args.4;
    let version = args.5;
    let filter_str = args.6;

    if version {
        println!("{} v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // Ensure GUI mode and verbose mode are not used together
    if enablegui && verbose {
        eprintln!("Error: Verbose mode (-v) cannot be used with GUI mode (-g)");
        std::process::exit(1);
    }

    if verbose {
        println!("Starting packet capture with the following options:");
        println!("Promiscuous mode: {}", promisc);
        println!("GUI mode: {}", enablegui);
        println!("Export location: {}", exportlocation);
        println!("Clear file: {}", clearfile);
    }

    if !exportlocation.is_empty() {
        match checkandprepareexportlocation(&exportlocation, clearfile, verbose) {
            Ok(path) => {
                exportlocation = path.clone();
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    } else if clearfile {
        eprintln!("Error: The --clear flag requires the --export flag to be set.");
        std::process::exit(1);
    }

    let mut appstate = AppState::new();
    appstate.filters = parse_filters(&filter_str);

    if verbose && !filter_str.is_empty() {
        println!("Applied filters:");
        for filter in &appstate.filters {
            match filter.filter_type {
                FilterType::Include => println!("Include: {}", filter.pattern),
                FilterType::Exclude => println!("Exclude: !{}", filter.pattern),
            }
        }
    }

    if !enablegui {
        let device = selectdevice(&appstate.devices); // Allow device selection in non-GUI mode
        match setupcapture(device, promisc, verbose) {
            Ok(mut capture) => {
                println!("Sniffing on device... Press Ctrl+C to stop.");
                while let Ok(packet) = capture.next_packet() {
                    let packetinfo = parsepacket(&packet.data, appstate.totalpackets, verbose);
                    if appstate.should_display_packet(&packetinfo) {
                        appstate.packets.insert(0, packetinfo.clone());
                        appstate.updatestats();

                        if appstate.packets.len() > 100 {
                            appstate.packets.pop();
                        }

                        if verbose {
                            println!("Captured packet: {}", packetinfo);
                        }

                        println!("{}", packetinfo);
                        if !exportlocation.is_empty() {
                            exportdata(&exportlocation, &packetinfo)?;
                        }
                    }
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
                            match setupcapture(device, promisc, verbose) {
                                Ok(capture) => {
                                    let mut capture = capture.setnonblock().unwrap();

                                    appstate.starttime = Instant::now();
                                    appstate.iscapturing = true;

                                    'capture: loop {
                                        if event::poll(Duration::from_millis(1))? {
                                            if let Event::Key(key) = event::read()? {
                                                match key.code {
                                                    KeyCode::Char('q') => break 'outer,
                                                    KeyCode::Char('c')
                                                        if key.modifiers.contains(KeyModifiers::CONTROL) =>
                                                    {
                                                        break 'outer
                                                    }
                                                    KeyCode::Char('s') => {
                                                        appstate.iscapturing = !appstate.iscapturing;
                                                        updatetui(&mut terminal, &appstate)?;
                                                    }
                                                    _ => {}
                                                }
                                            }
                                        }

                                        if appstate.iscapturing {
                                            match capture.next_packet() {
                                                Ok(packet) => {
                                                    let packetinfo = parsepacket(&packet.data, appstate.totalpackets, verbose);
                                                    if appstate.should_display_packet(&packetinfo) {
                                                        appstate.packets.insert(0, packetinfo.clone());
                                                        if !exportlocation.is_empty() {
                                                            if let Err(e) = exportdata(&exportlocation, &packetinfo) {
                                                                eprintln!("Failed to export packet data: {}", e);
                                                            }
                                                        }
                                                        appstate.updatestats();

                                                        if appstate.packets.len() > 100 {
                                                            appstate.packets.pop();
                                                        }

                                                        updatetui(&mut terminal, &appstate)?;
                                                    }
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