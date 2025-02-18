use pcap::{Device, Capture};

fn selectdevice() -> Device {
    let devices = match Device::list() {
        Ok(devices) => devices,
        Err(e) => {
            eprintln!("Error listing devices: {}", e);
            std::process::exit(1);
        }
    };
    for (i, device) in devices.iter().enumerate() {
        println!("{}. {}", i + 1, device.name);
    }
    println!("Select a device to capture: ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    let input: u32 = match input.trim().parse() {
        Ok(num) => num,
        Err(_) => {
            println!("Invalid input! Please enter a number.");
            std::process::exit(1);
        }
    };
    let device = match devices.get(input as usize - 1) {
        Some(device) => device,
        None => {
            eprintln!("Invalid device selection!");
            std::process::exit(1);
        }
    };
    println!("Selected device: {}", device.name);
    device.clone()
}

fn settings(device: Device) -> Capture<pcap::Active> {
    println!("Settings:");
    println!("Get all packets not just one for your device (T): ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    let input = input.trim().to_uppercase();
    let promisc = input.trim().eq_ignore_ascii_case("t");

    Capture::from_device(device)
        .unwrap()
        .promisc(promisc)
        .immediate_mode(true)
        .snaplen(65535)
        .open()
        .unwrap()
}

fn main() {
    let device = selectdevice();
    let mut cap = settings(device);

    println!("Sniffing on device... Press Ctrl+C to stop.");
    while let Ok(packet) = cap.next_packet() {
        println!("Captured {} bytes", packet.header.len);
    }
}