# Akaja

**Akaja** is a stress testing tool designed to simulate ACK and SYN flood network attacks. Written in C, Akaja mimics behaviors commonly associated with malware specifically for research and stress testing purposes.

> **Warning:**  
> This tool is intended solely for controlled, personal, and educational use.  
> Do **not** deploy on production servers or use against systems without proper authorization.  
> The developer does **not** endorse malicious activity.

---

## Features

- Simulates high-throughput ACK and SYN flood attacks.
- Useful for network resilience and security research.
- Single-user, in-development utility (not a production-ready tool).

## Getting Started

### Prerequisites

- GCC or compatible C compiler
- Linux environment (recommended; may require `sudo` for raw sockets)

### Build Instructions

```bash
git clone https://github.com/Pushpenderrathore/akaja.git
cd akaja
gcc -o akaja akaja.c
```

### Usage

> **Note:** Only use against systems you own or are authorized to test.

```bash
./akaja [OPTIONS]
```

Refer to the source code and comments for available configuration options and arguments.  
Detailed usage instructions will be available as the tool matures.

---

## Development Status

This project is under active development and intended for personal use only.  
Expect frequent changes and potential bugs.

---

## Contribution

Contributions are **not** required. This project is maintained solely by [Pushpenderrathore](https://github.com/Pushpenderrathore).

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Author

**Pushpenderrathore**
