# EASM (Enterprise Attack Surface Management)

A web-based security monitoring and alert system with both console and web interfaces.

## Features

- Scanning and monitoring of network hosts
- Real-time security alerts
- Risk assessment and reporting
- Secure user authentication
- Web-based dashboard
- Console-based interface

## Project Structure

```
Assignment 2 ICT/
├── web_server.py        # Flask web application
├── console_ui.py        # Console interface
├── init_db.py          # Database initialization
├── easm.db             # SQLite database
├── config.txt          # Configuration file
└── templates/          # Flask HTML templates
    ├── base.html       # Base template
    ├── login.html      # Login page
    ├── register.html   # Registration page
    ├── scan.html       # Scan results page
    └── alerts.html     # Alerts page
```

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd Assignment-2-ICT
   ```

2. Create a virtual environment and activate it:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
   ```

3. Install required packages:
   ```bash
   pip install flask bcrypt
   ```

## Configuration

1. Update the config.txt file with your settings:
   ```
   telegram_token=your-token
   chat_id=your-chat-id
   ```

## Usage

1. Start the web server:
   ```bash
   python web_server.py
   ```
   Access the web interface at http://localhost:5000

2. Run the console interface:
   ```bash
   python console_ui.py
   ```

## Security Features

- Bcrypt password hashing
- SQL injection prevention
- Session-based authentication
- Parameterized queries
- Input validation

## Database Structure

### Tables

1. Hosts
   - id (INTEGER PRIMARY KEY)
   - ip (TEXT)
   - port (INTEGER)
   - service (TEXT)
   - risk (TEXT)
   - last_seen (TEXT)

2. Alerts
   - id (INTEGER PRIMARY KEY)
   - host_id (INTEGER FOREIGN KEY)
   - severity (TEXT)
   - rule (TEXT)
   - message (TEXT)
   - created_at (TEXT)

3. Users
   - id (INTEGER PRIMARY KEY)
   - username (TEXT UNIQUE)
   - password (BLOB)
   - created_at (TIMESTAMP)

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.