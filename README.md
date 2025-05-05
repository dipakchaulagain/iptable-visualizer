# IPTables Visualizer

A Flask-based web application for visualizing and organizing iptables rules. This tool allows users to paste their iptables rules and see them parsed, grouped, and displayed in a user-friendly format.

## Features

- Parse raw iptables rules (e.g., from `iptables-save` output)
- Group rules by chain, action, protocol, and interface
- Filter rules by keyword
- View detailed information for each rule
- Responsive design for desktop and mobile

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/iptables-visualizer.git
   cd iptables-visualizer
   ```

2. Create a virtual environment and activate it:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

1. Start the application:
   ```
   python run.py
   ```

2. Open your browser and navigate to `http://localhost:5000`

3. Paste your iptables rules (e.g., output from `iptables-save`) into the text area and click "Parse Rules"

4. View the parsed rules in the table and explore the different grouping options

## Development

### Project Structure

```
iptables-visualizer/
│
├── app/
│   ├── __init__.py              # Flask app initialization
│   ├── routes.py                # Flask routes and API endpoints
│   ├── iptables_parser.py       # Logic for parsing and grouping iptables rules
│   ├── templates/
│   │   └── index.html           # Main HTML template for the frontend
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css        # Custom CSS for additional styling
│   │   ├── js/
│   │   │   └── main.js          # jQuery scripts for frontend interactivity
│
├── tests/
│   ├── test_parser.py           # Unit tests for iptables_parser
│   ├── test_routes.py           # Integration tests for API endpoints
│
├── requirements.txt             # Python dependencies
├── run.py                       # Entry point to run the Flask app
├── README.md                    # Project documentation
└── .gitignore                   # Git ignore file
```

### Running Tests

Run the tests using pytest:

```
pytest
```

## Dependencies

### Backend
- Flask 3.0.3
- pytest 8.3.2 (for testing)
- requests 2.32.3 (for testing)

### Frontend (via CDN)
- Bootstrap 5.3.3
- jQuery 3.7.1

## License

This project is licensed under the MIT License - see the LICENSE file for details.
