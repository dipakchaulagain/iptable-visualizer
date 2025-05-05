from flask import Blueprint, render_template, request, jsonify
from app.iptables_parser import parse_iptables_rules, group_rules, sanitize_input

main = Blueprint('main', __name__)

@main.route('/')
def index():
    """Render the main page."""
    return render_template('index.html')

@main.route('/api/parse_rules', methods=['POST'])
def parse_rules():
    """Parse and group iptables rules."""
    data = request.get_json()
    
    if not data or 'rules' not in data:
        return jsonify({
            'status': 'error',
            'message': 'No rules provided'
        }), 400
    
    raw_rules = data['rules']
    
    # Sanitize input to prevent injection attacks
    sanitized_rules = sanitize_input(raw_rules)
    
    try:
        # Parse the rules
        parsed_rules = parse_iptables_rules(sanitized_rules)
        
        # Group the rules
        grouped_rules = group_rules(parsed_rules)
        
        return jsonify({
            'status': 'success',
            'rules': parsed_rules,
            'grouped_rules': grouped_rules
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error parsing rules: {str(e)}'
        }), 400
