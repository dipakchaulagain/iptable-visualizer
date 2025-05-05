import re

def sanitize_input(raw_rules):
    """
    Sanitize input to prevent injection attacks.
    
    Args:
        raw_rules (str): Raw iptables rules string
        
    Returns:
        str: Sanitized rules string
    """
    # Remove potentially dangerous characters or commands
    # This is a basic implementation - in production, more thorough sanitization might be needed
    sanitized = re.sub(r'[;&|`$]', '', raw_rules)
    return sanitized

def parse_iptables_rules(raw_rules):
    """
    Parse raw iptables rules into a structured format.
    
    Args:
        raw_rules (str): Raw iptables rules string (e.g., from iptables-save)
        
    Returns:
        list: List of dictionaries, each representing a rule
    """
    parsed_rules = []
    lines = raw_rules.strip().split('\n')
    
    # Regular expressions for parsing different parts of iptables rules
    chain_re = re.compile(r'^:(\S+)\s+(\S+)')
    rule_re = re.compile(r'^-A\s+(\S+)\s+(.*)')
    source_re = re.compile(r'-s\s+(\S+)')
    destination_re = re.compile(r'-d\s+(\S+)')
    protocol_re = re.compile(r'-p\s+(\S+)')
    port_re = re.compile(r'--dport\s+(\S+)')
    sport_re = re.compile(r'--sport\s+(\S+)')
    interface_in_re = re.compile(r'-i\s+(\S+)')
    interface_out_re = re.compile(r'-o\s+(\S+)')
    action_re = re.compile(r'-j\s+(\S+)')
    comment_re = re.compile(r'--comment\s+"([^"]*)"')
    
    current_table = "filter"  # Default table
    
    for line in lines:
        line = line.strip()
        
        # Skip empty lines and comments
        if not line or line.startswith('#'):
            continue
        
        # Check for table declaration
        if line.startswith('*'):
            current_table = line[1:]
            continue
        
        # Check for chain declaration
        chain_match = chain_re.match(line)
        if chain_match:
            continue  # We're just parsing rules for now, not chain policies
        
        # Check for rule
        rule_match = rule_re.match(line)
        if rule_match:
            chain = rule_match.group(1)
            rule_body = rule_match.group(2)
            
            # Extract rule components
            source = source_re.search(rule_body)
            source = source.group(1) if source else "0.0.0.0/0"
            
            destination = destination_re.search(rule_body)
            destination = destination.group(1) if destination else "0.0.0.0/0"
            
            protocol = protocol_re.search(rule_body)
            protocol = protocol.group(1) if protocol else "all"
            
            port = port_re.search(rule_body)
            port = port.group(1) if port else ""
            
            sport = sport_re.search(rule_body)
            sport = sport.group(1) if sport else ""
            
            interface_in = interface_in_re.search(rule_body)
            interface_in = interface_in.group(1) if interface_in else ""
            
            interface_out = interface_out_re.search(rule_body)
            interface_out = interface_out.group(1) if interface_out else ""
            
            action = action_re.search(rule_body)
            action = action.group(1) if action else ""
            
            comment = comment_re.search(rule_body)
            comment = comment.group(1) if comment else ""
            
            rule = {
                'table': current_table,
                'chain': chain,
                'source': source,
                'destination': destination,
                'protocol': protocol,
                'dport': port,
                'sport': sport,
                'in_interface': interface_in,
                'out_interface': interface_out,
                'action': action,
                'comment': comment,
                'raw': line
            }
            
            parsed_rules.append(rule)
    
    return parsed_rules

def group_rules(rules):
    """
    Group parsed rules by common attributes.
    
    Args:
        rules (list): List of parsed rule dictionaries
        
    Returns:
        dict: Dictionary with grouped rules
    """
    grouped = {
        'by_chain': {},
        'by_action': {},
        'by_protocol': {},
        'by_interface': {}
    }
    
    # Group by chain
    for rule in rules:
        chain = rule['chain']
        if chain not in grouped['by_chain']:
            grouped['by_chain'][chain] = []
        grouped['by_chain'][chain].append(rule)
    
    # Group by action
    for rule in rules:
        action = rule['action']
        if action not in grouped['by_action']:
            grouped['by_action'][action] = []
        grouped['by_action'][action].append(rule)
    
    # Group by protocol
    for rule in rules:
        protocol = rule['protocol']
        if protocol not in grouped['by_protocol']:
            grouped['by_protocol'][protocol] = []
        grouped['by_protocol'][protocol].append(rule)
    
    # Group by interface (in or out)
    for rule in rules:
        in_interface = rule['in_interface']
        out_interface = rule['out_interface']
        
        if in_interface:
            if in_interface not in grouped['by_interface']:
                grouped['by_interface'][in_interface] = []
            grouped['by_interface'][in_interface].append(rule)
        
        if out_interface:
            if out_interface not in grouped['by_interface']:
                grouped['by_interface'][out_interface] = []
            grouped['by_interface'][out_interface].append(rule)
    
    return grouped
