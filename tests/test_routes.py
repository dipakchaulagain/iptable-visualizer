import pytest
import json
from app import create_app

@pytest.fixture
def client():
    """Create a test client for the app."""
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_index_route(client):
    """Test the index route."""
    response = client.get('/')
    assert response.status_code == 200
    assert b'IPTables Visualizer' in response.data

def test_parse_rules_empty(client):
    """Test the parse_rules route with empty data."""
    response = client.post('/api/parse_rules', 
                          data=json.dumps({}),
                          content_type='application/json')
    assert response.status_code == 400
    data = json.loads(response.data)
    assert data['status'] == 'error'
    assert 'No rules provided' in data['message']

def test_parse_rules_valid(client):
    """Test the parse_rules route with valid data."""
    rules = """*filter
:INPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT"""
    
    response = client.post('/api/parse_rules',
                          data=json.dumps({'rules': rules}),
                          content_type='application/json')
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['status'] == 'success'
    assert len(data['rules']) == 2
    assert 'grouped_rules' in data
    assert 'by_chain' in data['grouped_rules']
    assert 'INPUT' in data['grouped_rules']['by_chain']

def test_parse_rules_invalid(client):
    """Test the parse_rules route with invalid data."""
    # This is not a valid iptables rule format
    rules = "This is not a valid iptables rule"
    
    response = client.post('/api/parse_rules',
                          data=json.dumps({'rules': rules}),
                          content_type='application/json')
    
    # It should still return 200 with empty rules
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['status'] == 'success'
    assert len(data['rules']) == 0
