import requests

try:
    r1 = requests.post('http://localhost:8080/api/login', json={'username': 'admin', 'password': 'password'})
    print('Login:', r1.status_code, r1.text)
    
    if r1.status_code == 200:
        token = r1.json().get('token')
        r2 = requests.get('http://localhost:8080/api/agents', headers={'Authorization': 'Bearer ' + token})
        print('Agents:', r2.status_code, r2.text)
except Exception as e:
    print('Error:', e)
