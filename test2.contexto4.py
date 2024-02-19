import re
import subprocess
import ipaddress
import pyfiglet
from colorama import Fore, Style # Importamos Fore y Style desde colorama
import nmap

def create_banner(tool_name, color=Fore.BLUE):  # Puedes cambiar el color predeterminado aquí
    banner = pyfiglet.figlet_format(tool_name, font="slant")
    colored_banner = f"{color}{banner}{Style.RESET_ALL}"  # Añadimos el color y restablecemos al estilo predeterminado
    return colored_banner

def scan_ip(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-O')  # Escaneo de puertos y detección del sistema operativo

    if ip in nm.all_hosts():
        if nm[ip].state() == 'up':
            print(f"\nInformación sobre la máquina con la dirección IP {ip}:\n")
            if 'osclass' in nm[ip]:
                print("Sistema operativo detectado:")
                for osclass in nm[ip]['osclass']:
                    print(f"  - Clase: {osclass['osclass']}, Tipo: {osclass['osfamily']}")
            else:
                print("No se pudo detectar el sistema operativo.")

            if nm[ip].all_protocols():
                print("\nPuertos abiertos:")
                for proto in nm[ip].all_protocols():
                    ports = nm[ip][proto].keys()
                    for port in ports:
                        print(f"  - Puerto {port} ({nm[ip][proto][port]['name']}) está abierto.")
            else:
                print("No se encontraron puertos abiertos.")
        else:
            print(f"La máquina con la dirección IP {ip} está apagada o no responde.")
    else:
        print(f"No se encontró información para la dirección IP {ip}.")

def input_ip_addresses():
    addresses = []
    while True:
        ip_address = input("Ingrese una dirección IP (o escriba 'fin' para terminar): ")
        if ip_address.lower() == 'fin':
            break
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip_address):
            addresses.append(ip_address)
        else:
            print("Dirección IP no válida. Intente nuevamente.")
    return addresses

def ping(ip, intentos=1):
    response = subprocess.run(["ping", "-n", str(intentos), ip], capture_output=True, text=True)
    
    if "Tiempo de espera agotado" in response.stdout:
        print(f"{ip} no respondió (Tiempo de espera agotado).")
        return False
    elif "Host de destino inaccesible" in response.stdout:
        print(f"{ip} no respondió (Host de destino inaccesible).")
        return False
    elif response.returncode == 0:
        print(f"{ip} está respondiendo.")
        return True
    else:
        print(f"{ip} no respondió.")
        return False

def main_script():
    ip_regex = r"^(\d{1,3}\.){3}\d{1,3}$"

    while True:
        inicio = input("Ingrese la dirección IP inicial del segmento de red: ")
        if re.match(ip_regex, inicio):
            break
        else:
            print("Dirección IP inicial no válida. Intente nuevamente.")

    while True:
        fin = input("Ingrese la dirección IP final del segmento de red: ")
        if re.match(ip_regex, fin):
            break
        else:
            print("Dirección IP final no válida. Intente nuevamente.")

    intentos = int(input("Ingrese la cantidad de intentos de ping: "))

    inicio = ipaddress.IPv4Address(inicio)
    fin = ipaddress.IPv4Address(fin)

    with open("resultados.txt", "w") as archivo:
        for ip in range(int(inicio), int(fin) + 1):
            current_ip = str(ipaddress.IPv4Address(ip))
            if ping(current_ip, intentos):
                archivo.write(current_ip + "\n")

def other_script():
    print("Este es otro script. Ingrese las direcciones IP manualmente.")
    
    direcciones_ip = input_ip_addresses()

    # Crea el archivo para almacenar los resultados
    with open("resultadosScript2.txt", "w") as archivo:
        # Itera sobre las direcciones IP ingresadas por el usuario
        for ip in direcciones_ip:
            # Pingea la IP actual
            if ping(ip):
                # Agrega las IPs que responden al archivo
                archivo.write(ip + "\n")

def main():
    print("1. Escanear un segmento de red y guardar en un .txt las ips que respondan")
    print("2. Escanear direcciones IPs Especificas")
    print("3. Escanear una dirección IP especifica en profundidad")

    opcion = input("Seleccione una opción (1, 2 o 3): ")

    if opcion == "1":
        main_script()
    elif opcion == "2":
        other_script()
    elif opcion == "3":
        ip_to_scan = input("Ingrese la dirección IP a escanear: ")
        scan_ip(ip_to_scan)
    else:
        print("Opción no válida.")

if __name__ == "__main__":
    tool_name = "Scanner IP"
    banner = create_banner(tool_name, color=Fore.LIGHTMAGENTA_EX)  # Cambia el color según tus preferencias
    print(banner)
    main()
    input("Presiona Enter para salir")