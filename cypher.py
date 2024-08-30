from cryptography.fernet import Fernet
import base64
import hashlib

def generar_clave(password):
    """
    Genera una clave a partir de una contraseña.
    """
    # Usa SHA-256 para crear un hash de la contraseña
    password_bytes = password.encode('utf-8')
    hashed_password = hashlib.sha256(password_bytes).digest()

    # Base64-encode el hash para que se convierta en una clave de 32 bytes
    return base64.urlsafe_b64encode(hashed_password)

def cifrar_coordenadas(coordenadas, password):
    """
    Cifra las coordenadas usando la contraseña proporcionada.
    """
    # Generar la clave de cifrado a partir de la contraseña
    clave = generar_clave(password)
    fernet = Fernet(clave)

    # Convertir las coordenadas en una cadena de texto
    coordenadas_str = f"{coordenadas[0]},{coordenadas[1]}"
    coordenadas_bytes = coordenadas_str.encode('utf-8')

    # Cifrar las coordenadas
    coordenadas_cifradas = fernet.encrypt(coordenadas_bytes)

    # Convertir a binario
    coordenadas_binario = ''.join(format(byte, '08b') for byte in coordenadas_cifradas)

    return coordenadas_binario

if __name__ == "__main__":
    coordenadas = (40.7128, -74.0060)  # Ejemplo de coordenadas (latitud, longitud)
    password = input("Introduce la contraseña para cifrar: ")
    resultado_cifrado = cifrar_coordenadas(coordenadas, password)
    print(f"Coordenadas cifradas en binario: {resultado_cifrado}")
