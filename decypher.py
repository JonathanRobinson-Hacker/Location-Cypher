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

def binario_a_bytes(binario):
    """
    Convierte una cadena binaria en bytes.
    """
    bytearray_result = bytearray()
    for i in range(0, len(binario), 8):
        byte = binario[i:i+8]
        bytearray_result.append(int(byte, 2))
    return bytes(bytearray_result)

def descifrar_coordenadas(coordenadas_binario, password):
    """
    Descifra las coordenadas binarias usando la contraseña proporcionada.
    """
    # Generar la clave de cifrado a partir de la contraseña
    clave = generar_clave(password)
    fernet = Fernet(clave)

    # Convertir el binario de vuelta a bytes
    coordenadas_bytes = binario_a_bytes(coordenadas_binario)

    # Descifrar las coordenadas
    coordenadas_descifradas = fernet.decrypt(coordenadas_bytes)
    coordenadas_str = coordenadas_descifradas.decode('utf-8')

    # Convertir la cadena de vuelta a una tupla de coordenadas
    latitud, longitud = map(float, coordenadas_str.split(','))
    return latitud, longitud

if __name__ == "__main__":
    coordenadas_binario = input("Introduce las coordenadas cifradas en binario: ")
    password = input("Introduce la contraseña para descifrar: ")
    coordenadas_originales = descifrar_coordenadas(coordenadas_binario, password)
    print(f"Coordenadas descifradas: {coordenadas_originales}")
