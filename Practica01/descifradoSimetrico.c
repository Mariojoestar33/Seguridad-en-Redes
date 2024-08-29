#include <openssl/evp.h>
#include <openssl/aes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void handleErrors() {
	ERR_print_errors_fp(stderr);
	abort();
}

int main() {
	// Declaración de variables
	FILE *file;
	long file_size;
	unsigned char iv[16];
	unsigned char *mensajeDescifrar;
	unsigned char *mensajeDescifrado;
	int len, plaintext_len;

	// Abrir el archivo criptograma.txt en modo lectura
	file = fopen("criptograma.txt", "rb");
	if (file == NULL) {
    	perror("No se pudo abrir el archivo criptograma.txt");
    	return 1;
	}

	// Leer el IV del archivo (primeros 16 bytes)
	if (fread(iv, 1, sizeof(iv), file) != sizeof(iv)) {
    	perror("No se pudo leer el IV del archivo");
    	fclose(file);
    	return 1;
	}

	// Determinar el tamaño del archivo para reservar memoria para el mensaje cifrado
	fseek(file, 0, SEEK_END);
	file_size = ftell(file) - sizeof(iv); // Tamaño del archivo menos el IV
	rewind(file);
	fseek(file, sizeof(iv), SEEK_SET); // Saltar el IV

	// Reservar memoria para almacenar el contenido cifrado
	mensajeDescifrar = (unsigned char *)malloc(file_size);
	if (mensajeDescifrar == NULL) {
    	perror("No se pudo asignar memoria para mensajeDescifrar");
    	fclose(file);
    	return 1;
	}

	// Leer el contenido cifrado del archivo y almacenarlo en mensajeDescifrar
	if (fread(mensajeDescifrar, 1, file_size, file) != file_size) {
    	perror("Error al leer el archivo cifrado");
    	free(mensajeDescifrar);
    	fclose(file);
    	return 1;
	}

	// Cerrar el archivo criptograma.txt
	fclose(file);

	// Solicitar la clave al usuario
	unsigned char key[32];
	printf("Introduce la clave de 32 caracteres utilizada para el cifrado:\n");
	fgets((char *)key, sizeof(key), stdin);
	key[strcspn((char *)key, "\n")] = 0; // Eliminar el salto de línea

	// Rellenar con ceros si la clave es menor de 32 bytes
	for (int i = strlen((char *)key); i < 32; i++) {
    	key[i] = 0;
	}

	// Crear y inicializar el contexto de descifrado
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if(!ctx) {
    	handleErrors();
	}

	// Inicializar el proceso de descifrado (AES-256-CBC)
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
    	handleErrors();
	}

	// Reservar memoria para el mensaje descifrado
	mensajeDescifrado = (unsigned char *)malloc(file_size + AES_BLOCK_SIZE);
	if (mensajeDescifrado == NULL) {
    	perror("No se pudo asignar memoria para mensajeDescifrado");
    	free(mensajeDescifrar);
    	EVP_CIPHER_CTX_free(ctx);
    	return 1;
	}

	// Descifrar el mensaje
	if(1 != EVP_DecryptUpdate(ctx, mensajeDescifrado, &len, mensajeDescifrar, file_size)) {
    	handleErrors();
	}
	plaintext_len = len;

	if(1 != EVP_DecryptFinal_ex(ctx, mensajeDescifrado + len, &len)) {
    	handleErrors();
	}
	plaintext_len += len;

	// Abrir el archivo textodescifrado.txt en modo escritura
	file = fopen("textodescifrado.txt", "w");
	if (file == NULL) {
    	perror("No se pudo abrir el archivo textodescifrado.txt");
    	free(mensajeDescifrar);
    	free(mensajeDescifrado);
    	EVP_CIPHER_CTX_free(ctx);
    	return 1;
	}

	// Escribir el mensaje descifrado en el archivo
	fwrite(mensajeDescifrado, 1, plaintext_len, file);

	// Cerrar el archivo textodescifrado.txt
	fclose(file);

	// Limpiar
	EVP_CIPHER_CTX_free(ctx);
	free(mensajeDescifrar);
	free(mensajeDescifrado);

	printf("Descifrado exitoso y almacenado en textodescifrado.txt\n");

	return 0;
}
