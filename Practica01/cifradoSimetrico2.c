#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
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
	char *textoPlano;
	long file_size;

	// Abrir el archivo textoclaro.txt en modo lectura
	file = fopen("textoclaro.txt", "r");
	if (file == NULL) {
    	perror("No se pudo abrir el archivo textoclaro.txt");
    	return 1;
	}

	// Determinar el tamaño del archivo
	fseek(file, 0, SEEK_END);
	file_size = ftell(file);
	rewind(file);

	// Reservar memoria para almacenar el contenido del archivo
	textoPlano = (char *)malloc(sizeof(char) * (file_size + 1));
	if (textoPlano == NULL) {
    	perror("No se pudo asignar memoria para textoPlano");
    	fclose(file);
    	return 1;
	}

	// Leer el contenido del archivo y almacenarlo en textoPlano
	size_t result = fread(textoPlano, 1, file_size, file);
	if (result != file_size) {
    	perror("Error al leer el archivo");
    	free(textoPlano);
    	fclose(file);
    	return 1;
	}
	textoPlano[file_size] = '\0'; // Asegurarse de que el texto esté terminado en NULL

	// Cerrar el archivo textoclaro.txt
	fclose(file);

	// Solicitar la clave al usuario
	unsigned char key[32];
	printf("Introduce una clave de 32 caracteres para el cifrado (o menos y se llenará con ceros):\n");
	fgets((char *)key, sizeof(key), stdin);
	key[strcspn((char *)key, "\n")] = 0; // Eliminar el salto de línea

	// Rellenar con ceros si la clave es menor de 32 bytes
	for (int i = strlen((char *)key); i < 32; i++) {
    	key[i] = 0;
	}

	// Variables para el cifrado
	EVP_CIPHER_CTX *ctx;
	unsigned char iv[16];
	unsigned char *mensajeCifrado;
	int len, ciphertext_len;

	// Generar un IV aleatorio
	if(!RAND_bytes(iv, sizeof(iv))) {
    	handleErrors();
	}

	// Crear y inicializar el contexto de cifrado
	ctx = EVP_CIPHER_CTX_new();
	if(!ctx) {
    	handleErrors();
	}

	// Inicializar el proceso de cifrado (AES-256-CBC)
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
    	handleErrors();
	}

	// Reservar memoria para el mensaje cifrado
	mensajeCifrado = (unsigned char *)malloc(file_size + AES_BLOCK_SIZE);
	if (mensajeCifrado == NULL) {
    	perror("No se pudo asignar memoria para mensajeCifrado");
    	free(textoPlano);
    	EVP_CIPHER_CTX_free(ctx);
    	return 1;
	}

	// Cifrar el texto plano
	if(1 != EVP_EncryptUpdate(ctx, mensajeCifrado, &len, (unsigned char *)textoPlano, file_size)) {
    	handleErrors();
	}
	ciphertext_len = len;

	if(1 != EVP_EncryptFinal_ex(ctx, mensajeCifrado + len, &len)) {
    	handleErrors();
	}
	ciphertext_len += len;

	// Abrir el archivo criptograma.txt en modo escritura
	file = fopen("criptograma.txt", "w");
	if (file == NULL) {
    	perror("No se pudo abrir el archivo criptograma.txt");
    	free(textoPlano);
    	free(mensajeCifrado);
    	EVP_CIPHER_CTX_free(ctx);
    	return 1;
	}

	// Escribir el IV y el mensaje cifrado en el archivo
	fwrite(iv, 1, sizeof(iv), file);
	fwrite(mensajeCifrado, 1, ciphertext_len, file);

	// Cerrar el archivo criptograma.txt
	fclose(file);

	// Limpiar
	EVP_CIPHER_CTX_free(ctx);
	free(textoPlano);
	free(mensajeCifrado);

	printf("Cifrado exitoso y almacenado en criptograma.txt\n");

	return 0;
}
