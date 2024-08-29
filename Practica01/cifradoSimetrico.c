#include <stdio.h>
#include <stdlib.h>

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

	// Imprimir el contenido leído
	printf("Contenido de textoclaro.txt:\n%s\n", textoPlano);

	// Liberar la memoria asignada
	free(textoPlano);

	return 0;
}
