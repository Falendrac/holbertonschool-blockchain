#include "hblk_crypto.h"

/**
 * _generateFilePath - Allocate a new char pointer to crate the full filepath
 *
 * @folder: The path of the folder
 * @fileName: The name of the file
 *
 * Return: NULL if it failled, the filePath that is a pointer of char otherwise
*/
char *_generateFilePath(char const *folder, char const *fileName)
{
	char *filePath = NULL;
	int folderLength, fileLength;

	folderLength = strlen(folder);
	fileLength = strlen(fileName);

	filePath = calloc((folderLength + fileLength + 2), sizeof(char));
	if (filePath == NULL)
		return (NULL);

	strcat(filePath, folder);
	strcat(filePath, "/");
	strcat(filePath, fileName);

	return (filePath);
}

/**
 * checkDirectory - Check if the directory in the folder path exist
 * if not, the function create the directory
 *
 * @folder: The path of the folder
*/
void checkDirectory(char const *folder)
{
	struct stat st = {0};

	if (lstat(folder, &st) == -1)
		mkdir(folder, 0700);
}

/**
 * _generateKeySave - Create the files key.pem and key_pub.pem with
 * private key in key.pem and public key in key_pub.pem
 *
 * @key: The EC_KEY with the key pair
 * @folder: The path of the .pem file
 * @typeFile: When the function call, see if is for public or private
 *
 * Return: 0 for faillure to save, 1 if success
*/
int _generateKeySave(EC_KEY *key, char const *folder, int typeFile)
{
	FILE *fileStream = NULL;

	fileStream = fopen(folder, "a+");
	if (!fileStream)
		return (0);

	if (typeFile == IS_PUB && PEM_write_EC_PUBKEY(fileStream, key) == 0)
	{
		fclose(fileStream);
		return (0);
	}

	if (typeFile == IS_PRI &&
		PEM_write_ECPrivateKey(fileStream, key, NULL, NULL, 0, NULL, NULL) == 0)
	{
		fclose(fileStream);
		return (0);
	}

	fclose(fileStream);

	return (1);
}

/**
 * ec_save - Saves an existing EC key pair on the disk
 *
 * @key: The key pair to save
 * @folder: The path of the folder where to save
 *
 * Return: 1 if the save is a success, 0 otherwise
*/
int ec_save(EC_KEY *key, char const *folder)
{
	char *filePath = NULL;

	if (folder)
		checkDirectory(folder);
	else
		folder = ".";

	filePath = _generateFilePath(folder, PUB_FILENAME);
	if (filePath == NULL)
		return (0);

	if (_generateKeySave(key, filePath, IS_PUB) == 0)
	{
		free(filePath);
		return (0);
	}
	free(filePath);
	filePath = _generateFilePath(folder, PRI_FILENAME);
	if (filePath == NULL)
		return (0);

	if (_generateKeySave(key, filePath, IS_PRI) == 0)
	{
		free(filePath);
		return (0);
	}
	free(filePath);

	return (1);
}
