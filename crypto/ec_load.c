#include "hblk_crypto.h"

/**
 * ec_load - Load an EC key pair from the disk
 * By finding key.pem for private key and key_pub.pem for public key
 *
 * @folder: The path to the folder from which to load the keys
 *
 * Return: Pointer to a new EC key pair, NULL if the load is a faillure
*/
EC_KEY *ec_load(char const *folder)
{
	EC_KEY *keyLoaded = NULL;
	FILE *fileStream = NULL;
	char *filePath = NULL;

	keyLoaded = EC_KEY_new_by_curve_name(EC_CURVE);
	if (!keyLoaded)
		return (NULL);

	filePath = _generateFilePath(folder, PUB_FILENAME);
	if (filePath == NULL)
	{
		EC_KEY_free(keyLoaded);
		return (NULL);
	}
	fileStream = fopen(filePath, "r");
	PEM_read_EC_PUBKEY(fileStream, &keyLoaded, NULL, NULL);
	fclose(fileStream);
	free(filePath);

	filePath = _generateFilePath(folder, PRI_FILENAME);
	if (filePath == NULL)
	{
		EC_KEY_free(keyLoaded);
		return (NULL);
	}
	fileStream = fopen(filePath, "r");
	PEM_read_ECPrivateKey(fileStream, &keyLoaded, NULL, NULL);
	fclose(fileStream);
	free(filePath);

	return (keyLoaded);
}
