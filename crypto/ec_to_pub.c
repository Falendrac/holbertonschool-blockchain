#include "hblk_crypto.h"

/**
 * ec_to_pub - Extract the public key from an EC_KEY
 *
 * @key: The EC_KEY we want to extract the public key
 * @pub: The buffer where the public key is stored
 *
 * Return: NULL if the EC_KEY is NULL, the public key otherwise
*/
uint8_t *ec_to_pub(EC_KEY const *key, uint8_t pub[EC_PUB_LEN])
{
	uint8_t *pubBuf;
	BN_CTX *ctxPub = BN_CTX_new();
	int index;

	if (!key)
	{
		return (NULL);
	}

	EC_KEY_key2buf(key, EC_KEY_get_conv_form(key), &pubBuf, ctxPub);

	for (index = 0; index < EC_PUB_LEN; index++)
		pub[index] = pubBuf[index];

	BN_CTX_free(ctxPub);
	free(pubBuf);

	return (pub);
}
