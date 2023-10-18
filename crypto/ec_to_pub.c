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
	if (!key)
	{
		return (NULL);
	}

	if (!EC_POINT_point2oct(EC_KEY_get0_group(key),
		EC_KEY_get0_public_key(key),
		POINT_CONVERSION_UNCOMPRESSED, pub, EC_PUB_LEN, NULL))
	{
		return (NULL);
	}

	return (pub);
}
